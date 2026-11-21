"""Evidence ingestion tests — deterministic Normalize/Correlate stage."""

import pytest

from hub.erkg.ingestion import EvidenceIngestor, IngestResult, invocation_hash
from hub.erkg.store import ERKGStore
from hub.models import (
    EntityType,
    EpistemicStatus,
    EvidenceArtifact,
    InvestigationConfig,
    InvestigationState,
    utc_now,
)
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

INV = "inv-ingest"


# ── helpers ─────────────────────────────────────────────────────────────

def bootstrap(store, target_id=INV) -> str:
    now = utc_now()
    store.create_investigation(InvestigationState(
        target_id=target_id, raw_input="seed", created_at=now, updated_at=now,
        config=InvestigationConfig(target_id=target_id, raw_input="seed"),
    ))
    artifact = EvidenceArtifact(
        artifact_id=f"art_{target_id}", investigation_id=target_id,
        source_tool="holehe", invocation_params_hash="h",
        timestamp_utc=now, raw_evidence_snippet="evidence",
        raw_output_sha256="c" * 64, parser_version="2.0.0",
    )
    store.add_artifact(artifact)
    return artifact.artifact_id


def parse_output() -> ParseOutput:
    return ParseOutput(
        entities=[
            EntityCandidate(type=EntityType.EMAIL, value="target@example.com",
                            confidence=0.8, evidence="[+] target@example.com",
                            attributes={"verified": True}),
            EntityCandidate(type=EntityType.SERVICE, value="github",
                            confidence=0.9, evidence="[+] github.com",
                            attributes={"registered": True}),
            EntityCandidate(type=EntityType.USERNAME, value="targetuser",
                            confidence=0.7, evidence="profile: targetuser"),
        ],
        relations=[
            RelationCandidate(
                subject_type=EntityType.EMAIL, subject_value="target@example.com",
                predicate="REGISTERED_ON", object_type=EntityType.SERVICE,
                object_value="github", confidence=0.9,
                evidence="[+] github.com",
            ),
        ],
    )


class TestIngest:
    def test_ingest_creates_entities_and_claims(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        result = EvidenceIngestor(store).ingest(
            INV, parse_output(), artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        assert isinstance(result, IngestResult)
        assert result.entities_seen == 3
        assert result.new_claims >= 4
        assert len(store.list_entities(INV)) >= 4  # email, service, username + mail domain
        assert result.relation_claims == 1

    def test_identity_claims_are_evidence_backed(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        EvidenceIngestor(store).ingest(
            INV, parse_output(), artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        identity_claims = [c for c in store.list_claims(INV)
                           if c.predicate == "IDENTIFIED_AS"]
        assert identity_claims
        for claim in identity_claims:
            assert claim.artifact_ids == [artifact]
            assert claim.status == EpistemicStatus.SINGLE_SOURCE_LEAD

    def test_attributes_become_claims(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        EvidenceIngestor(store).ingest(
            INV, parse_output(), artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        attrs = [c for c in store.list_claims(INV)
                 if c.predicate.startswith("HAS_ATTRIBUTE:")]
        keys = {c.predicate.split(":", 1)[1] for c in attrs}
        assert "verified" in keys
        assert "registered" in keys

    def test_relation_becomes_edge_claim(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        EvidenceIngestor(store).ingest(
            INV, parse_output(), artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        edges = store.get_edges(INV)
        predicates = {edge.predicate for edge in edges}
        assert "REGISTERED_ON" in predicates

    def test_derived_nodes_created(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        EvidenceIngestor(store).ingest(
            INV, parse_output(), artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        domain = store.get_entity_by_value(INV, "domain", "example.com")
        assert domain is not None

    def test_second_tool_corroborates_identity(self, store_factory):
        store = store_factory()
        artifact1 = bootstrap(store)
        artifact2 = EvidenceArtifact(
            artifact_id="art_maigret", investigation_id=INV,
            source_tool="maigret", invocation_params_hash="h2",
            timestamp_utc=utc_now(), raw_output_sha256="d" * 64,
            parser_version="2.0.0",
        )
        store.add_artifact(artifact2)
        output = parse_output()
        ingestor = EvidenceIngestor(store)
        ingestor.ingest(INV, output, artifact_id=artifact1, tool_id="holehe",
                       accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        ingestor.ingest(INV, output, artifact_id=artifact2.artifact_id,
                       tool_id="maigret", accepted_types=[EntityType.EMAIL],
                       timestamp=utc_now())
        entity = store.get_entity_by_value(INV, "email", "target@example.com")
        identity = [c for c in store.list_claims(INV, subject_id=entity.entity_id)
                    if c.predicate == "IDENTIFIED_AS"][0]
        assert identity.status in (EpistemicStatus.CORROBORATED, EpistemicStatus.CONFIRMED)
        assert identity.confidence >= 0.85
        assert len(identity.independent_sources) == 2
        assert store.count_entities(INV) == len(store.list_entities(INV))  # no dupes

    def test_tool_confidence_does_not_override_epistemic_math(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        output = ParseOutput(entities=[EntityCandidate(
            type=EntityType.DOMAIN, value="highconf.example", confidence=0.99,
            evidence="claimed certainty")])
        EvidenceIngestor(store).ingest(
            INV, output, artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.DOMAIN], timestamp=utc_now())
        entity = store.get_entity_by_value(INV, "domain", "highconf.example")
        claim = [c for c in store.list_claims(INV, subject_id=entity.entity_id)
                 if c.predicate == "IDENTIFIED_AS"][0]
        assert claim.confidence <= 0.65  # single source cap still applies

    def test_empty_output_is_valid(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        result = EvidenceIngestor(store).ingest(
            INV, ParseOutput(), artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        assert result.new_claims == 0
        assert result.new_entity_ids == []

    def test_bad_entity_does_not_kill_batch(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        output = ParseOutput(entities=[
            EntityCandidate(type=EntityType.EMAIL, value="", confidence=0.5),
            EntityCandidate(type=EntityType.EMAIL, value="good@example.com",
                            confidence=0.8),
        ])
        result = EvidenceIngestor(store).ingest(
            INV, output, artifact_id=artifact, tool_id="holehe",
            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        assert store.get_entity_by_value(INV, "email", "good@example.com") is not None
        assert result.warnings  # empty value recorded as a warning

    def test_duplicate_ingest_does_not_duplicate_entities(self, store_factory):
        store = store_factory()
        artifact = bootstrap(store)
        ingestor = EvidenceIngestor(store)
        output = parse_output()
        for _ in range(3):
            ingestor.ingest(INV, output, artifact_id=artifact, tool_id="holehe",
                            accepted_types=[EntityType.EMAIL], timestamp=utc_now())
        emails = store.list_entities(INV, types=[EntityType.EMAIL])
        assert len(emails) == 1
        assert store.count_claims(INV) == len(store.list_claims(INV))

    def test_invocation_hash_is_deterministic(self):
        assert invocation_hash("holehe", {"email": "a@b.com"}) == \
            invocation_hash("holehe", {"email": "a@b.com"})
        assert invocation_hash("holehe", {"email": "a@b.com"}) != \
            invocation_hash("holehe", {"email": "c@d.com"})
