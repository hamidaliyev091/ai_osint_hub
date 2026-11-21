"""Phase 8 tests — multi-clue intake, provenance linking, bounded permutations."""

from __future__ import annotations

import asyncio

import pytest

from hub.erkg.graph import GraphView
from hub.intake import (
    MAX_HYPOTHESIS_CONFIDENCE,
    USER_PROVIDED_SEED,
    MultiClueIntake,
    StructuredSeeds,
)
from hub.intake import HypothesisDraft
from hub.investigation.engine import InvestigationEngine
from hub.models import EntityType, EpistemicStatus
from tests.mock_tools import (
    MockRunner,
    empty_output,
    make_capability,
    parse_mock,
)

MESSY = (
    "Target is Linus Torvalds, goes by torvalds, works at Linux Foundation "
    "in Portland, domain kernel.org, contact linus@kernel.org, "
    "phone +14155552671, see https://kernel.org/contact and @torvalds"
)


class TestFreeTextExtraction:
    def test_extracts_all_seed_types(self):
        clues = MultiClueIntake().extract(MESSY)
        by_type: dict[EntityType, set[str]] = {}
        for clue in clues:
            by_type.setdefault(clue.entity_type, set()).add(clue.value.lower())
        assert "linus torvalds" in by_type.get(EntityType.PERSON, set())
        assert "torvalds" in by_type.get(EntityType.USERNAME, set())
        assert "linus@kernel.org" in by_type.get(EntityType.EMAIL, set())
        assert "kernel.org" in by_type.get(EntityType.DOMAIN, set())
        assert "linux foundation" in by_type.get(EntityType.ORGANIZATION, set())
        assert "portland" in by_type.get(EntityType.LOCATION, set())
        assert "+14155552671" in by_type.get(EntityType.PHONE, set())
        assert any("https://kernel.org" in url
                   for url in by_type.get(EntityType.URL, set()))

    def test_ip_extraction(self):
        clues = MultiClueIntake().extract("server 93.184.216.34 and 2606:4700::1")
        ips = {clue.value.lower() for clue in clues if clue.entity_type == EntityType.IP}
        assert "93.184.216.34" in ips
        assert "2606:4700::1" in ips

    def test_prose_does_not_fallback_to_bare_username(self):
        # Phase 15: bare prose words are never inferred as handles.
        clues = MultiClueIntake().extract("investigate unknownhandle please")
        assert not any(clue.entity_type == EntityType.USERNAME for clue in clues)
        # A standalone target still works (no explicit cue needed).
        clues = MultiClueIntake().extract("unknownhandle")
        assert any(clue.entity_type == EntityType.USERNAME for clue in clues)

    def test_bounds_respected(self):
        text = " ".join(f"user{i}@example.com" for i in range(40))
        clues = MultiClueIntake().extract(text)
        emails = [clue for clue in clues if clue.entity_type == EntityType.EMAIL]
        assert len(emails) <= 15


class TestStructuredSeeds:
    def test_from_mapping_accepts_strings_and_lists(self):
        fields = StructuredSeeds.from_mapping({
            "name": "Linus Torvalds",
            "usernames": "torvalds, linus",
            "emails": ["linus@kernel.org"],
            "domains": "kernel.org",
            "phone": "+14155552671",
            "org": "Linux Foundation",
            "location": "Portland",
        })
        assert fields.name == "Linus Torvalds"
        assert fields.usernames == ["torvalds", "linus"]
        assert fields.emails == ["linus@kernel.org"]
        assert fields.domains == ["kernel.org"]
        assert fields.phones == ["+14155552671"]
        assert fields.organizations == ["Linux Foundation"]
        assert fields.locations == ["Portland"]

    def test_multi_clue_provenance(self):
        candidates = MultiClueIntake().seed_candidates(
            "",
            {"name": "Linus Torvalds", "emails": ["linus@kernel.org"],
             "domains": ["kernel.org"], "usernames": ["torvalds"]},
        )
        assert candidates
        for candidate in candidates:
            provenance = candidate.metadata["provenance"]
            assert provenance in {
                USER_PROVIDED_SEED, "EMAIL_DERIVED_DOMAIN",
                "EMAIL_DERIVED_USERNAME",
            }
            assert candidate.attributes["provenance"] == provenance
            assert candidate.evidence.startswith(f"[{provenance}")

    def test_primary_person_name(self):
        intake = MultiClueIntake()
        assert intake.primary_person_name("", {"name": "Linus Torvalds"}) == "Linus Torvalds"
        assert intake.primary_person_name(MESSY) == "Linus Torvalds"


class TestHypothesisPermutations:
    def test_bounded_counts_and_confidence(self):
        drafts = MultiClueIntake().hypothesis_drafts(
            "Subject is Linus Torvalds, domain kernel.org, suffix 91")
        usernames = [d for d in drafts if d.entity_type == EntityType.USERNAME]
        emails = [d for d in drafts if d.entity_type == EntityType.EMAIL]
        assert 1 <= len(usernames) <= 20
        assert 1 <= len(emails) <= 10
        assert all(draft.confidence <= MAX_HYPOTHESIS_CONFIDENCE for draft in drafts)
        assert any("torvalds" in draft.value for draft in usernames)
        assert any(draft.value.endswith("@kernel.org") for draft in emails)

    def test_deterministic(self):
        intake = MultiClueIntake()
        first = [(d.entity_type, d.value, d.confidence)
                 for d in intake.hypothesis_drafts(MESSY)]
        second = [(d.entity_type, d.value, d.confidence)
                  for d in intake.hypothesis_drafts(MESSY)]
        assert first == second

    def test_no_person_no_permutations(self):
        drafts = MultiClueIntake().hypothesis_drafts("domain only example.com")
        assert drafts == []

    def test_confidence_clamped(self):
        draft = HypothesisDraft(EntityType.USERNAME, "x", confidence=0.99)
        assert draft.confidence <= MAX_HYPOTHESIS_CONFIDENCE


class TestEngineIntegration:
    @pytest.fixture()
    def engine_factory(self, tmp_path, isolated_mock_registry):
        isolated_mock_registry(
            make_capability("mock_username", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.8),
            make_capability("mock_email", [EntityType.EMAIL],
                            [EntityType.BREACH_RECORD], prior_yield=0.7),
        )

        def build():
            return InvestigationEngine(
                runner=MockRunner(default=lambda cap, params: empty_output()),
                parser_resolver=lambda capability: parse_mock,
                health_probe=lambda capability: True,
                state_root=tmp_path / "state",
            )

        return build

    def test_structured_seeds_initialized_and_linked(self, engine_factory):
        engine = engine_factory()
        created = asyncio.run(engine.create(
            MESSY,
            {"min_pivot_threshold": 0.99},
            structured_seeds={"organizations": ["Linux Foundation"],
                              "locations": ["Portland"],
                              "domains": ["kernel.org"]},
        ))
        store = engine.open_store(created.target_id)
        try:
            entities = store.list_entities(created.target_id)
            values = {entity.canonical_value for entity in entities}
            assert "linus torvalds" in values
            assert "torvalds" in values
            assert "linus@kernel.org" in values
            assert "kernel.org" in values
            assert "linux foundation" in values
            assert "portland" in values
            person = store.get_entity_by_value(created.target_id, "person",
                                               "linus torvalds")
            assert person is not None
            assert person.metadata.get("provenance") == USER_PROVIDED_SEED
            claims = store.list_claims(created.target_id, subject_id=person.entity_id)
            predicates = {claim.predicate for claim in claims}
            assert {"HAS_USERNAME", "HAS_EMAIL", "OWNS", "LOCATED_IN"}.issubset(predicates)
            # All user clues share the seed artifact and provenance attribute.
            seed_claims = [claim for claim in claims if claim.artifact_ids]
            assert seed_claims
            for claim in seed_claims:
                artifacts = store.get_claim_artifacts(claim.claim_id)
                assert artifacts and artifacts[0].source_tool == "seed"
        finally:
            store.close()

    def test_hypothesis_entities_linked_with_bounded_confidence(self, engine_factory):
        engine = engine_factory()
        created = asyncio.run(engine.create(
            "Subject is Linus Torvalds, domain kernel.org, suffix 91",
            {"min_pivot_threshold": 0.99},
        ))
        store = engine.open_store(created.target_id)
        try:
            hypotheses = store.list_hypotheses(created.target_id)
            # Phase-8 hypothesis *claims* (not pivot hypotheses) are used for
            # speculative username/email entities.
            claims = store.list_claims(created.target_id)
            speculative = [claim for claim in claims
                           if claim.status == EpistemicStatus.HYPOTHESIS]
            assert speculative
            assert all(claim.confidence <= MAX_HYPOTHESIS_CONFIDENCE
                       for claim in speculative)
            person = store.get_entity_by_value(created.target_id, "person",
                                               "linus torvalds")
            linked = [claim for claim in claims
                      if claim.subject_id == person.entity_id
                      and claim.status == EpistemicStatus.HYPOTHESIS]
            assert linked
            graph = GraphView(store, created.target_id,
                              [person.entity_id])
            username_entity = store.get_entity_by_value(created.target_id,
                                                        "username", "torvalds")
            assert username_entity is not None
            assert graph.hop_distance(username_entity.entity_id) <= 1
        finally:
            store.close()

    def test_free_text_only_investigation_seeds_graph(self, engine_factory):
        engine = engine_factory()
        created = asyncio.run(engine.create("goes by torvalds, works at Linux Foundation"))
        store = engine.open_store(created.target_id)
        try:
            values = {entity.canonical_value
                      for entity in store.list_entities(created.target_id)}
            assert "torvalds" in values
            assert "linux foundation" in values
        finally:
            store.close()
