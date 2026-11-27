"""ERKG store tests — WAL persistence, provenance, ledger, crash resume, graph."""

import threading
import time

import pytest

from hub.erkg.graph import GraphView
from hub.erkg.store import ERKGStore
from hub.models import (
    ClaimSource,
    EntityType,
    EpistemicStatus,
    ErrorCode,
    EvidenceArtifact,
    ExecutionRecord,
    ExecutionStatus,
    Hypothesis,
    HypothesisStatus,
    HypothesisType,
    InvestigationConfig,
    InvestigationState,
    IterationRecord,
    RunStatus,
    utc_now,
)

INV = "inv-001"


# ── helpers ─────────────────────────────────────────────────────────────

def make_investigation(store, target_id=INV):
    now = utc_now()
    state = InvestigationState(
        target_id=target_id, raw_input="seed target", created_at=now, updated_at=now,
        config=InvestigationConfig(target_id=target_id, raw_input="seed target"),
    )
    store.create_investigation(state)
    return state


def add_artifact(store, tool="holehe", suffix="1", *, investigation=INV,
                 snippet="raw evidence", sha=None):
    artifact = EvidenceArtifact(
        artifact_id=f"art_{tool}_{suffix}", investigation_id=investigation,
        source_tool=tool, invocation_params_hash=f"hash_{suffix}",
        timestamp_utc=utc_now(), raw_evidence_snippet=snippet,
        raw_output_sha256=sha or ("a" * 63 + suffix[-1]),
        parser_version="2.0.0",
    )
    store.add_artifact(artifact)
    return artifact.artifact_id


def add_entity(store, etype, value, entity_id=None, artifact_id=None, investigation=INV):
    from hub.erkg.resolution import canonical_entity_id
    from hub.models import Entity
    eid = entity_id or canonical_entity_id(etype, value)
    now = utc_now()
    entity = Entity(
        entity_id=eid, investigation_id=investigation, type=EntityType.coerce(etype),
        canonical_value=value, display_value=value, first_seen=now, last_seen=now,
        created_by_artifact=artifact_id,
    )
    store.insert_entity(investigation, entity,
                        alias_keys=[f"{EntityType.coerce(etype).value}:{value}"])
    return eid


# ══════════════════════════════════════════════════════════════════════
# Schema / WAL
# ══════════════════════════════════════════════════════════════════════

class TestSchemaAndPragmas:
    def test_wal_enabled(self, store_factory):
        store = store_factory()
        pragmas = store.pragmas()
        assert pragmas["journal_mode"].lower() == "wal"
        assert pragmas["synchronous"] == 1          # NORMAL
        assert pragmas["busy_timeout"] == 5000

    def test_schema_tables_exist(self, store_factory):
        store = store_factory()
        tables = {row[0] for row in store._query_all(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("investigations", "entities", "claims", "artifacts",
                      "execution_ledger", "hypotheses", "iterations", "contradictions"):
            assert table in tables

    def test_status_enum_enforced_at_db_level(self, store_factory):
        import sqlite3
        store = store_factory()
        make_investigation(store)
        with pytest.raises(sqlite3.IntegrityError):
            store._write(
                """INSERT INTO claims (claim_id, investigation_id, subject_id, predicate,
                   object_literal, status, confidence, first_seen, updated_at)
                   VALUES ('c1', 'inv-001', 's1', 'P', '\"x\"', 'BOGUS', 0.5, 't', 't')""")


# ══════════════════════════════════════════════════════════════════════
# Investigations
# ══════════════════════════════════════════════════════════════════════

class TestInvestigations:
    def test_roundtrip(self, store_factory):
        store = store_factory()
        make_investigation(store)
        loaded = store.get_investigation(INV)
        assert loaded is not None
        assert loaded.target_id == INV
        assert loaded.status == RunStatus.ACTIVE
        assert loaded.config.budgets.max_iterations == 20

    def test_missing_returns_none(self, store_factory):
        assert store_factory().get_investigation("nope") is None

    def test_bump_counters(self, store_factory):
        store = store_factory()
        make_investigation(store)
        store.bump_counters(INV, iterations=1, tool_calls=2)
        store.bump_counters(INV, iterations=2, tool_calls=3)
        loaded = store.get_investigation(INV)
        assert loaded.iteration_count == 3
        assert loaded.tool_calls == 5

    def test_finish(self, store_factory):
        store = store_factory()
        make_investigation(store)
        store.finish_investigation(INV, RunStatus.COMPLETED, "objectives_met")
        loaded = store.get_investigation(INV)
        assert loaded.status == RunStatus.COMPLETED
        assert loaded.stop_reason == "objectives_met"

    def test_objectives_roundtrip(self, store_factory):
        from hub.models import Objective
        store = store_factory()
        make_investigation(store)
        objectives = [Objective(objective_id="obj1", description="d", entity_id="e1")]
        store.set_objectives(INV, objectives)
        assert store.get_investigation(INV).objectives[0].objective_id == "obj1"


# ══════════════════════════════════════════════════════════════════════
# Artifacts / entities
# ══════════════════════════════════════════════════════════════════════

class TestArtifacts:
    def test_immutable_on_duplicate_id(self, store_factory):
        store = store_factory()
        make_investigation(store)
        first = add_artifact(store, snippet="original")
        # Attempt to overwrite the same artifact id with different content.
        duplicate = EvidenceArtifact(
            artifact_id=first, investigation_id=INV, source_tool="holehe",
            invocation_params_hash="other", timestamp_utc=utc_now(),
            raw_evidence_snippet="TAMPERED", raw_output_sha256="b" * 64,
            parser_version="9.9.9",
        )
        store.add_artifact(duplicate)
        loaded = store.get_artifact(first)
        assert loaded.raw_evidence_snippet == "original"
        assert loaded.raw_output_sha256 != "b" * 64

    def test_artifact_required_fields(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            EvidenceArtifact(
                artifact_id="x", source_tool="holehe", invocation_params_hash="h",
                timestamp_utc=utc_now(), raw_output_sha256="", parser_version="1",
            )


class TestEntities:
    def test_insert_and_read(self, store_factory):
        store = store_factory()
        make_investigation(store)
        eid = add_entity(store, "email", "a@b.com")
        entity = store.get_entity(eid)
        assert entity.type == EntityType.EMAIL
        assert store.count_entities(INV) == 1

    def test_unique_per_investigation_type_value(self, store_factory):
        store = store_factory()
        make_investigation(store)
        eid1 = add_entity(store, "email", "a@b.com")
        add_entity(store, "email", "a@b.com", entity_id="different-id")
        # UNIQUE(investigation, type, canonical_value) keeps the first row.
        assert store.count_entities(INV) == 1
        assert store.get_entity_by_value(INV, "email", "a@b.com").entity_id == eid1

    def test_alias_lookup(self, store_factory):
        store = store_factory()
        make_investigation(store)
        eid = add_entity(store, "email", "a@b.com")
        assert store.find_entity_by_alias(INV, "email:a@b.com") == eid

    def test_touch_appends_raw_values(self, store_factory):
        store = store_factory()
        make_investigation(store)
        eid = add_entity(store, "email", "a@b.com")
        store.touch_entity(eid, raw_value="A@B.com", aliases=["A@B.com"],
                           alias_keys=["email:a@b.com"], timestamp=utc_now())
        entity = store.get_entity(eid)
        assert "A@B.com" in entity.raw_values

    def test_list_filter_by_type(self, store_factory):
        store = store_factory()
        make_investigation(store)
        add_entity(store, "email", "a@b.com")
        add_entity(store, "username", "user")
        emails = store.list_entities(INV, types=[EntityType.EMAIL])
        assert len(emails) == 1 and emails[0].type == EntityType.EMAIL


# ══════════════════════════════════════════════════════════════════════
# Claims / provenance / contradictions
# ══════════════════════════════════════════════════════════════════════

class TestClaims:
    def _setup(self, store):
        make_investigation(store)
        artifact = add_artifact(store, "holehe")
        subject = add_entity(store, "username", "user", artifact_id=artifact)
        return artifact, subject

    def test_single_source_claim(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        claim = store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:registered",
                                   object_literal=True, artifact_id=artifact,
                                   source_tool="holehe")
        assert claim.status == EpistemicStatus.SINGLE_SOURCE_LEAD
        assert claim.artifact_ids == [artifact]
        assert claim.confidence <= 0.65

    def test_corroboration_across_tools(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        artifact2 = add_artifact(store, "maigret", suffix="2")
        store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:registered",
                           object_literal=True, artifact_id=artifact,
                           source_tool="holehe")
        claim = store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:registered",
                                   object_literal=True, artifact_id=artifact2,
                                   source_tool="maigret")
        assert claim.status in (EpistemicStatus.CORROBORATED, EpistemicStatus.CONFIRMED)
        assert claim.confidence >= 0.85
        assert len(claim.artifact_ids) == 2

    def test_claim_requires_artifact(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        with pytest.raises(ValueError):
            store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:x", object_literal=1,
                               artifact_id=None, source_tool="holehe")

    def test_planner_hypothesis_claim_needs_no_artifact(self, store_factory):
        store = store_factory()
        _, subject = self._setup(store)
        claim = store.add_hypothesis_claim(INV, subject, "HAS_EMAIL",
                                           object_literal="guess@example.com")
        assert claim.status == EpistemicStatus.HYPOTHESIS
        assert claim.confidence <= 0.40

    def test_functional_predicate_contradiction(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        artifact2 = add_artifact(store, "maigret", suffix="2")
        # HAS_EMAIL is multi-valued (non-functional) so multiple verified emails never contradict.
        e1 = store.upsert_claim(INV, subject, "HAS_EMAIL",
                                object_literal="a@example.com",
                                artifact_id=artifact, source_tool="holehe")
        e2 = store.upsert_claim(INV, subject, "HAS_EMAIL",
                                object_literal="b@example.com",
                                artifact_id=artifact2, source_tool="maigret")
        assert store.list_contradictions(INV) == []
        assert store.get_claim(e1.claim_id).status != EpistemicStatus.CONTRADICTED
        assert store.get_claim(e2.claim_id).status != EpistemicStatus.CONTRADICTED

        # Single-valued functional predicates (such as HAS_PHONE) still flag contradictions.
        first = store.upsert_claim(INV, subject, "HAS_PHONE",
                                   object_literal="+15550001111",
                                   artifact_id=artifact, source_tool="holehe")
        second = store.upsert_claim(INV, subject, "HAS_PHONE",
                                    object_literal="+15550002222",
                                    artifact_id=artifact2, source_tool="maigret")
        contradictions = store.list_contradictions(INV)
        assert len(contradictions) == 1
        assert store.get_claim(first.claim_id).status == EpistemicStatus.CONTRADICTED
        assert store.get_claim(second.claim_id).status == EpistemicStatus.CONTRADICTED
        assert store.get_claim(first.claim_id).confidence == 0.30

    def test_nonfunctional_predicate_allows_multiple_objects(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        service = add_entity(store, "service", "github")
        store.upsert_claim(INV, subject, "REGISTERED_ON", object_id=service,
                           artifact_id=artifact, source_tool="holehe")
        service2 = add_entity(store, "service", "twitter")
        store.upsert_claim(INV, subject, "REGISTERED_ON", object_id=service2,
                           artifact_id=artifact, source_tool="holehe")
        assert len(store.list_claims(INV, predicate="REGISTERED_ON")) == 2
        assert store.list_contradictions(INV) == []

    def test_edges_only_for_object_claims(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        service = add_entity(store, "service", "github")
        store.upsert_claim(INV, subject, "REGISTERED_ON", object_id=service,
                           artifact_id=artifact, source_tool="holehe")
        store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:registered",
                           object_literal=True, artifact_id=artifact,
                           source_tool="holehe")
        edges = store.get_edges(INV)
        assert len(edges) == 1 and edges[0].object_id == service

    def test_status_counts(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:a", object_literal=1,
                           artifact_id=artifact, source_tool="holehe")
        counts = store.claim_status_counts(INV)
        assert counts.get("SINGLE_SOURCE_LEAD") == 1

    def test_claim_sources_have_artifact_provenance(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        claim = store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:a",
                                   object_literal=1, artifact_id=artifact,
                                   source_tool="holehe", snippet="proof line")
        sources = store.get_claim_sources(claim.claim_id)
        assert sources[0].artifact_id == artifact
        assert sources[0].snippet == "proof line"
        assert store.get_claim_artifacts(claim.claim_id)[0].artifact_id == artifact

    def test_integrity_ok_for_evidence_backed_claims(self, store_factory):
        store = store_factory()
        artifact, subject = self._setup(store)
        store.upsert_claim(INV, subject, "HAS_ATTRIBUTE:a", object_literal=1,
                           artifact_id=artifact, source_tool="holehe")
        report = store.integrity_report(INV)
        assert report["ok"] is True
        assert report["claims_without_artifacts"] == []


# ══════════════════════════════════════════════════════════════════════
# Execution ledger
# ══════════════════════════════════════════════════════════════════════

class TestExecutionLedger:
    def _record(self, status=ExecutionStatus.SUCCESS, tool="holehe", entity="e1",
                ph="p1", code=None):
        return ExecutionRecord(
            investigation_id=INV, entity_id=entity, tool_id=tool, param_hash=ph,
            status=status, error_code=code, artifact_id=None, run_at=utc_now(),
            duration_ms=12,
        )

    def test_record_and_lookup(self, store_factory):
        store = store_factory()
        make_investigation(store)
        store.record_execution(self._record())
        assert store.has_execution(INV, "e1", "holehe", "p1") is True
        loaded = store.get_execution(INV, "e1", "holehe", "p1")
        assert loaded.status == ExecutionStatus.SUCCESS

    def test_duplicate_run_blocked(self, store_factory):
        store = store_factory()
        make_investigation(store)
        store.record_execution(self._record(status=ExecutionStatus.EMPTY))
        assert store.has_execution(INV, "e1", "holehe", "p1") is True

    def test_upsert_same_key(self, store_factory):
        store = store_factory()
        make_investigation(store)
        store.record_execution(self._record(status=ExecutionStatus.TIMEOUT,
                                            code=ErrorCode.TIMEOUT))
        store.record_execution(self._record(status=ExecutionStatus.SUCCESS))
        assert store.count_tool_calls(INV) == 1
        assert store.get_execution(INV, "e1", "holehe", "p1").status == ExecutionStatus.SUCCESS

    def test_status_filter(self, store_factory):
        store = store_factory()
        make_investigation(store)
        store.record_execution(self._record(status=ExecutionStatus.ERROR, ph="p1"))
        store.record_execution(self._record(status=ExecutionStatus.SUCCESS, ph="p2"))
        errored = store.list_ledger(INV, statuses=[ExecutionStatus.ERROR])
        assert len(errored) == 1
        assert store.ledger_status_counts(INV) == {"ERROR": 1, "SUCCESS": 1}

    def test_empty_status_enum_only_four(self):
        assert {s.value for s in ExecutionStatus} == {"SUCCESS", "EMPTY", "TIMEOUT", "ERROR"}

    def test_try_claim_execution_is_exclusive(self, store_factory):
        store = store_factory()
        make_investigation(store)
        record = self._record()
        assert store.try_claim_execution(record) is True
        assert store.try_claim_execution(record) is False
        assert store.has_execution(INV, "e1", "holehe", "p1") is True
        # Final outcome overwrite keeps exactly one ledger row.
        store.record_execution(record.model_copy(update={"status": ExecutionStatus.SUCCESS}))
        assert store.list_ledger(INV)[0].status == ExecutionStatus.SUCCESS
        assert store.count_tool_calls(INV) == 1

    def test_two_threads_only_one_claims(self, tmp_path):
        db_path = tmp_path / "claim.sqlite3"
        setup = ERKGStore(db_path)
        make_investigation(setup)
        setup.close()
        results: list[bool] = []
        barrier = threading.Barrier(2)

        def worker():
            store = ERKGStore(db_path)
            record = ExecutionRecord(
                investigation_id=INV, entity_id="e1", tool_id="holehe",
                param_hash="p1", status=ExecutionStatus.ERROR,
                error_code=ErrorCode.SPAWN_ERROR, run_at=utc_now(),
                error_message="in_flight",
            )
            barrier.wait(timeout=10)
            results.append(store.try_claim_execution(record))
            store.close()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert sorted(results) == [False, True]


# ══════════════════════════════════════════════════════════════════════
# Hypotheses / iterations
# ══════════════════════════════════════════════════════════════════════

class TestHypotheses:
    def test_lifecycle(self, store_factory):
        store = store_factory()
        make_investigation(store)
        now = utc_now()
        hypothesis = Hypothesis(
            hypothesis_id="hyp1", investigation_id=INV,
            hypothesis_type=HypothesisType.CORROBORATION,
            question="is it real?", target_entity_id="e1",
            proposed_tool_ids=["holehe"], created_at=now, updated_at=now,
        )
        store.add_hypothesis(hypothesis)
        assert store.list_hypotheses(INV, statuses=[HypothesisStatus.OPEN])[0].hypothesis_id == "hyp1"
        store.update_hypothesis("hyp1", status=HypothesisStatus.SUPPORTED,
                                closing_note="two tools agree")
        loaded = store.get_hypothesis("hyp1")
        assert loaded.status == HypothesisStatus.SUPPORTED
        assert loaded.closing_note == "two tools agree"

    def test_exists_guard_prevents_duplicates(self, store_factory):
        store = store_factory()
        make_investigation(store)
        assert not store.hypothesis_exists(INV, "CORROBORATION", "e1", None)
        now = utc_now()
        store.add_hypothesis(Hypothesis(
            hypothesis_id="h", investigation_id=INV,
            hypothesis_type=HypothesisType.CORROBORATION, question="q",
            target_entity_id="e1", created_at=now, updated_at=now,
        ))
        assert store.hypothesis_exists(INV, "CORROBORATION", "e1", None)


class TestIterations:
    def test_record_and_list(self, store_factory):
        store = store_factory()
        make_investigation(store)
        for i in (1, 2):
            store.record_iteration(INV, IterationRecord(
                iteration=i, timestamp_utc=utc_now(),
                action={"tool": "holehe"}, result={"status": "SUCCESS"},
            ))
        iterations = store.list_iterations(INV)
        assert [it.iteration for it in iterations] == [1, 2]


# ══════════════════════════════════════════════════════════════════════
# Crash resume & concurrency
# ══════════════════════════════════════════════════════════════════════

class TestCrashResume:
    def test_rolled_back_transaction_leaves_no_partial_state(self, store_factory, tmp_path):
        store = store_factory()
        make_investigation(store)
        artifact = add_artifact(store)
        add_entity(store, "email", "committed@example.com", artifact_id=artifact)
        try:
            with store.transaction():
                add_entity(store, "email", "uncommitted@example.com", artifact_id=artifact)
                store.record_execution(ExecutionRecord(
                    investigation_id=INV, entity_id="e", tool_id="holehe",
                    param_hash="p", status=ExecutionStatus.SUCCESS, run_at=utc_now(),
                ))
                store.bump_counters(INV, iterations=1)
                raise RuntimeError("simulated crash mid-iteration")
        except RuntimeError:
            pass
        # Committed data is intact; partial iteration is gone.
        assert store.get_entity_by_value(INV, "email", "committed@example.com") is not None
        assert store.get_entity_by_value(INV, "email", "uncommitted@example.com") is None
        assert store.count_tool_calls(INV) == 0
        assert store.get_investigation(INV).iteration_count == 0

    def test_reopen_after_close_preserves_state(self, store_factory, tmp_path):
        store = store_factory()
        make_investigation(store)
        artifact = add_artifact(store)
        eid = add_entity(store, "email", "persist@example.com", artifact_id=artifact)
        store.upsert_claim(INV, eid, "HAS_ATTRIBUTE:verified", object_literal=True,
                           artifact_id=artifact, source_tool="holehe")
        store.bump_counters(INV, iterations=2, tool_calls=2)
        store.close()

        reopened = ERKGStore(tmp_path / "erkg.sqlite3")
        loaded = reopened.get_investigation(INV)
        assert loaded.iteration_count == 2
        assert reopened.get_entity_by_value(INV, "email", "persist@example.com") is not None
        assert reopened.count_claims(INV) == 1
        reopened.close()

    def test_pragmas_survive_reopen(self, store_factory, tmp_path):
        store = store_factory()
        make_investigation(store)
        store.close()
        reopened = ERKGStore(tmp_path / "erkg.sqlite3")
        assert reopened.pragmas()["journal_mode"].lower() == "wal"
        assert reopened.get_investigation(INV) is not None
        reopened.close()


class TestConcurrency:
    def test_concurrent_writers_no_lock_crash(self, tmp_path):
        db_path = tmp_path / "concurrent.sqlite3"
        setup = ERKGStore(db_path)
        make_investigation(setup)
        artifact = add_artifact(setup)
        setup.close()

        errors: list[BaseException] = []

        def worker(worker_id: int):
            try:
                store = ERKGStore(db_path)
                for item in range(10):
                    with store.transaction():
                        add_entity(store, "email",
                                   f"w{worker_id}_{item}@example.com",
                                   artifact_id=artifact)
                store.close()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert errors == [], f"concurrent writers raised: {errors}"
        check = ERKGStore(db_path)
        assert check.count_entities(INV) == 60
        check.close()


# ══════════════════════════════════════════════════════════════════════
# Graph view
# ══════════════════════════════════════════════════════════════════════

class TestGraphView:
    def _build(self, store):
        make_investigation(store)
        artifact = add_artifact(store)
        seed = add_entity(store, "email", "seed@example.com", entity_id="email:seed",
                          artifact_id=artifact)
        service = add_entity(store, "service", "github", entity_id="service:github",
                             artifact_id=artifact)
        username = add_entity(store, "username", "seeduser", entity_id="username:seeduser",
                              artifact_id=artifact)
        distant = add_entity(store, "domain", "far.example.com",
                             entity_id="domain:far", artifact_id=artifact)
        store.upsert_claim(INV, seed, "REGISTERED_ON", object_id=service,
                           artifact_id=artifact, source_tool="holehe")
        store.upsert_claim(INV, seed, "HAS_USERNAME", object_id=username,
                           artifact_id=artifact, source_tool="holehe")
        store.upsert_claim(INV, username, "ASSOCIATED_WITH", object_id=distant,
                           artifact_id=artifact, source_tool="maigret")
        return seed, service, username, distant

    def test_hop_distances(self, store_factory):
        store = store_factory()
        seed, service, username, distant = self._build(store)
        view = GraphView(store, INV, seed_entity_ids=[seed])
        assert view.hop_distance(seed) == 0
        assert view.hop_distance(service) == 1
        assert view.hop_distance(username) == 1
        assert view.hop_distance(distant) == 2

    def test_disconnected_entity_treated_far(self, store_factory):
        store = store_factory()
        seed, *_ = self._build(store)
        add_entity(store, "domain", "island.example", entity_id="domain:island")
        view = GraphView(store, INV, seed_entity_ids=[seed])
        assert view.hop_distance("domain:island") >= 3

    def test_neighbors(self, store_factory):
        store = store_factory()
        seed, service, username, _ = self._build(store)
        view = GraphView(store, INV, seed_entity_ids=[seed])
        assert set(view.neighbors(seed)) == {service, username}

    def test_shares_corroborated_identifier(self, store_factory):
        store = store_factory()
        seed, service, username, distant = self._build(store)
        add_artifact(store, "maigret", suffix="2")
        artifact2 = "art_maigret_2"
        store.upsert_claim(INV, seed, "HAS_ATTRIBUTE:verified", object_literal=True,
                           artifact_id=add_artifact(store, "holehe", suffix="3"),
                           source_tool="holehe")
        store.upsert_claim(INV, seed, "HAS_ATTRIBUTE:verified", object_literal=True,
                           artifact_id=artifact2, source_tool="maigret")
        view = GraphView(store, INV, seed_entity_ids=[seed])
        # seed itself and its direct neighbours share seed identifiers/aliases
        assert view.shares_corroborated_identifier(seed) is True
        assert view.shares_corroborated_identifier(distant) is False

    def test_local_neighborhood(self, store_factory):
        store = store_factory()
        seed, service, username, _ = self._build(store)
        view = GraphView(store, INV, seed_entity_ids=[seed])
        neighborhood = view.local_neighborhood(seed, radius=1)
        assert neighborhood["entity"] == seed
        ids = {node["entity_id"] for node in neighborhood["nodes"]}
        assert seed in ids and service in ids

    def test_summary(self, store_factory):
        store = store_factory()
        seed, *_ = self._build(store)
        view = GraphView(store, INV, seed_entity_ids=[seed])
        summary = view.summary()
        assert summary["total_nodes"] == 4
        assert summary["total_edges"] == 3
        assert summary["seed_entities"] == 1

    def test_stats(self, store_factory):
        store = store_factory()
        self._build(store)
        stats = store.stats(INV)
        assert stats["entities"] == 4
        assert stats["claims"] == 3
