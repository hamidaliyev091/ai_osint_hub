"""Hypothesis generation + correlation tests."""

import pytest

from hub.investigation.hypotheses import (
    HypothesisGenerator,
    correlate_after_run,
    mark_stale_hypotheses,
)
from hub.models import (
    EntityType,
    EpistemicStatus,
    ExecutionStatus,
    HypothesisStatus,
    HypothesisType,
)
from tests import support
from tests.mock_tools import make_capability


@pytest.fixture()
def registry(isolated_mock_registry):
    isolated_mock_registry(
        make_capability("mock_services", [EntityType.EMAIL], [EntityType.SERVICE]),
        make_capability("mock_breach", [EntityType.EMAIL], [EntityType.BREACH_RECORD]),
        make_capability("mock_username", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE]),
    )


def seeded_store(store):
    support.bootstrap(store)
    seed = support.entity(store, EntityType.EMAIL, "target@example.com")
    support.claim(store, seed.entity_id, "IDENTIFIED_AS",
                  object_literal="target@example.com", tools=("holehe",))
    support.set_seeds(store, [seed.entity_id])
    return store.get_investigation(support.DEFAULT_INV), seed


class TestGeneration:
    def test_corroboration_hypothesis_for_lead_claim(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        graph = support.graph(store, [seed.entity_id])
        generator = HypothesisGenerator(store)
        new = generator.generate(investigation, graph,
                                 available_tool_ids=["mock_services", "mock_breach"])
        types = {hypothesis.hypothesis_type for hypothesis in new}
        assert HypothesisType.CORROBORATION in types
        corroboration = next(h for h in new
                             if h.hypothesis_type == HypothesisType.CORROBORATION)
        assert corroboration.target_claim_id is not None
        assert "mock_services" in corroboration.proposed_tool_ids
        assert "holehe" not in corroboration.proposed_tool_ids

    def test_expansion_hypotheses_for_seed(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        graph = support.graph(store, [seed.entity_id])
        new = HypothesisGenerator(store).generate(
            investigation, graph, available_tool_ids=["mock_services"])
        expansions = [h for h in new if h.hypothesis_type == HypothesisType.EXPANSION]
        assert expansions and expansions[0].target_entity_id == seed.entity_id

    def test_identity_link_hypothesis_creates_username(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        graph = support.graph(store, [seed.entity_id])
        new = HypothesisGenerator(store).generate(
            investigation, graph, available_tool_ids=["mock_username"])
        identity = [h for h in new if h.hypothesis_type == HypothesisType.IDENTITY_LINK]
        assert identity
        username = store.get_entity_by_value(support.DEFAULT_INV, EntityType.USERNAME,
                                             "target")
        assert username is not None
        claims = store.list_claims(support.DEFAULT_INV, subject_id=username.entity_id)
        assert any(claim.status == EpistemicStatus.HYPOTHESIS for claim in claims)
        assert identity[0].target_entity_id == username.entity_id

    def test_no_duplicate_hypotheses(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        generator = HypothesisGenerator(store)
        graph = support.graph(store, [seed.entity_id])
        first = generator.generate(investigation, graph,
                                   available_tool_ids=["mock_services"])
        second = generator.generate(investigation, graph,
                                    available_tool_ids=["mock_services"])
        assert first
        assert second == []
        assert len(store.list_hypotheses(support.DEFAULT_INV)) == len(first)

    def test_resolution_hypothesis_for_contradiction(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        username = support.entity(store, EntityType.USERNAME, "conflict")
        support.claim(store, username.entity_id, "HAS_PHONE",
                      object_literal="+15550001111", tools=("holehe",))
        support.claim(store, username.entity_id, "HAS_PHONE",
                      object_literal="+15550002222", tools=("maigret",))
        graph = support.graph(store, [seed.entity_id])
        new = HypothesisGenerator(store).generate(
            investigation, graph, available_tool_ids=["mock_username"])
        resolutions = [h for h in new if h.hypothesis_type == HypothesisType.RESOLUTION]
        assert resolutions
        assert resolutions[0].target_entity_id == username.entity_id

    def test_no_hypotheses_when_no_tools_available(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        graph = support.graph(store, [seed.entity_id])
        new = HypothesisGenerator(store).generate(investigation, graph,
                                                   available_tool_ids=[])
        assert new == []


class TestCorrelation:
    def test_corroboration_supported(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        graph = support.graph(store, [seed.entity_id])
        generator = HypothesisGenerator(store)
        new = generator.generate(investigation, graph,
                                 available_tool_ids=["mock_services"])
        hypothesis = next(h for h in new
                          if h.hypothesis_type == HypothesisType.CORROBORATION)
        # Simulate independent corroboration of the target claim.
        target_claim = store.get_claim(hypothesis.target_claim_id)
        support.claim(store, seed.entity_id, target_claim.predicate,
                      object_literal="target@example.com",
                      tools=("mock_services",))
        closed = correlate_after_run(
            store, support.DEFAULT_INV, executed_entity_id=seed.entity_id,
            executed_tool_id="mock_services", run_status=ExecutionStatus.SUCCESS,
            new_claims=2)
        updated = store.get_hypothesis(hypothesis.hypothesis_id)
        assert updated.status == HypothesisStatus.SUPPORTED
        # Corroboration hypothesis is already closed; expansion ones may close too.
        assert closed >= 1

    def test_expansion_refuted_by_empty_run(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        graph = support.graph(store, [seed.entity_id])
        new = HypothesisGenerator(store).generate(investigation, graph,
                                                   available_tool_ids=["mock_services"])
        expansion = next(h for h in new
                         if h.hypothesis_type == HypothesisType.EXPANSION)
        correlate_after_run(store, support.DEFAULT_INV,
                            executed_entity_id=expansion.target_entity_id,
                            executed_tool_id=expansion.proposed_tool_ids[0],
                            run_status=ExecutionStatus.EMPTY, new_claims=0)
        assert store.get_hypothesis(expansion.hypothesis_id).status == HypothesisStatus.REFUTED

    def test_mark_stale_at_end(self, store_factory, registry):
        store = store_factory()
        investigation, seed = seeded_store(store)
        graph = support.graph(store, [seed.entity_id])
        HypothesisGenerator(store).generate(investigation, graph,
                                            available_tool_ids=["mock_services"])
        stale = mark_stale_hypotheses(store, support.DEFAULT_INV)
        assert stale > 0
        assert store.list_hypotheses(support.DEFAULT_INV,
                                     statuses=[HypothesisStatus.OPEN]) == []
        assert store.list_hypotheses(support.DEFAULT_INV,
                                     statuses=[HypothesisStatus.INCONCLUSIVE])
