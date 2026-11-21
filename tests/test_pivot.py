"""Pivot scoring tests — exact formula, hop penalty, corroboration boost, dedupe."""

import pytest

from hub.investigation.pivot import EntitySignal, PivotScorer, entity_signals
from hub.models import (
    EntityType,
    EpistemicStatus,
    Hypothesis,
    HypothesisStatus,
    HypothesisType,
    PivotWeights,
    utc_now,
)
from tests.mock_tools import make_capability
from tests import support


# ── fixtures ───────────────────────────────────────────────────────────

@pytest.fixture()
def registry(isolated_mock_registry):
    isolated_mock_registry(
        make_capability("mock_services", [EntityType.EMAIL], [EntityType.SERVICE],
                        prior_yield=1.0, reliability=0.9),
        make_capability("mock_breach", [EntityType.EMAIL], [EntityType.BREACH_RECORD],
                        prior_yield=0.5, reliability=0.8),
        make_capability("mock_dns", [EntityType.DOMAIN], [EntityType.IP],
                        prior_yield=0.6, reliability=0.9),
        make_capability("mock_active", [EntityType.DOMAIN], [EntityType.IP],
                        prior_yield=0.6, reliability=0.9,
                        mode=__import__("hub.models", fromlist=["ExecutionMode"]).ExecutionMode.ACTIVE_RECON),
    )


def weights(**kwargs) -> PivotWeights:
    return PivotWeights(**kwargs).normalized()


def build_graph(store, *, seed=True):
    """Seed email 0 hops, service 1 hop, username 2 hops, domain 3 hops."""
    inv = support.DEFAULT_INV
    support.bootstrap(store)
    seed_entity = support.entity(store, EntityType.EMAIL, "seed@example.com")
    service = support.entity(store, EntityType.SERVICE, "github")
    username = support.entity(store, EntityType.USERNAME, "seeduser")
    domain = support.entity(store, EntityType.DOMAIN, "farexample.com")
    support.claim(store, seed_entity.entity_id, "REGISTERED_ON",
                  object_id=service.entity_id, tools=("holehe",))
    support.claim(store, service.entity_id, "HAS_USERNAME",
                  object_id=username.entity_id, tools=("maigret",))
    support.claim(store, username.entity_id, "ASSOCIATED_WITH",
                  object_id=domain.entity_id, tools=("sherpa",))
    seed_ids = [seed_entity.entity_id] if seed else []
    support.set_seeds(store, seed_ids)
    return seed_entity, service, username, domain, seed_ids


class TestPivotFormula:
    def test_expected_info_gain_term(self, store_factory, registry):
        store = store_factory()
        seed_entity, _, _, _, seed_ids = build_graph(store)
        view = support.graph(store, seed_ids)
        scorer = PivotScorer(weights(w1_info_gain=1.0, w2_corroboration=0.0,
                                     w3_hop_penalty=0.0, w4_cost=0.0),
                             min_threshold=0.0)
        ranking = scorer.rank(view, [], allowed_tool_ids={"mock_services"})
        pivot = ranking.selected[0]
        # Seed entity has a single-source claim; expected info gain derives from
        # the claim's actual deterministic confidence.
        seed_claims = store.list_claims(support.DEFAULT_INV,
                                        subject_id=seed_entity.entity_id)
        max_confidence = max(claim.confidence for claim in seed_claims)
        expected = 1.0 * (0.35 + 0.65 * (1.0 - max_confidence))
        assert pivot.expected_info_gain == pytest.approx(expected, abs=1e-3)
        assert pivot.score == pytest.approx(expected, abs=1e-3)

    def test_hop_penalty_term(self, store_factory, registry):
        store = store_factory()
        _, _, _, domain, seed_ids = build_graph(store)
        view = support.graph(store, seed_ids)
        scorer = PivotScorer(weights(w1_info_gain=0.0, w2_corroboration=0.0,
                                     w3_hop_penalty=1.0, w4_cost=0.0),
                             min_threshold=-1.0)
        ranking = scorer.rank(view, [], allowed_tool_ids={"mock_dns"})
        pivot = next(p for p in ranking.all_candidates if p.entity_id == domain.entity_id)
        assert pivot.hop_distance == 3
        assert pivot.hop_penalty == pytest.approx(0.75)
        assert pivot.score == pytest.approx(-0.75)

    def test_hop_penalty_capped(self):
        scorer = PivotScorer()
        assert scorer._hop_penalty(2, False) == 0.0
        assert scorer._hop_penalty(3, False) == pytest.approx(0.75)
        assert scorer._hop_penalty(5, False) == pytest.approx(1.0)
        assert scorer._hop_penalty(8, False) == pytest.approx(1.0)

    def test_identifier_exemption_reduces_penalty(self):
        scorer = PivotScorer()
        assert scorer._hop_penalty(4, True) == pytest.approx(1.0 * 0.2)

    def test_identifier_exemption_in_ranking(self, store_factory, registry):
        store = store_factory()
        seed_entity, _, username, _, seed_ids = build_graph(store)
        # Create a 3-hop domain that carries the seed's alias -> shares identifier.
        distant = support.entity(store, EntityType.DOMAIN, "aliasexample.com",
                                 aliases=[seed_entity.canonical_value])
        support.claim(store, username.entity_id, "ASSOCIATED_WITH",
                      object_id=distant.entity_id, tools=("sherpa",))
        view = support.graph(store, seed_ids)
        scorer = PivotScorer(weights(w1_info_gain=0.0, w2_corroboration=0.0,
                                     w3_hop_penalty=1.0, w4_cost=0.0),
                             min_threshold=-1.0)
        ranking = scorer.rank(view, [], allowed_tool_ids={"mock_dns"})
        pivot = next(p for p in ranking.all_candidates if p.entity_id == distant.entity_id)
        assert view.shares_corroborated_identifier(distant.entity_id) is True
        assert pivot.hop_penalty < 0.5

    def test_execution_cost_passive_vs_active(self, store_factory, registry):
        store = store_factory()
        _, _, _, domain, seed_ids = build_graph(store)
        view = support.graph(store, seed_ids)
        passive = PivotScorer(weights(w1_info_gain=0.0, w2_corroboration=0.0,
                                      w3_hop_penalty=0.0, w4_cost=1.0),
                              min_threshold=-1.0)
        p1 = next(p for p in passive.rank(view, [], allowed_tool_ids={"mock_dns"}).all_candidates
                  if p.entity_id == domain.entity_id)
        p2 = next(p for p in passive.rank(view, [], allowed_tool_ids={"mock_active"}).all_candidates
                  if p.entity_id == domain.entity_id)
        assert p2.execution_cost > p1.execution_cost
        assert p1.score == pytest.approx(-p1.execution_cost)
        assert p2.score == pytest.approx(-p2.execution_cost)

    def test_weights_are_normalized(self):
        normalized = PivotWeights(w1_info_gain=2, w2_corroboration=2,
                                  w3_hop_penalty=2, w4_cost=4).normalized()
        assert normalized.w1_info_gain == pytest.approx(0.2)
        assert normalized.w4_cost == pytest.approx(0.4)
        assert (normalized.w1_info_gain + normalized.w2_corroboration
                + normalized.w3_hop_penalty + normalized.w4_cost) == pytest.approx(1.0)


class TestCorroborationValue:
    def _entity_with_claims(self, store, statuses):
        seed_entity = support.entity(store, EntityType.EMAIL, "corr@example.com")
        for index, tools in enumerate(statuses):
            support.claim(store, seed_entity.entity_id, f"HAS_ATTRIBUTE:attr{index}",
                          object_literal=index, tools=tuple(tools))
        return seed_entity

    def test_unverified_claim_boosts(self, store_factory, registry):
        store = store_factory()
        support.bootstrap(store)
        seed_entity = self._entity_with_claims(store, [("holehe",)])
        view = support.graph(store, [seed_entity.entity_id])
        scorer = PivotScorer(weights(w1_info_gain=0.0, w2_corroboration=1.0,
                                     w3_hop_penalty=0.0, w4_cost=0.0),
                             min_threshold=-1.0)
        pivot = next(p for p in scorer.rank(view, [], allowed_tool_ids={"mock_breach"}).all_candidates
                     if p.entity_id == seed_entity.entity_id)
        assert pivot.corroboration_value == 0.6
        assert pivot.score == pytest.approx(0.6)

    def test_open_hypothesis_max_boost(self, store_factory, registry):
        store = store_factory()
        support.bootstrap(store)
        seed_entity = support.entity(store, EntityType.EMAIL, "hyp@example.com")
        now = utc_now()
        hypothesis = Hypothesis(
            hypothesis_id="hyp_x", investigation_id=support.DEFAULT_INV,
            hypothesis_type=HypothesisType.CORROBORATION,
            question="q", target_entity_id=seed_entity.entity_id,
            proposed_tool_ids=["mock_services"], status=HypothesisStatus.OPEN,
            created_at=now, updated_at=now,
        )
        store.add_hypothesis(hypothesis)
        view = support.graph(store, [seed_entity.entity_id])
        scorer = PivotScorer(weights(w1_info_gain=0.0, w2_corroboration=1.0,
                                     w3_hop_penalty=0.0, w4_cost=0.0),
                             min_threshold=-1.0)
        ranking = scorer.rank(view, store.list_hypotheses(support.DEFAULT_INV),
                              allowed_tool_ids={"mock_services"})
        pivot = ranking.selected[0]
        assert pivot.hypothesis_id == "hyp_x"
        assert pivot.corroboration_value == 1.0
        assert pivot.score == pytest.approx(1.0)


class TestDedupeAndThreshold:
    def test_ledger_excludes_candidate(self, store_factory, registry):
        store = store_factory()
        seed_entity, _, _, _, seed_ids = build_graph(store)
        view = support.graph(store, seed_ids)
        from hub.models import param_hash
        from hub.tools import capabilities as cap_registry

        capability = cap_registry.get_tool("mock_services")
        params = {"email": seed_entity.canonical_value}
        key = (seed_entity.entity_id, capability.tool_id, param_hash(capability.tool_id, params))
        scorer = PivotScorer()
        ranking = scorer.rank(view, [], allowed_tool_ids={"mock_services"},
                              executed_keys={key})
        assert all(p.entity_id != seed_entity.entity_id for p in ranking.all_candidates)

    def test_below_threshold_not_selected(self, store_factory, registry):
        store = store_factory()
        _, _, _, _, seed_ids = build_graph(store)
        view = support.graph(store, seed_ids)
        scorer = PivotScorer(min_threshold=0.9)
        ranking = scorer.rank(view, [], allowed_tool_ids={"mock_services"})
        assert ranking.generated > 0
        assert ranking.selected == []
        assert ranking.above_threshold == 0

    def test_unavailable_tools_excluded(self, store_factory, registry):
        store = store_factory()
        _, _, _, _, seed_ids = build_graph(store)
        view = support.graph(store, seed_ids)
        ranking = PivotScorer().rank(view, [], allowed_tool_ids=set())
        assert ranking.generated == 0

    def test_deterministic_ranking(self, store_factory, registry):
        store = store_factory()
        _, _, _, _, seed_ids = build_graph(store)
        view = support.graph(store, seed_ids)
        scorer = PivotScorer()
        first = scorer.rank(view, [], allowed_tool_ids={"mock_services", "mock_breach"})
        second = scorer.rank(view, [], allowed_tool_ids={"mock_services", "mock_breach"})
        assert [p.pivot_id for p in first.selected] == [p.pivot_id for p in second.selected]

    def test_diversification_caps_per_entity(self, store_factory):
        store = store_factory()
        support.bootstrap(store)
        emails = [support.entity(store, EntityType.EMAIL, f"e{i}@example.com")
                  for i in range(3)]
        # register 4 tools accepting EMAIL
        caps = [make_capability(f"mock_{i}", [EntityType.EMAIL], [EntityType.SERVICE],
                                prior_yield=0.5 + 0.1 * i) for i in range(4)]
        from hub.tools import capabilities as registry_mod
        for cap in caps:
            registry_mod.register(cap, replace=True)
        view = support.graph(store, [e.entity_id for e in emails])
        scorer = PivotScorer(top_k=5, max_per_entity=2)
        ranking = scorer.rank(view, [], allowed_tool_ids={c.tool_id for c in caps})
        counts: dict[str, int] = {}
        for pivot in ranking.selected:
            counts[pivot.entity_id] = counts.get(pivot.entity_id, 0) + 1
        assert max(counts.values()) <= 2
        assert len(ranking.selected) > 0


class TestEntitySignals:
    def test_signals_from_claims(self, store_factory):
        store = store_factory()
        support.bootstrap(store)
        entity = support.entity(store, EntityType.EMAIL, "sig@example.com")
        support.claim(store, entity.entity_id, "HAS_ATTRIBUTE:a", object_literal=True,
                      tools=("holehe",))
        view = support.graph(store, [entity.entity_id])
        signals = entity_signals(view)
        signal = signals[entity.entity_id]
        assert signal.has_claims is True
        assert signal.has_unverified is True
        assert signal.contradicted is False
        assert 0.0 <= signal.max_confidence <= 1.0
