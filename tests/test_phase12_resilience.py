"""Phase 12 resilience regression tests — location semantics, breakers, collectors, UI."""

from __future__ import annotations

import asyncio
import json
import sys

import pytest

from hub.erkg.graph import GraphView
from hub.intake import EMAIL_DERIVED_DOMAIN, MultiClueIntake
from hub.investigation.engine import InvestigationEngine
from hub.investigation.pivot import PivotScorer
from hub.models import (
    EdgeType,
    EntityType,
    ErrorCode,
    ExecutionStatus,
    InvocationSpec,
    ParameterSpec,
    ScopeConfig,
    ToolCapability,
    ToolRunResult,
    utc_now,
    param_hash,
)
from hub.tools import capabilities as cap_registry
from tests import support
from tests.mock_tools import (
    MockRunner,
    empty_output,
    make_capability,
    parse_mock,
)
from tests.test_api_collectors_phase10 import (
    GITHUB_TOKEN,
    _collect,
    _install_transport,
    _response,
    _set_secrets,
)


# ════════════════════════════════════════════════════════════════════════
# 1. LOCATED_IN hierarchy: city + country never contradict, phoneinfoga corroborates
# ════════════════════════════════════════════════════════════════════════

class TestLocationSemantics:
    def test_hierarchical_locations_do_not_contradict(self, store_factory):
        store = store_factory()
        support.bootstrap(store)
        person = support.entity(store, EntityType.PERSON, "Elvin Tashkin")
        baku = support.entity(store, EntityType.LOCATION, "Baku")
        az = support.entity(store, EntityType.LOCATION, "AZ")
        support.claim(store, person.entity_id, "LOCATED_IN",
                      object_id=baku.entity_id, tools=("seed",))
        support.claim(store, person.entity_id, "LOCATED_IN",
                      object_id=az.entity_id, tools=("seed",))
        claims = store.list_claims(support.DEFAULT_INV)
        located = [claim for claim in claims if claim.predicate == "LOCATED_IN"]
        assert len(located) == 2
        assert all(claim.status is not None for claim in located)
        assert store.list_contradictions(support.DEFAULT_INV) == []
        assert not any(claim.status.value == "CONTRADICTED" for claim in located)

    def test_phoneinfoga_country_corroborates_seed_location(self, store_factory):
        store = store_factory()
        support.bootstrap(store)
        person = support.entity(store, EntityType.PERSON, "Elvin Tashkin")
        az = support.entity(store, EntityType.LOCATION, "AZ")
        support.claim(store, person.entity_id, "LOCATED_IN",
                      object_id=az.entity_id, tools=("seed",))
        support.claim(store, person.entity_id, "LOCATED_IN",
                      object_id=az.entity_id, tools=("phoneinfoga",))
        located = [claim for claim in store.list_claims(support.DEFAULT_INV)
                   if claim.predicate == "LOCATED_IN"]
        assert located
        assert located[0].status.value in {"CONFIRMED", "CORROBORATED"}
        assert store.list_contradictions(support.DEFAULT_INV) == []

    def test_location_list_expansion_preserves_city_country(self):
        intake = MultiClueIntake()
        clues = intake.extract("", {"locations": "Baku, AZ"})
        values = {clue.value.lower() for clue in clues
                  if clue.entity_type is EntityType.LOCATION}
        assert {"baku, az", "baku", "az"} <= values


# ════════════════════════════════════════════════════════════════════════
# 2. Circuit breaker + institutional email-domain seed-wave coverage
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def breaker_engine(tmp_path, isolated_mock_registry):
    isolated_mock_registry(
        make_capability("mock_rate_tool", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.98),
        make_capability("mock_ok_tool", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.40),
        make_capability("mock_domain_tool", [EntityType.DOMAIN],
                        [EntityType.IP], prior_yield=0.95),
    )
    rate_limited = ToolRunResult(
        tool_id="mock_rate_tool", status=ExecutionStatus.ERROR,
        error_code=ErrorCode.RATE_LIMITED, exit_code=1,
        error_message="HTTP 429",
    )
    runner = MockRunner(script={"mock_rate_tool": [rate_limited]},
                        default=lambda capability, params: empty_output())
    engine = InvestigationEngine(
        runner=runner,
        parser_resolver=lambda capability: parse_mock,
        health_probe=lambda capability: True,
        state_root=tmp_path / "state",
    )
    return engine, runner


class TestCircuitBreaker:
    def test_rate_limited_tool_never_selected_again(self, breaker_engine):
        engine, runner = breaker_engine
        outcome = asyncio.run(engine.investigate(
            "elv1ntsk",
            {"target_id": "phase12_breaker", "max_iterations": 2,
             "max_tool_calls": 2, "min_pivot_threshold": 0.0},
        ))
        assert outcome.target_id == "phase12_breaker"
        assert runner.tool_calls.count("mock_rate_tool") <= 1
        # The second iteration must not burn another call on the breaker tool.
        assert "mock_rate_tool" not in runner.tool_calls[1:]
        store = engine.open_store("phase12_breaker")
        try:
            ledger = store.list_ledger("phase12_breaker")
            tripped = {entry.tool_id for entry in ledger
                       if entry.error_code is ErrorCode.RATE_LIMITED}
            assert tripped == {"mock_rate_tool"}
            blocked = engine._circuit_breaker_tools(store, "phase12_breaker")
            assert blocked == {"mock_rate_tool"}
        finally:
            store.close()

    def test_scorer_blocked_excludes_candidates(self, store_factory, isolated_mock_registry):
        isolated_mock_registry(
            make_capability("mock_rate_tool", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.98),
        )
        store = store_factory()
        support.bootstrap(store)
        seed = support.entity(store, EntityType.USERNAME, "elv1ntsk",
                              metadata={"provenance": "USER_PROVIDED_SEED"})
        support.set_seeds(store, [seed.entity_id])
        graph = GraphView(store, support.DEFAULT_INV, [seed.entity_id])
        ranking = PivotScorer(min_threshold=0.0).rank(
            graph, [], allowed_tool_ids={"mock_rate_tool"},
            blocked_tool_ids={"mock_rate_tool"})
        assert ranking.generated == 0
        assert ranking.selected == []

    def test_institutional_email_domain_promoted_to_seed_wave(self, breaker_engine):
        engine, _ = breaker_engine
        created = asyncio.run(engine.create(
            "",
            {"min_pivot_threshold": 0.0},
            structured_seeds={"emails": ["elvin.s.tashkin.std@example.edu.az"]},
        ))
        store = engine.open_store(created.target_id)
        try:
            investigation = store.get_investigation(created.target_id)
            graph = GraphView(store, created.target_id,
                              investigation.seed_entity_ids)
            domain = next(entity for entity in graph.entities.values()
                          if entity.type is EntityType.DOMAIN
                          and entity.canonical_value == "example.edu.az")
            assert domain.metadata.get("provenance") == EMAIL_DERIVED_DOMAIN
            assert domain.entity_id in investigation.seed_entity_ids
            # Derived domain is a seed-wave node, NOT a scope grant.
            assert "example.edu.az" not in investigation.config.scope.allow_domains
            ranking = engine._rank_pivots(
                store, investigation, graph,
                available_tool_ids={"mock_domain_tool"})
            assert ranking.selected
            assert ranking.selected[0].entity_id == domain.entity_id
            assert ranking.selected[0].tool_id == "mock_domain_tool"
        finally:
            store.close()


# ════════════════════════════════════════════════════════════════════════
# 3. GitHub resilience + maigret nonzero tolerance
# ════════════════════════════════════════════════════════════════════════

class TestGithubResilience:
    def test_404_username_is_clean_empty(self, monkeypatch):
        async def handler(request):
            return _response({"message": "Not Found"}, status=404)

        _set_secrets(monkeypatch)  # keyless
        _install_transport(monkeypatch, handler)
        result = _collect(__import__("hub.tools.builtin.github_osint",
                                    fromlist=["collect"]),
                          {"username": "ghost-user-does-not-exist"})
        assert result.exit_code == 0
        assert result.error_code is None
        assert result.stdout == ""

    def test_profile_survives_commit_search_403(self, monkeypatch):
        import hub.tools.builtin.github_osint as github_collector

        async def handler(request):
            path = request.url.path
            if path == "/users/octocat":
                return _response({"login": "octocat", "name": "The Octocat",
                                  "html_url": "https://github.com/octocat"})
            if path.endswith("/repos"):
                return _response([])
            if path.endswith("/events/public"):
                return _response([])
            if path == "/search/commits":
                return _response({"message": "Forbidden"}, status=403)
            return _response({"message": "Not Found"}, status=404)

        _set_secrets(monkeypatch, github={"token": GITHUB_TOKEN})
        _install_transport(monkeypatch, handler)
        result = _collect(github_collector, {"username": "octocat"})
        assert result.exit_code == 0
        assert result.error_code is None
        payload = json.loads(result.stdout)
        assert payload["user"]["login"] == "octocat"
        assert payload["auth_status"] == "CONFIGURED"

    def test_commit_search_422_is_non_fatal(self, monkeypatch):
        import hub.tools.builtin.github_osint as github_collector

        async def handler(request):
            path = request.url.path
            if path == "/users/octocat":
                return _response({"login": "octocat"})
            if path.endswith("/repos"):
                return _response([])
            if path.endswith("/events/public"):
                return _response([])
            if path == "/search/commits":
                return _response({"message": "Validation Failed"}, status=422)
            return _response({"message": "Not Found"}, status=404)

        _set_secrets(monkeypatch)
        _install_transport(monkeypatch, handler)
        result = _collect(github_collector, {"username": "octocat"})
        assert result.exit_code == 0
        assert result.error_code is None
        assert json.loads(result.stdout)["user"]["login"] == "octocat"

    def test_bad_token_retries_unauthenticated(self, monkeypatch):
        import hub.tools.builtin.github_osint as github_collector

        seen: list[str] = []
        seen_headers: list[dict] = []

        async def handler(request):
            auth = request.headers.get("authorization", "")
            seen.append(auth)
            seen_headers.append({k.lower(): v for k, v in request.headers.items()})
            if auth:
                return _response({"message": "Bad credentials"}, status=401)
            path = request.url.path
            if path == "/users/octocat":
                return _response({"login": "octocat"})
            if path.endswith("/repos") or path.endswith("/events/public"):
                return _response([])
            return _response({"message": "Not Found"}, status=404)

        _set_secrets(monkeypatch, github={"token": GITHUB_TOKEN})
        _install_transport(monkeypatch, handler)
        result = _collect(github_collector, {"username": "octocat"})
        assert result.exit_code == 0 and result.error_code is None
        assert result.stdout
        assert any(value for value in seen)  # authenticated attempt
        assert any(not value for value in seen)  # unauthenticated retry
        assert all(h.get("api-version") or h.get("x-github-api-version")
                   for h in seen_headers)
        assert all(h.get("user-agent") for h in seen_headers)
        assert GITHUB_TOKEN not in result.stderr + result.stdout

    def test_maigret_manifest_tolerates_nonzero_with_stdout(self):
        cap = cap_registry.get_tool("maigret")
        assert cap.invocation.tolerate_nonzero_with_stdout is True
        assert cap.invocation.env.get("PYTHONIOENCODING") == "utf-8"
        assert cap.invocation.env.get("PYTHONUTF8") == "1"

    def test_runtime_tolerates_nonzero_stdout_for_flag(self):
        from hub.tools.runtime import RunContext, ToolRuntime

        cap = ToolCapability(
            tool_id="tolerant_probe", display_name="Tolerant probe",
            description="test",
            accepted_entity_types=[EntityType.USERNAME],
            produced_entity_types=[EntityType.USERNAME],
            invocation=InvocationSpec(
                kind="binary", binary=sys.executable,
                prefix_args=["-c", "import sys; print('partial-results'); sys.exit(1)"],
                tolerate_nonzero_with_stdout=True,
            ),
            parser_ref="hub.tools.parsers.holehe:parse",
        )

        async def run():
            runtime = ToolRuntime()
            try:
                return await runtime.run(
                    cap, {},
                    RunContext(investigation_id="t", entity_id="e",
                               scope=ScopeConfig(), timeout_override_s=30))
            finally:
                await runtime.aclose()

        result = asyncio.run(run())
        assert result.status is ExecutionStatus.SUCCESS
        assert "partial-results" in result.stdout


# ════════════════════════════════════════════════════════════════════════
# 4. Web graph de-clutter payload/UI defaults
# ════════════════════════════════════════════════════════════════════════

class TestGraphDeclutter:
    def test_hypothesis_nodes_are_flagged(self, store_factory):
        from hub.web import build_workbench_graph

        store = store_factory()
        support.bootstrap(store)
        person = support.entity(store, EntityType.PERSON, "Elvin Tashkin")
        guessed = support.entity(store, EntityType.USERNAME, "elvin_in")
        store.add_hypothesis_claim(
            support.DEFAULT_INV, guessed.entity_id, "IDENTIFIED_AS",
            object_literal=guessed.canonical_value, timestamp=utc_now(),
            confidence=0.30)
        entities = store.list_entities(support.DEFAULT_INV)
        claims = store.list_claims(support.DEFAULT_INV)
        index = {entity.entity_id: entity for entity in entities}
        graph = build_workbench_graph(entities, claims, index)
        rows = {node["id"]: node for node in graph["nodes"]}
        assert rows[guessed.entity_id]["is_hypothesis"] is True
        assert rows[guessed.entity_id]["evidence_count"] == 0
        assert rows[person.entity_id]["is_hypothesis"] is False

    def test_ui_defaults_hide_hypotheses_and_edge_labels(self):
        from hub.web import WORKBENCH_HTML

        html = WORKBENCH_HTML
        for marker in ("id=\"show-hypotheses\"", "id=\"show-edge-labels\"",
                       "id=\"hyp-count\"", "Show Hypotheses", "Show Edge Labels",
                       "showHypotheses: false", "showEdgeLabels: false"):
            assert marker in html, marker
        # Hypothesis and edge-label checkboxes are not pre-checked.
        assert 'id="show-hypotheses" type="checkbox" checked' not in html
        assert 'id="show-edge-labels" type="checkbox" checked' not in html

    def test_worker_payload_has_graph_hypothesis_flag_contract(self):
        # The frontend hides node.is_hypothesis and only labels edges when the
        # toggle asks for it; verify the JS conditions exist.
        from hub.web import WORKBENCH_HTML

        assert "node.is_hypothesis && !state.graphView.showHypotheses" in WORKBENCH_HTML
        assert "var showEdgeLabels = !!state.graphView.showEdgeLabels" in WORKBENCH_HTML
