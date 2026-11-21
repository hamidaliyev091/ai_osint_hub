"""Phase 14 coverage tests — seed rescue, provider cooldown, Web defaults."""

from __future__ import annotations

import asyncio
import json

import pytest

from hub.erkg.graph import GraphView
from hub.investigation.engine import InvestigationEngine
from hub.investigation.pivot import PivotScorer
from hub.models import (
    EntityType,
    ErrorCode,
    ExecutionStatus,
    ToolRunResult,
    utc_now,
    param_hash,
)
from hub.tools import capabilities, cooldown
from hub.tools.cooldown import (
    RATE_LIMIT_COOLDOWN_SEC,
    cooled_tool_ids,
    is_cooling,
    mark_rate_limited,
    reset_cache,
)
from tests import support
from tests.mock_tools import (
    MockRunner,
    empty_output,
    make_capability,
    parse_mock,
)


# ════════════════════════════════════════════════════════════════════════
# 1. Uncovered seed rescue + fast domain / preferred username ordering
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def coverage_registry(isolated_mock_registry):
    isolated_mock_registry(
        make_capability("github_osint", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.9),
        make_capability("sherlock", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.7),
        make_capability("maigret", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.75),
        make_capability("snscrape", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.6),
        make_capability("theharvester", [EntityType.DOMAIN],
                        [EntityType.URL], prior_yield=0.8),
        make_capability("dns_lookup", [EntityType.DOMAIN],
                        [EntityType.IP], prior_yield=0.5),
        make_capability("tls_cert", [EntityType.DOMAIN],
                        [EntityType.SUBDOMAIN], prior_yield=0.5),
        make_capability("rdap_lookup", [EntityType.DOMAIN],
                        [EntityType.ORGANIZATION], prior_yield=0.5),
        make_capability("virustotal_lookup", [EntityType.DOMAIN],
                        [EntityType.SUBDOMAIN], prior_yield=0.7),
        make_capability("photon_crawler", [EntityType.DOMAIN],
                        [EntityType.URL], prior_yield=0.6),
    )


def _coverage_graph(store):
    support.bootstrap(store)
    seeds = {}
    seeds["user1"] = support.entity(
        store, EntityType.USERNAME, "elv1ntsk",
        metadata={"provenance": "USER_PROVIDED_SEED"})
    seeds["user2"] = support.entity(
        store, EntityType.USERNAME, "108.elv1n",
        metadata={"provenance": "USER_PROVIDED_SEED"})
    seeds["email"] = support.entity(
        store, EntityType.EMAIL, "user@example.edu.az",
        metadata={"provenance": "USER_PROVIDED_SEED"})
    seeds["phone"] = support.entity(
        store, EntityType.PHONE, "+994551234567",
        metadata={"provenance": "USER_PROVIDED_SEED"})
    seeds["domain"] = support.entity(
        store, EntityType.DOMAIN, "example.edu.az",
        metadata={"provenance": "EMAIL_DERIVED_DOMAIN"})
    support.set_seeds(store, [entity.entity_id for entity in seeds.values()])
    return seeds


class TestSeedCoverage:
    def test_empty_runs_get_uncovered_seed_rescue(self, store_factory,
                                                  coverage_registry):
        store = store_factory()
        seeds = _coverage_graph(store)
        executed = set()
        for key in ("user1", "user2"):
            params = {"username": seeds[key].canonical_value}
            executed.add((seeds[key].entity_id, "github_osint",
                          param_hash("github_osint", params)))
        domain_params = {"domain": "example.edu.az"}
        executed.add((seeds["domain"].entity_id, "theharvester",
                      param_hash("theharvester", domain_params)))
        graph = support.graph(store, [entity.entity_id for entity in seeds.values()])
        scoring = PivotScorer(min_threshold=0.0).rank(
            graph, [], allowed_tool_ids={
                "github_osint", "sherlock", "maigret", "snscrape",
                "theharvester", "dns_lookup", "tls_cert", "rdap_lookup",
                "virustotal_lookup", "photon_crawler"},
            executed_keys=executed,
            successful_entity_ids=set())  # every prior run was EMPTY/ERROR
        rescue_candidates = [
            candidate for candidate in scoring.all_candidates
            if "uncovered-seed rescue" in candidate.rationale]
        rescued_entities = {candidate.entity_id for candidate in rescue_candidates}
        assert seeds["user1"].entity_id in rescued_entities
        assert seeds["user2"].entity_id in rescued_entities
        assert seeds["domain"].entity_id in rescued_entities
        for key in ("user1", "user2"):
            tools = {candidate.tool_id for candidate in rescue_candidates
                     if candidate.entity_id == seeds[key].entity_id}
            assert tools & {"sherlock", "maigret"}
        domain_tools = {candidate.tool_id for candidate in rescue_candidates
                        if candidate.entity_id == seeds["domain"].entity_id}
        assert domain_tools & {"dns_lookup", "tls_cert", "rdap_lookup",
                               "virustotal_lookup", "photon_crawler"}
        # Fast native domain collectors are scheduled for the seed domain. The
        # already-executed theHarvester EMPTY pivot is correctly deduped, so its
        # own candidate is absent; the fast collectors occupy the top slots.
        fast_positions = [index for index, candidate in enumerate(scoring.all_candidates)
                          if candidate.entity_id == seeds["domain"].entity_id
                          and candidate.tool_id in {"dns_lookup", "tls_cert",
                                                    "rdap_lookup",
                                                    "virustotal_lookup",
                                                    "photon_crawler"}]
        assert fast_positions
        assert min(fast_positions) <= 5

    def test_sherlock_maigret_precede_snscrape(self, store_factory,
                                               coverage_registry):
        store = store_factory()
        seeds = _coverage_graph(store)
        graph = support.graph(store, [entity.entity_id for entity in seeds.values()])
        scoring = PivotScorer(min_threshold=0.0).rank(
            graph, [], allowed_tool_ids={"sherlock", "maigret", "snscrape"})
        positions = {candidate.tool_id: index
                     for index, candidate in enumerate(scoring.all_candidates)
                     if candidate.entity_id == seeds["user1"].entity_id}
        assert positions["sherlock"] < positions["snscrape"]
        assert positions["maigret"] < positions["snscrape"]

    def test_multi_seed_engine_simulation_covers_all_seed_types(
            self, tmp_path, isolated_mock_registry):
        """Acceptance scenario: 2 usernames + email + phone + domain, 10 calls."""
        isolated_mock_registry(
            make_capability("github_osint", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.75),
            make_capability("sherlock", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.70),
            make_capability("maigret", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.75),
            make_capability("snscrape", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.60),
            make_capability("holehe", [EntityType.EMAIL],
                            [EntityType.SERVICE], prior_yield=0.55),
            make_capability("gravatar_lookup", [EntityType.EMAIL],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.50),
            make_capability("phoneinfoga", [EntityType.PHONE],
                            [EntityType.ORGANIZATION], prior_yield=0.60),
            make_capability("theharvester", [EntityType.DOMAIN],
                            [EntityType.URL], prior_yield=0.80),
            make_capability("dns_lookup", [EntityType.DOMAIN],
                            [EntityType.IP], prior_yield=0.50),
            make_capability("tls_cert", [EntityType.DOMAIN],
                            [EntityType.SUBDOMAIN], prior_yield=0.50),
            make_capability("rdap_lookup", [EntityType.DOMAIN],
                            [EntityType.ORGANIZATION], prior_yield=0.50),
            make_capability("virustotal_lookup", [EntityType.DOMAIN],
                            [EntityType.SUBDOMAIN], prior_yield=0.70),
            make_capability("photon_crawler", [EntityType.DOMAIN],
                            [EntityType.URL], prior_yield=0.60),
        )
        reset_cache()
        runner = MockRunner(default=lambda capability, params: empty_output())
        engine = InvestigationEngine(
            runner=runner,
            parser_resolver=lambda capability: parse_mock,
            health_probe=lambda capability: True,
            state_root=tmp_path / "state",
        )
        asyncio.run(engine.create(
            "",
            {"target_id": "phase14_multi_seed", "max_iterations": 10,
             "max_tool_calls": 10, "min_pivot_threshold": 0.0},
            structured_seeds={
                "name": "Elvin Taşkin",
                "usernames": ["elv1ntsk", "108.elv1n"],
                "emails": ["user@example.edu.az"],
                "phones": ["+994551234567"],
                "domains": ["example.edu.az"],
            }))
        asyncio.run(engine.resume("phase14_multi_seed"))
        calls = [(call.tool_id, call.params.get("username")
                  or call.params.get("domain") or call.params.get("email")
                  or call.params.get("phone")) for call in runner.calls]
        username_calls = {username: [tool for tool, value in calls if value == username]
                          for username in ("elv1ntsk", "108.elv1n")}
        for username, tools in username_calls.items():
            assert tools, f"no pivot executed for {username}"
            assert set(tools) & {"sherlock", "maigret"}, (username, tools)
        domain_tools = {tool for tool, value in calls if value == "example.edu.az"}
        assert domain_tools & {"dns_lookup", "virustotal_lookup", "tls_cert"}
        assert any(value == "user@example.edu.az" for _, value in calls)
        assert any(value == "+994551234567" for _, value in calls)

    def test_successful_seed_run_clears_rescue_bonus(self, store_factory,
                                                     coverage_registry):
        store = store_factory()
        seeds = _coverage_graph(store)
        executed = {(seeds["user1"].entity_id, "github_osint",
                     param_hash("github_osint",
                                {"username": "elv1ntsk"}))}
        graph = support.graph(store, [entity.entity_id for entity in seeds.values()])
        ranking = PivotScorer(min_threshold=0.0).rank(
            graph, [], allowed_tool_ids={"github_osint", "sherlock"},
            executed_keys=executed,
            successful_entity_ids={seeds["user1"].entity_id})
        user1_rescues = [candidate for candidate in ranking.all_candidates
                         if candidate.entity_id == seeds["user1"].entity_id
                         and "uncovered-seed rescue" in candidate.rationale]
        assert user1_rescues == []

    def test_engine_ranking_passes_successful_seed_ids(self, tmp_path,
                                                       isolated_mock_registry,
                                                       store_factory):
        isolated_mock_registry(
            make_capability("sherlock", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.8),
            make_capability("github_osint", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.9),
        )
        store = store_factory()
        support.bootstrap(store)
        user1 = support.entity(store, EntityType.USERNAME, "elv1ntsk",
                               metadata={"provenance": "USER_PROVIDED_SEED"})
        user2 = support.entity(store, EntityType.USERNAME, "108.elv1n",
                               metadata={"provenance": "USER_PROVIDED_SEED"})
        support.set_seeds(store, [user1.entity_id, user2.entity_id])
        for entity in (user1, user2):
            support.claim(store, entity.entity_id, "IDENTIFIED_AS",
                          object_literal=entity.canonical_value,
                          tools=("seed",))
        store.record_execution(__import__("hub.models", fromlist=["ExecutionRecord"]).ExecutionRecord(
            investigation_id=support.DEFAULT_INV, entity_id=user1.entity_id,
            tool_id="github_osint",
            param_hash=param_hash("github_osint", {"username": "elv1ntsk"}),
            status=ExecutionStatus.EMPTY, run_at=utc_now()))
        investigation = store.get_investigation(support.DEFAULT_INV)
        graph = GraphView(store, support.DEFAULT_INV,
                          investigation.seed_entity_ids)
        engine = InvestigationEngine(
            runner=MockRunner(default=lambda capability, params: empty_output()),
            parser_resolver=lambda capability: parse_mock,
            health_probe=lambda capability: True,
            state_root=tmp_path / "state",
        )
        ranking = engine._rank_pivots(
            store, investigation, graph,
            available_tool_ids={"sherlock", "github_osint"})
        assert ranking.all_candidates
        rescued = [candidate for candidate in ranking.all_candidates
                   if candidate.entity_id == user1.entity_id
                   and "uncovered-seed rescue" in candidate.rationale]
        assert rescued
        # user1's github pivot was already executed, so rescue is sherlock.
        assert {candidate.tool_id for candidate in rescued} == {"sherlock"}


# ════════════════════════════════════════════════════════════════════════
# 2. Cross-run provider cooldown cache
# ════════════════════════════════════════════════════════════════════════

class TestProviderCooldown:
    @pytest.fixture(autouse=True)
    def isolated_cache(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_OSINT_HUB_HOME", str(tmp_path / "home"))
        reset_cache()
        yield
        reset_cache()

    def test_rate_limit_cooldown_round_trip(self):
        assert is_cooling("hunter_lookup") is False
        mark_rate_limited("hunter_lookup")
        assert is_cooling("hunter_lookup") is True
        assert "hunter_lookup" in cooled_tool_ids()
        assert cooldown.cache_path().is_file()
        assert cooldown.active_cooldowns()["hunter_lookup"] <= RATE_LIMIT_COOLDOWN_SEC
        reset_cache()
        assert is_cooling("hunter_lookup") is False
        assert cooldown.cache_path().is_file() is False

    def test_cooldown_expires(self):
        mark_rate_limited("shodan_lookup", seconds=1)
        assert is_cooling("shodan_lookup") is True
        assert is_cooling("shodan_lookup",
                          now=__import__("time").time() + 2) is False

    def test_credentials_update_clears_cooldown(self, tmp_path):
        from hub import credentials

        mark_rate_limited("hunter_lookup")
        credentials.save_provider("hunter", {"api_key": "hu-" + "x" * 24},
                                  sync_config=False)
        assert is_cooling("hunter_lookup") is False

    def test_engine_ranking_skips_cooled_tool(self, tmp_path,
                                              isolated_mock_registry,
                                              store_factory):
        isolated_mock_registry(
            make_capability("hunter_lookup", [EntityType.EMAIL],
                            [EntityType.EMAIL], prior_yield=0.9),
            make_capability("holehe", [EntityType.EMAIL],
                            [EntityType.SERVICE], prior_yield=0.7),
        )
        store = store_factory()
        support.bootstrap(store)
        seed = support.entity(store, EntityType.EMAIL, "elvin@example.edu.az",
                              metadata={"provenance": "USER_PROVIDED_SEED"})
        support.set_seeds(store, [seed.entity_id])
        mark_rate_limited("hunter_lookup")
        investigation = store.get_investigation(support.DEFAULT_INV)
        graph = GraphView(store, support.DEFAULT_INV, [seed.entity_id])
        engine = InvestigationEngine(
            runner=MockRunner(default=lambda capability, params: empty_output()),
            parser_resolver=lambda capability: parse_mock,
            health_probe=lambda capability: True,
            state_root=tmp_path / "state",
        )
        ranking = engine._rank_pivots(
            store, investigation, graph,
            available_tool_ids={"hunter_lookup", "holehe"})
        tools = {candidate.tool_id for candidate in ranking.all_candidates}
        assert "hunter_lookup" not in tools
        assert "holehe" in tools

    def test_rate_limited_api_tool_marks_cooldown_in_engine(self, tmp_path,
                                                            isolated_mock_registry,
                                                            store_factory):
        isolated_mock_registry(
            make_capability("hunter_lookup", [EntityType.EMAIL],
                            [EntityType.EMAIL], prior_yield=0.9),
        )
        rate_limited = ToolRunResult(
            tool_id="hunter_lookup", status=ExecutionStatus.ERROR,
            error_code=ErrorCode.RATE_LIMITED, exit_code=1,
            error_message="HTTP 429 restricted_account",
        )
        store = store_factory()
        support.bootstrap(store)
        seed = support.entity(store, EntityType.EMAIL, "elvin@example.edu.az",
                              metadata={"provenance": "USER_PROVIDED_SEED"})
        support.set_seeds(store, [seed.entity_id])
        # Build a minimal investigation through the engine so the ledger records.
        engine = InvestigationEngine(
            runner=MockRunner(script={"hunter_lookup": [rate_limited]},
                              default=lambda capability, params: empty_output()),
            parser_resolver=lambda capability: parse_mock,
            health_probe=lambda capability: True,
            state_root=tmp_path / "state",
        )
        asyncio.run(engine.investigate(
            "elvin@example.edu.az",
            {"target_id": "phase14_cooldown", "max_iterations": 1,
             "max_tool_calls": 1, "min_pivot_threshold": 0.0}))
        assert is_cooling("hunter_lookup") is True


# ════════════════════════════════════════════════════════════════════════
# 3. Web UI defaults / checkbox state
# ════════════════════════════════════════════════════════════════════════

class TestWebDefaults:
    def test_hypothesis_and_edge_label_checkboxes_unchecked(self):
        import re

        from hub.web import WORKBENCH_HTML

        for control_id in ("show-hypotheses", "show-edge-labels"):
            match = re.search(
                r'<input[^>]*id="%s"[^>]*>' % control_id, WORKBENCH_HTML)
            assert match is not None, control_id
            assert "checked" not in match.group(0).lower()

    def test_max_iterations_defaults_to_16(self):
        from hub.web import InvestigateRequest, WORKBENCH_HTML

        assert InvestigateRequest().max_iterations == 16
        assert 'id="in-max-iterations" type="number" value="16"' in WORKBENCH_HTML
        assert "in-max-iterations\").value || 16" in WORKBENCH_HTML
        assert '"in-max-iterations": "16"' in WORKBENCH_HTML
        assert InvestigateRequest().max_tool_calls == 20

    def test_clear_form_resets_toggles_unchecked(self):
        from hub.web import WORKBENCH_HTML

        snippet_start = WORKBENCH_HTML.find("function clearForm()")
        assert snippet_start != -1
        snippet = WORKBENCH_HTML[snippet_start:snippet_start + 1500]
        assert '["show-hypotheses", "show-edge-labels"]' in snippet
        assert "state.graphView.showHypotheses = false" in snippet
        assert "state.graphView.showEdgeLabels = false" in snippet
