"""Phase 11 quality regression tests — parsers, intake precision, seed-first pivots, Web UI."""

from __future__ import annotations

import json

import pytest

from hub.erkg.ingestion import EvidenceIngestor
from hub.intake import (
    EMAIL_DERIVED_DOMAIN,
    EMAIL_DERIVED_USERNAME,
    MultiClueIntake,
    USER_PROVIDED_SEED,
    transliteration_variants,
)
from hub.investigation.pivot import PivotScorer
from hub.models import EntityType, Hypothesis, HypothesisStatus, HypothesisType, utc_now, param_hash
from hub.tools import capabilities as cap_registry
from hub.tools.parsers.holehe import parse as parse_holehe
from tests.mock_tools import make_capability
from tests import support


# ════════════════════════════════════════════════════════════════════════
# 1. holehe — positive hits only, banner credits stripped, no fake contradictions
# ════════════════════════════════════════════════════════════════════════

HOLEHE_NOISY = """      _     _                 _
holehe v1.61
Twitter : @palenath
Github : https://github.com/megadose/holehe
For BTC Donations : 1FHDM49QfZX6pJmhjLE5tB2K6CaTLMZpXZ

Email: alice@example.com
[x] about.me
[-] amazon.com
[+] spotify.com
[-] instagram.com
[+] twitter.com
[+] Email used, [-] Email not used, [x] Rate limit
121 websites checked in 10.92 seconds
Twitter : @palenath
Github : https://github.com/megadose/holehe
"""


class TestHolehePrecision:
    def test_positive_hits_only(self):
        out = parse_holehe(HOLEHE_NOISY, "alice@example.com")
        services = {entity.value for entity in out.entities
                    if entity.type is EntityType.SERVICE}
        assert services == {"spotify.com", "twitter.com"}
        assert "amazon.com" not in services
        assert "about.me" not in services
        assert len(out.relations) == 2
        assert all(rel.predicate.value == "REGISTERED_ON" for rel in out.relations)

    def test_banner_handles_never_extracted(self):
        out = parse_holehe(HOLEHE_NOISY, "alice@example.com")
        values = {entity.value.lower() for entity in out.entities}
        assert "megadose" not in values
        assert "palenath" not in values
        assert "1fhdm49qfzx6pjmhjle5tb2k6catlmzpxz" not in values

    def test_no_global_registered_attribute_on_services(self):
        out = parse_holehe(HOLEHE_NOISY, "alice@example.com")
        for entity in out.entities:
            if entity.type is EntityType.SERVICE:
                assert "registered" not in entity.attributes
                assert entity.attributes == {}
            assert "megadose" not in str(entity.value).lower()

    def test_negative_lines_do_not_fabricate_registered_false(self):
        out = parse_holehe("[+] spotify.com\n[-] spotify.com\n[x] spotify.com\n",
                           "alice@example.com")
        services = {entity.value: entity for entity in out.entities
                    if entity.type is EntityType.SERVICE}
        assert set(services) == {"spotify.com"}
        assert services["spotify.com"].metadata.get("marker") == "+"
        assert services["spotify.com"].attributes == {}

    def test_two_emails_do_not_create_contradictions(self, store_factory):
        store = store_factory()
        support.bootstrap(store)
        out_a = parse_holehe("[+] spotify.com\n", "alice@example.com")
        out_b = parse_holehe("[-] spotify.com\n[x] spotify.com\n",
                             "bob@example.com")
        artifact_a = support.artifact(store, "holehe", suffix="a",
                                      snippet="[+] spotify.com")
        artifact_b = support.artifact(store, "holehe", suffix="b",
                                      snippet="[-] spotify.com")
        ingestor = EvidenceIngestor(store)
        ingestor.ingest(support.DEFAULT_INV, out_a, artifact_id=artifact_a,
                        tool_id="holehe", accepted_types=[], timestamp=utc_now())
        ingestor.ingest(support.DEFAULT_INV, out_b, artifact_id=artifact_b,
                        tool_id="holehe", accepted_types=[], timestamp=utc_now())
        contradictions = store.list_contradictions(support.DEFAULT_INV)
        assert contradictions == []
        service = store.get_entity_by_value(support.DEFAULT_INV, "service", "spotify.com")
        assert service is not None
        assert "registered" not in (service.metadata or {})
        # No global HAS_ATTRIBUTE:registered claim exists anywhere.
        for claim in store.list_claims(support.DEFAULT_INV):
            assert claim.predicate.lower() != "has_attribute:registered"
            if claim.object_literal is not None:
                assert str(claim.object_literal) != "False"


# ════════════════════════════════════════════════════════════════════════
# 2. intake — transliteration, stopwords, precise permutations, field splitting
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def engine_factory(tmp_path, isolated_mock_registry):
    from hub.investigation.engine import InvestigationEngine
    from tests.mock_tools import MockRunner, empty_output, parse_mock

    isolated_mock_registry(
        make_capability("mock_email_tool", [EntityType.EMAIL],
                        [EntityType.SERVICE], prior_yield=0.9),
        make_capability("mock_user_tool", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.9),
        make_capability("mock_phone_tool", [EntityType.PHONE],
                        [EntityType.ORGANIZATION], prior_yield=0.9))

    def build():
        return InvestigationEngine(
            runner=MockRunner(default=lambda capability, params: empty_output()),
            parser_resolver=lambda capability: parse_mock,
            health_probe=lambda capability: True,
            state_root=tmp_path / "state",
        )

    return build


class TestIntakePrecision:
    def test_transliteration_digraph_and_ascii(self):
        assert transliteration_variants("Taşkin") == ["tashkin", "taskin"]
        assert transliteration_variants("Əliyev") == ["eliyev", "aliyev"]
        assert transliteration_variants("Fərid") == ["ferid", "farid"]

    def test_hypotheses_transliterate_not_strip(self):
        intake = MultiClueIntake()
        drafts = intake.hypothesis_drafts(
            "Target is Elvin Taşkin",
            {"emails": ["elvin.s.tashkin.std@example.edu.az"]},
        )
        usernames = [d.value for d in drafts if d.entity_type == EntityType.USERNAME]
        emails = [d.value for d in drafts if d.entity_type == EntityType.EMAIL]
        assert {"elvin.tashkin", "elvin_tashkin", "elvintashkin",
                "elvin.taskin"} <= set(usernames)
        assert all("takin" not in value for value in usernames + emails)
        assert any("tashkin" in value for value in emails)
        assert any("taskin" in value for value in emails)
        assert len(usernames) <= 6
        assert len(emails) <= 4

    def test_stopwords_and_generic_first_name_emails_banned(self):
        drafts = MultiClueIntake().hypothesis_drafts(
            "Target is Elvin Taşkin, student in a few days, goes by elv1ntsk")
        values = [d.value for d in drafts]
        assert not any("elvin_in" in value or "_in" in value for value in values)
        banned = {"elvin@gmail.com", "elvin@outlook.com", "elvin@protonmail.com"}
        assert not (set(values) & banned)
        usernames = [d.value for d in drafts if d.entity_type == EntityType.USERNAME]
        assert all(not any(part in {"in", "at", "on", "of", "the", "and", "by"}
                           for part in username.replace(".", "_").split("_"))
                   for username in usernames)

    def test_organizations_and_handles_split(self):
        intake = MultiClueIntake()
        orgs = [clue.value for clue in intake.extract(
            "", {"organizations": "acme, techuni, laborg"})
            if clue.entity_type == EntityType.ORGANIZATION]
        assert orgs == ["acme", "techuni", "laborg"]
        usernames = [clue.value for clue in intake.extract(
            "", {"usernames": "elv1ntsk 108.elv1n"})
            if clue.entity_type == EntityType.USERNAME]
        assert usernames == ["elv1ntsk", "108.elv1n"]
        locations = [clue.value for clue in intake.extract(
            "", {"locations": "Baku; Ganja\nSumqayit"})
            if clue.entity_type == EntityType.LOCATION]
        assert locations == ["Baku", "Ganja", "Sumqayit"]

    def test_seed_email_surname_tokens_used(self):
        drafts = MultiClueIntake().hypothesis_drafts(
            'Target is Elvin, email "elvin.s.tashkin.std@example.edu.az"')
        usernames = {d.value for d in drafts if d.entity_type == EntityType.USERNAME}
        assert any("tashkin" in value for value in usernames)

    def test_scope_not_locked_by_seed_email(self, engine_factory):
        import asyncio

        engine = engine_factory()
        created = asyncio.run(engine.create(
            "user@example.edu.az",
            {"min_pivot_threshold": 0.99},
        ))
        store = engine.open_store(created.target_id)
        try:
            investigation = store.get_investigation(created.target_id)
            assert "example.edu.az" not in investigation.config.scope.allow_domains
        finally:
            store.close()


# ════════════════════════════════════════════════════════════════════════
# 3. seed-first pivot scoring + cross-tool/entity diversification
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def seed_registry(isolated_mock_registry):
    isolated_mock_registry(
        make_capability("mock_user_tool", [EntityType.USERNAME],
                        [EntityType.SOCIAL_PROFILE], prior_yield=0.9),
        make_capability("mock_email_tool", [EntityType.EMAIL],
                        [EntityType.SERVICE], prior_yield=0.9),
        make_capability("mock_phone_tool", [EntityType.PHONE],
                        [EntityType.ORGANIZATION], prior_yield=0.9),
    )


def _seed_graph(store):
    support.bootstrap(store)
    seed_user = support.entity(store, EntityType.USERNAME, "elv1ntsk",
                               metadata={"provenance": USER_PROVIDED_SEED,
                                         "origin": "raw_input"})
    seed_email = support.entity(store, EntityType.EMAIL,
                                "elvin.s.tashkin.std@example.edu.az",
                                metadata={"provenance": USER_PROVIDED_SEED,
                                          "origin": "raw_input"})
    seed_phone = support.entity(store, EntityType.PHONE, "+994551234567",
                                metadata={"provenance": USER_PROVIDED_SEED,
                                          "origin": "raw_input"})
    guessed = support.entity(store, EntityType.EMAIL, "elvin@gmail.com",
                             metadata={"provenance": "USER_DERIVED_HYPOTHESIS",
                                       "origin": "hypothesis"})
    support.claim(store, seed_user.entity_id, "HAS_EMAIL",
                  object_id=seed_email.entity_id)
    support.claim(store, seed_user.entity_id, "HAS_PHONE",
                  object_id=seed_phone.entity_id)
    support.claim(store, seed_email.entity_id, "ASSOCIATED_WITH",
                  object_id=guessed.entity_id)
    support.set_seeds(store, [seed_user.entity_id, seed_email.entity_id,
                              seed_phone.entity_id])
    return seed_user, seed_email, seed_phone, guessed


class TestSeedFirstPivots:
    def test_seed_entities_rank_above_guessed_hypotheses(self, store_factory, seed_registry):
        store = store_factory()
        seed_user, seed_email, seed_phone, guessed = _seed_graph(store)
        view = support.graph(store, [seed_user.entity_id, seed_email.entity_id,
                                     seed_phone.entity_id])
        ranking = PivotScorer(min_threshold=0.0).rank(
            view, [], allowed_tool_ids={"mock_user_tool", "mock_email_tool",
                                        "mock_phone_tool"})
        assert ranking.selected
        selected_entities = [candidate.entity_id for candidate in ranking.selected]
        guessed_positions = [index for index, entity_id in enumerate(selected_entities)
                             if entity_id == guessed.entity_id]
        seed_positions = [index for index, entity_id in enumerate(selected_entities)
                          if entity_id in {seed_user.entity_id, seed_email.entity_id,
                                           seed_phone.entity_id}]
        assert seed_positions
        if guessed_positions:
            assert max(seed_positions) < min(guessed_positions)
        # all_candidates is tier-sorted: every USER_PROVIDED_SEED candidate comes
        # before the guessed HYPOTHESIS permutation.
        seed_idx = [i for i, c in enumerate(ranking.all_candidates)
                    if c.entity_id in {seed_user.entity_id, seed_email.entity_id,
                                       seed_phone.entity_id}]
        hyp_idx = [i for i, c in enumerate(ranking.all_candidates)
                   if c.entity_id == guessed.entity_id]
        assert seed_idx and hyp_idx
        assert max(seed_idx) < min(hyp_idx)

    def test_guessed_hypothesis_corroboration_capped(self, store_factory, seed_registry):
        store = store_factory()
        seed_user, seed_email, seed_phone, guessed = _seed_graph(store)
        now = utc_now()
        store.add_hypothesis(
            Hypothesis(
                hypothesis_id="hyp_guess",
                investigation_id=support.DEFAULT_INV,
                hypothesis_type=HypothesisType.CORROBORATION,
                question="Is the guessed email real?",
                target_entity_id=guessed.entity_id,
                proposed_tool_ids=["mock_email_tool"],
                rationale="verify guessed permutation",
                status=HypothesisStatus.OPEN,
                created_at=now, updated_at=now,
            )
        )
        view = support.graph(store, [seed_user.entity_id, seed_email.entity_id,
                                     seed_phone.entity_id])
        ranking = PivotScorer(min_threshold=0.0).rank(
            view, store.list_hypotheses(support.DEFAULT_INV),
            allowed_tool_ids={"mock_user_tool", "mock_email_tool", "mock_phone_tool"})
        guessed_candidates = [candidate for candidate in ranking.all_candidates
                              if candidate.entity_id == guessed.entity_id]
        assert guessed_candidates
        assert all(candidate.corroboration_value <= 0.20
                   for candidate in guessed_candidates)
        assert all(candidate.score < max(
            candidate.score for candidate in ranking.all_candidates
            if candidate.entity_id in {seed_user.entity_id, seed_email.entity_id,
                                       seed_phone.entity_id})
            for candidate in guessed_candidates)

    def test_engine_intake_provenance_and_seed_first_ranking(self, engine_factory):
        import asyncio

        from hub.erkg.graph import GraphView

        engine = engine_factory()
        created = asyncio.run(engine.create(
            "Target is Elvin Taşkin, goes by elv1ntsk, "
            "email elvin.s.tashkin.std@example.edu.az, phone +994551234567",
            {"min_pivot_threshold": 0.0},
        ))
        store = engine.open_store(created.target_id)
        try:
            investigation = store.get_investigation(created.target_id)
            graph = GraphView(store, created.target_id,
                              investigation.seed_entity_ids)
            seed_types = {graph.entities[entity_id].type
                          for entity_id in graph.seed_entity_ids
                          if entity_id in graph.entities}
            assert EntityType.USERNAME in seed_types
            assert EntityType.EMAIL in seed_types
            assert EntityType.PHONE in seed_types
            for entity_id in investigation.seed_entity_ids:
                entity = graph.entities.get(entity_id)
                assert entity is not None
                assert entity.metadata.get("provenance") in {
                    USER_PROVIDED_SEED, EMAIL_DERIVED_DOMAIN,
                    EMAIL_DERIVED_USERNAME,
                }
            # Guessed permutations exist too, but seed pivots rank first.
            guessed = [entity for entity in graph.entities.values()
                       if entity.metadata.get("provenance") == "USER_DERIVED_HYPOTHESIS"]
            assert guessed
            ranking = engine._rank_pivots(
                store, investigation, graph,
                available_tool_ids={"mock_user_tool", "mock_email_tool",
                                    "mock_phone_tool"})
            assert ranking.selected
            first = ranking.selected[0]
            assert first.entity_id in set(investigation.seed_entity_ids)
            guessed_ids = {entity.entity_id for entity in guessed}
            assert first.entity_id not in guessed_ids
            # All user seeds precede guessed hypotheses in the full ordering.
            seed_positions = [index for index, candidate in enumerate(ranking.all_candidates)
                              if candidate.entity_id in set(investigation.seed_entity_ids)]
            guessed_positions = [index for index, candidate in enumerate(ranking.all_candidates)
                                 if candidate.entity_id in guessed_ids]
            if seed_positions and guessed_positions:
                assert max(seed_positions) < min(guessed_positions)
        finally:
            store.close()

    def test_cross_entity_wave_after_first_seed_execution(self, store_factory, seed_registry):
        store = store_factory()
        seed_user, seed_email, seed_phone, guessed = _seed_graph(store)
        view = support.graph(store, [seed_user.entity_id, seed_email.entity_id,
                                     seed_phone.entity_id])
        capability = cap_registry.get_tool("mock_user_tool")
        params = cap_registry.build_params_for_entity(
            capability, EntityType.USERNAME, seed_user.canonical_value)
        executed = {(seed_user.entity_id, capability.tool_id,
                     param_hash(capability.tool_id, params))}
        ranking = PivotScorer(min_threshold=0.0).rank(
            view, [], allowed_tool_ids={"mock_user_tool", "mock_email_tool",
                                        "mock_phone_tool"},
            executed_keys=executed)
        assert ranking.selected
        first = ranking.selected[0]
        assert first.entity_id != seed_user.entity_id
        assert first.entity_id in {seed_email.entity_id, seed_phone.entity_id}
        # Guessed HYPOTHESIS still never displaces a user seed.
        assert first.entity_id != guessed.entity_id


# ════════════════════════════════════════════════════════════════════════
# 4. Web UI / SSE lifecycle quality
# ════════════════════════════════════════════════════════════════════════

class TestWebWorkbenchQuality:
    def test_interactive_graph_controls_and_clean_defaults(self):
        from hub.web import WORKBENCH_HTML, STREAM_KEEPALIVE_SEC

        html = WORKBENCH_HTML
        for marker in ("id=\"graph-toolbar\"", "id=\"zoom-in\"", "id=\"zoom-out\"",
                       "id=\"zoom-reset\"", "id=\"node-search\"",
                       "id=\"type-filters\"", "id=\"clear-form\"",
                       "filter-pill", "node-match", "node-dim",
                       "waitForCompletionAfterTimeout", "COMPLETED",
                       "graph-viewport", "wheel"):
            assert marker in html, marker
        # No pre-filled example values in intake controls.
        assert 'placeholder="example.com"' not in html
        assert 'placeholder="93.184.216.34"' not in html
        assert 'placeholder="hamid091, @target"' not in html
        assert STREAM_KEEPALIVE_SEC == 2.0

    def test_sse_deadline_uses_wall_clock_plus_buffer(self, monkeypatch):
        from hub import web

        fake_state = {
            "investigation": {"config": {"budgets": {
                "wall_clock_timeout_sec": 120}}},
        }
        monkeypatch.setattr(web, "_probe_stream_state", lambda service, target: fake_state)
        assert web._stream_deadline_seconds(service=None, target_id="case_x") == 150.0

    def test_stream_deadline_falls_back_conservatively(self, monkeypatch):
        from hub import web

        monkeypatch.setattr(web, "_probe_stream_state", lambda service, target: None)
        assert web._stream_deadline_seconds(service=None, target_id="case_x") == \
            web.STREAM_MAX_SECONDS
