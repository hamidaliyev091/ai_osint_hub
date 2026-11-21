"""Phase 17 self-test regression suite — handle guard, intake, GitHub, Ahmia, phone."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from hub.erkg.ingestion import EvidenceIngestor
from hub.erkg.resolution import derive_entity_drafts, normalize_phone, normalize_username
from hub.intake import (
    EMAIL_DERIVED_USERNAME,
    MultiClueIntake,
    StructuredSeeds,
)
from hub.investigation.engine import InvestigationEngine
from hub.models import EntityType
from hub.tools import capabilities
from hub.tools.builtin import darkweb_ahmia, github_osint
from hub.tools.parsers import github_osint as github_parser
from hub.tools.parsers.darkweb_ahmia import parse as parse_ahmia
from hub.tools.parsers.sherlock import parse as parse_sherlock
from tests import support
from tests.mock_tools import MockRunner, empty_output, parse_mock
from tests.test_api_collectors_phase10 import (
    _collect as _collect_builtin,
    _install_transport,
    _response,
    _set_secrets,
)


SELFTEST_STRUCTURED = {
    "name": "Kamran Mammadov",
    "usernames": ["kamranmmv"],
    "emails": ["kamranmammadov01@example.com"],
    "phones": ["0501234567"],
    "location": "Baku, AZ",
}
SELFTEST_RAW = "Kamran Mammadov studies in baku technical institute 18 years old"


# ════════════════════════════════════════════════════════════════════════
# 1. Global USERNAME guard + Sherlock soft-404 additions
# ════════════════════════════════════════════════════════════════════════

class TestUsernameGuard:
    def test_email_is_never_a_username(self):
        email = "kamranmammadov01@example.com"
        assert normalize_username(email) == ""
        assert derive_entity_drafts(EntityType.USERNAME, email)[0] == []
        assert derive_entity_drafts(EntityType.USERNAME,
                                    "search-by-username")[0] == []

    def test_ingestor_reclassifies_email_labelled_username(self, store_factory):
        from hub.tools.base import EntityCandidate, ParseOutput

        store = store_factory()
        support.bootstrap(store)
        artifact = support.artifact(store, "sherlock")
        EvidenceIngestor(store).ingest(
            support.DEFAULT_INV,
            ParseOutput(entities=[EntityCandidate(
                type=EntityType.USERNAME,
                value="kamranmammadov01@example.com", confidence=0.8)]),
            artifact_id=artifact, tool_id="sherlock", accepted_types=[],
            timestamp=support.utc_now())
        usernames = [entity.canonical_value for entity in
                     store.list_entities(support.DEFAULT_INV,
                                         types=[EntityType.USERNAME])]
        assert "kamranmammadov01@example.com" not in usernames
        assert any("@" in entity.canonical_value for entity in
                   store.list_entities(support.DEFAULT_INV,
                                       types=[EntityType.EMAIL]))

    def test_sherlock_soft404_expansion_and_root_urls(self):
        raw = (
            "[+] Hudson Rock: https://cavalier.hudsonrock.com/search-by-username\n"
            "[+] AniWorld: https://aniworld.to/user/ali\n"
            "[+] OMG.LOL: https://omg.lol/ali\n"
            "[+] Giphy: https://giphy.com/ali\n"
            "[+] Discord: https://discord.com\n"
            "[+] GitHub: https://github.com/ali\n"
        )
        out = parse_sherlock(raw, "ali")
        profiles = {entity.value for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        services = {entity.value for entity in out.entities
                    if entity.type is EntityType.SERVICE}
        assert profiles == {"https://github.com/ali"}
        assert services == {"github"}
        assert not any("search-by-username" in value.lower()
                       for entity in out.entities for value in [entity.value])

    def test_maigret_no_recursion_flag(self):
        cap = capabilities.get_tool("maigret")
        assert "--no-recursion" in cap.invocation.extra_flags


# ════════════════════════════════════════════════════════════════════════
# 2. Intake: person ali, doubled handles, derived username, E.164 phone
# ════════════════════════════════════════════════════════════════════════

class TestIntakeSelfTest:
    def test_no_person_prefix_or_doubled_hypotheses(self):
        intake = MultiClueIntake()
        clues = intake.extract(SELFTEST_RAW, StructuredSeeds.from_mapping(
            SELFTEST_STRUCTURED))
        persons = {clue.value.lower() for clue in clues
                   if clue.entity_type == EntityType.PERSON}
        assert persons == {"kamran mammadov"}
        drafts = intake.hypothesis_drafts(
            SELFTEST_RAW, SELFTEST_STRUCTURED)
        values = {draft.value.lower() for draft in drafts}
        for doubled in ("kamran.kamranmammadov01", "kamran_kamranmammadov01",
                        "kamrankamranmammadov01"):
            assert doubled not in values
            assert not any(doubled in value for value in values)
        for draft in drafts:
            if draft.entity_type == EntityType.USERNAME:
                assert not draft.value.startswith("kamran.kamran")
                assert not draft.value.startswith("kamran_kamran")

    def test_phone_is_normalized_to_azerbaijan_e164(self):
        clues = MultiClueIntake().extract(
            SELFTEST_RAW, StructuredSeeds.from_mapping(SELFTEST_STRUCTURED))
        phones = {clue.value for clue in clues
                  if clue.entity_type == EntityType.PHONE}
        assert phones == {"+994501234567"}
        assert normalize_phone("0501234567") == "+994501234567"
        assert normalize_phone("0044501234567").startswith("+44")
        cap = capabilities.get_tool("phoneinfoga")
        params = capabilities.build_params_for_entity(
            cap, EntityType.PHONE, "0501234567")
        assert params == {"phone": "+994501234567"}

    def test_engine_seed_wave_includes_email_derived_username(self, tmp_path):
        engine = InvestigationEngine(
            runner=MockRunner(default=lambda capability, params: empty_output()),
            parser_resolver=lambda capability: parse_mock,
            health_probe=lambda capability: True,
            state_root=tmp_path / "state",
        )
        created = asyncio.run(engine.create(
            SELFTEST_RAW,
            {"target_id": "phase17_intake", "min_pivot_threshold": 0.99},
            structured_seeds=SELFTEST_STRUCTURED,
        ))
        store = engine.open_store(created.target_id)
        try:
            investigation = store.get_investigation(created.target_id)
            seeded = [store.get_entity(entity_id)
                      for entity_id in investigation.seed_entity_ids]
            derived = [entity for entity in seeded
                       if entity.type is EntityType.USERNAME
                       and entity.canonical_value == "kamranmammadov01"]
            assert derived
            assert derived[0].metadata.get("provenance") == EMAIL_DERIVED_USERNAME
            phones = [entity.canonical_value for entity in seeded
                      if entity.type is EntityType.PHONE]
            assert "+994501234567" in phones
            persons = [entity.canonical_value for entity in
                       store.list_entities(created.target_id,
                                           types=[EntityType.PERSON])]
            assert persons == ["kamran mammadov"]
            person_id = next(entity.entity_id for entity in seeded
                             if entity.type is EntityType.PERSON)
            claims = store.list_claims(created.target_id, subject_id=person_id)
            assert any(claim.predicate == "HAS_USERNAME"
                       and claim.object_id == derived[0].entity_id
                       for claim in claims)
        finally:
            store.close()


# ════════════════════════════════════════════════════════════════════════
# 3. GitHub e-mail -> user/repo resolution
# ════════════════════════════════════════════════════════════════════════

GITHUB_SELFTEST_EMAIL = "kamranmammadov01@example.com"


def _github_selftest_handler(request):
    path = request.url.path
    if path == "/search/users":
        return _response({"total_count": 0, "items": []})
    if path == "/search/commits":
        return _response({"total_count": 1, "items": [{
            "author": {"login": "kamranmammadov01"},
            "committer": {"login": "kamranmammadov01"},
            "commit": {"author": {"email": GITHUB_SELFTEST_EMAIL}},
            "repository": {"full_name": "kamranmammadov01/project",
                           "html_url": "https://github.com/kamranmammadov01/project"},
        }]})
    if path == "/users/kamranmammadov01":
        return _response({"login": "kamranmammadov01", "name": "Kamran Mammadov",
                          "html_url": "https://github.com/kamranmammadov01",
                          "public_repos": 1})
    if path == "/users/kamranmammadov01/repos":
        return _response([{"full_name": "kamranmammadov01/project",
                           "html_url": "https://github.com/kamranmammadov01/project"}])
    return _response({"message": "Not Found"}, status=404)


class TestGithubEmailResolution:
    def test_email_resolves_login_and_repos(self, monkeypatch):
        _set_secrets(monkeypatch)
        _install_transport(monkeypatch, _github_selftest_handler)
        result = _collect_builtin(github_osint, {"email": GITHUB_SELFTEST_EMAIL})
        assert result.exit_code == 0 and result.error_code is None
        payload = json.loads(result.stdout)
        assert [user["login"] for user in payload["users"]] == ["kamranmammadov01"]
        assert [repo["full_name"] for repo in payload["repos"]] == [
            "kamranmammadov01/project"]

        parsed = github_parser.parse(result.stdout, GITHUB_SELFTEST_EMAIL)
        usernames = {entity.value for entity in parsed.entities
                     if entity.type is EntityType.USERNAME}
        repositories = {entity.value for entity in parsed.entities
                        if entity.type is EntityType.REPOSITORY}
        assert "kamranmammadov01" in usernames
        assert GITHUB_SELFTEST_EMAIL not in usernames
        assert "kamranmammadov01/project" in repositories
        assert any(relation.predicate.value == "OWNS"
                   and relation.object_value == "kamranmammadov01/project"
                   for relation in parsed.relations)

    def test_email_query_requests_commit_author_search(self, monkeypatch):
        seen: dict = {}

        async def handler(request):
            seen.setdefault("queries", []).append(
                (request.url.path, request.url.params.get("q", "")))
            return _github_selftest_handler(request)

        _set_secrets(monkeypatch)
        _install_transport(monkeypatch, handler)
        result = _collect_builtin(github_osint, {"email": GITHUB_SELFTEST_EMAIL})
        assert result.exit_code == 0
        queries = seen["queries"]
        assert any(path == "/search/commits"
                   and GITHUB_SELFTEST_EMAIL in query
                   for path, query in queries)
        assert any(path == "/users/kamranmammadov01" for path, _ in queries)


# ════════════════════════════════════════════════════════════════════════
# 4. Ahmia exact-match filtering
# ════════════════════════════════════════════════════════════════════════

AHMIA_SELFTEST_HTML = """<html><body><ul>
<li class="result"><a href="/search/redirect?search_term=x&amp;redirect_url=http%3A%2F%2Faaa.onion%2Fpage">Contact kamranmammadov01 profile</a><p>reach kamranmammadov01 via this page</p></li>
<li class="result"><a href="/search/redirect?search_term=x&amp;redirect_url=http%3A%2F%2Fbbb.onion%2Fshop">Buy guns</a><p>mail gitgitgadget@gmail.com for deals</p></li>
<li class="result"><a href="/search/redirect?search_term=x&amp;redirect_url=http%3A%2F%2Fccc.onion%2F">Unrelated shop</a><p>gmail.com only here</p></li>
</ul></body></html>"""


def _ahmia_selftest_handler(request):
    return httpx.Response(200, content=AHMIA_SELFTEST_HTML.encode("utf-8"),
                          headers={"content-type": "text/html"})


class TestAhmiaExactMatch:
    def test_collector_keeps_only_exact_local_part(self, monkeypatch):
        _install_transport(monkeypatch, _ahmia_selftest_handler)
        result = _collect_builtin(
            darkweb_ahmia, {"email": GITHUB_SELFTEST_EMAIL})
        assert result.exit_code == 0 and result.error_code is None
        payload = json.loads(result.stdout)
        assert [onion["url"] for onion in payload["onions"]] == [
            "http://aaa.onion/page"]

    def test_parser_drops_gmail_only_results(self):
        raw = json.dumps({
            "query": GITHUB_SELFTEST_EMAIL,
            "onions": [
                {"url": "http://aaa.onion/page",
                 "title": "Contact kamranmammadov01",
                 "snippet": "profile page"},
                {"url": "http://bbb.onion/shop", "title": "Buy guns",
                 "snippet": "gitgitgadget@gmail.com"},
            ],
            "evidence": {"params": {"email": GITHUB_SELFTEST_EMAIL}},
        })
        out = parse_ahmia(raw, GITHUB_SELFTEST_EMAIL)
        urls = [entity.value for entity in out.entities
                if entity.type is EntityType.URL]
        assert urls == ["http://aaa.onion/page"]

    def test_zero_exact_matches_yields_zero_urls(self):
        raw = json.dumps({
            "query": GITHUB_SELFTEST_EMAIL,
            "onions": [
                {"url": "http://bbb.onion/shop", "title": "Buy guns",
                 "snippet": "gitgitgadget@gmail.com"},
            ],
            "evidence": {"params": {"email": GITHUB_SELFTEST_EMAIL}},
        })
        out = parse_ahmia(raw, GITHUB_SELFTEST_EMAIL)
        assert not [entity for entity in out.entities
                    if entity.type is EntityType.URL]
