"""Phase 13 hygiene regression tests — banners/config files, public suffixes, snscrape, hypotheses."""

from __future__ import annotations

import asyncio
import json

import pytest

from hub.erkg.graph import GraphView
from hub.erkg.resolution import (
    derive_entity_drafts,
    normalize_domain,
    split_hostname,
)
from hub.investigation.engine import InvestigationEngine
from hub.investigation.hypotheses import HypothesisGenerator
from hub.models import EntityType, HypothesisType, utc_now
from hub.tools import capabilities as cap_registry
from hub.tools.builtin import snscrape as snscrape_collector
from hub.tools.parsers.sherlock import parse as parse_sherlock
from hub.tools.parsers.snscrape import parse as parse_snscrape
from hub.tools.parsers.theharvester import parse as parse_theharvester
from tests import support
from tests.mock_tools import (
    MockRunner,
    empty_output,
    make_capability,
    parse_mock,
)
from tests.test_api_collectors_phase10 import _install_transport, _response


# ════════════════════════════════════════════════════════════════════════
# 1. theHarvester banner/config noise + global file-extension guard
# ════════════════════════════════════════════════════════════════════════

THEHARVESTER_NOISE = """*******************************************************************
* theHarvester 4.11.1
* Christian Martorella
* cmartorella@edge-security.com
* https://edge-security.com
* An open source intelligence gathering tool
*******************************************************************
Read proxies.yaml from C:\\Users\\analyst\\.theHarvester\\proxies.yaml
Read api-keys.yaml from C:\\Users\\analyst\\.theHarvester\\api-keys.yaml
[*] Target: example.edu.az
[*] Emails found: 1
elvin.s.tashkin.std@example.edu.az
[*] Hosts found: 2
mail.example.edu.az:1.2.3.4
example.edu.az
[*] IPs found: 1
1.2.3.4
"""


class TestTheHarvesterHygiene:
    def test_banner_and_config_filenames_never_ingested(self):
        out = parse_theharvester(THEHARVESTER_NOISE, "example.edu.az")
        values = {(entity.type.value, entity.value.lower()) for entity in out.entities}
        for leaked in ("cmartorella@edge-security.com", "cmartorella",
                       "edge-security.com", "proxies.yaml", "api-keys.yaml"):
            assert all(leaked not in value for _, value in values), leaked
        assert ("email", "elvin.s.tashkin.std@example.edu.az") in values
        assert ("domain", "example.edu.az") in values
        assert ("subdomain", "mail.example.edu.az") in values
        assert ("ip", "1.2.3.4") in values

    def test_fallback_also_cleans_banner(self):
        raw = ("Author: Christian Martorella cmartorella@edge-security.com\n"
               "Read proxies.yaml from C:/tmp/proxies.yaml\n"
               "found example.edu.az and elvin@example.edu.az\n")
        out = parse_theharvester(raw, "example.edu.az")
        values = {entity.value.lower() for entity in out.entities}
        assert "example.edu.az" in values
        assert "elvin@example.edu.az" in values
        assert not any("edge-security" in value or "proxies.yaml" in value
                       for value in values)

    def test_file_extensions_never_valid_domains(self):
        for name in ("proxies.yaml", "api-keys.yml", "keys.json", "page.html",
                     "app.js", "dump.sqlite", "config.ini"):
            assert normalize_domain(name) == ""
            assert split_hostname(name) is None
            assert derive_entity_drafts(EntityType.DOMAIN, name)[0] == []

    def test_domain_file_extension_guard_is_global(self, store_factory):
        from hub.erkg.ingestion import EvidenceIngestor
        from hub.tools.base import EntityCandidate, ParseOutput

        store = store_factory()
        support.bootstrap(store)
        artifact = support.artifact(store, "theharvester")
        parsed = ParseOutput(entities=[
            EntityCandidate(type=EntityType.DOMAIN, value="proxies.yaml",
                            confidence=0.5),
            EntityCandidate(type=EntityType.DOMAIN, value="example.edu.az",
                            confidence=0.8),
        ])
        EvidenceIngestor(store).ingest(
            support.DEFAULT_INV, parsed, artifact_id=artifact,
            tool_id="theharvester", accepted_types=[],
            timestamp=utc_now())
        values = {entity.canonical_value
                  for entity in store.list_entities(support.DEFAULT_INV)
                  if entity.type is EntityType.DOMAIN}
        assert "example.edu.az" in values
        assert "proxies.yaml" not in values


# ════════════════════════════════════════════════════════════════════════
# 2. Multi-part public suffixes + email-domain edge semantics
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def engine(tmp_path, isolated_mock_registry):
    isolated_mock_registry(
        make_capability("mock_domain_tool", [EntityType.DOMAIN],
                        [EntityType.IP], prior_yield=0.9),
        make_capability("mock_email_tool", [EntityType.EMAIL],
                        [EntityType.SERVICE], prior_yield=0.9),
    )
    return InvestigationEngine(
        runner=MockRunner(default=lambda capability, params: empty_output()),
        parser_resolver=lambda capability: parse_mock,
        health_probe=lambda capability: True,
        state_root=tmp_path / "state",
    )


class TestPublicSuffixesAndDomainEdges:
    def test_multi_part_country_suffixes_are_public(self):
        assert split_hostname("example.edu.az") == ("example.edu.az", "example.edu.az", False)
        assert split_hostname("mail.example.edu.az") == (
            "mail.example.edu.az", "example.edu.az", True)
        for host in ("example.edu.tr", "school.ac.uk", "agency.gov.az",
                     "company.com.az", "org.co.uk"):
            host_value, registrable, is_sub = split_hostname(host)
            assert host_value == host and registrable == host and is_sub is False

    def test_domain_drafts_never_create_public_suffix_domain(self):
        drafts, relations = derive_entity_drafts(EntityType.DOMAIN, "example.edu.az")
        assert [(draft.entity_type, draft.canonical_value) for draft in drafts] == [
            (EntityType.DOMAIN, "example.edu.az")]
        assert not any("edu.az" == draft.canonical_value for draft in drafts)
        drafts, relations = derive_entity_drafts(EntityType.DOMAIN,
                                                 "mail.example.edu.az")
        values = {(draft.entity_type.value, draft.canonical_value)
                  for draft in drafts}
        assert values == {("subdomain", "mail.example.edu.az"),
                          ("domain", "example.edu.az")}
        assert any(relation.predicate.value == "SUBDOMAIN_OF"
                   and relation.object_raw == "example.edu.az"
                   for relation in relations)

    def test_email_derived_domain_links_associated_not_owned(self, engine):
        created = asyncio.run(engine.create(
            "Target is Elvin Taşkin, email elvin.s.tashkin.std@example.edu.az",
            {"min_pivot_threshold": 0.99}))
        store = engine.open_store(created.target_id)
        try:
            person = store.get_entity_by_value(created.target_id, EntityType.PERSON,
                                               "elvin taşkin") or \
                store.get_entity_by_value(created.target_id, EntityType.PERSON,
                                          "elvin tashkin")
            domain = store.get_entity_by_value(created.target_id, EntityType.DOMAIN,
                                               "example.edu.az")
            assert person is not None and domain is not None
            assert store.get_entity_by_value(created.target_id, EntityType.DOMAIN,
                                             "edu.az") is None
            claims = store.list_claims(created.target_id,
                                       subject_id=person.entity_id)
            by_predicate = {}
            for claim in claims:
                by_predicate.setdefault(claim.predicate, []).append(claim)
            assert not by_predicate.get("OWNS")
            associated = by_predicate.get("ASSOCIATED_WITH", [])
            assert any(claim.object_id == domain.entity_id for claim in associated)
            email = store.get_entity_by_value(
                created.target_id, EntityType.EMAIL,
                "elvin.s.tashkin.std@example.edu.az")
            email_claims = store.list_claims(created.target_id,
                                             subject_id=email.entity_id)
            assert any(claim.predicate == "ASSOCIATED_WITH"
                       and claim.object_id == domain.entity_id
                       for claim in email_claims)
        finally:
            store.close()

    def test_explicitly_provided_domain_still_owned(self, engine):
        created = asyncio.run(engine.create(
            "",
            {"min_pivot_threshold": 0.99},
            structured_seeds={
                "name": "Elvin Taşkin",
                "emails": ["elvin.s.tashkin.std@example.edu.az"],
                "domains": ["personal.example"],
            }))
        store = engine.open_store(created.target_id)
        try:
            person = store.get_entity_by_value(created.target_id, EntityType.PERSON,
                                               "elvin taşkin") or \
                store.get_entity_by_value(created.target_id, EntityType.PERSON,
                                          "elvin tashkin")
            explicit = store.get_entity_by_value(created.target_id, EntityType.DOMAIN,
                                                 "personal.example")
            derived = store.get_entity_by_value(created.target_id, EntityType.DOMAIN,
                                                "example.edu.az")
            claims = store.list_claims(created.target_id,
                                       subject_id=person.entity_id)
            owned = [claim for claim in claims if claim.predicate == "OWNS"]
            associated = [claim for claim in claims if claim.predicate == "ASSOCIATED_WITH"]
            assert any(claim.object_id == explicit.entity_id for claim in owned)
            assert any(claim.object_id == derived.entity_id for claim in associated)
            assert not any(claim.object_id == derived.entity_id for claim in owned)
        finally:
            store.close()


# ════════════════════════════════════════════════════════════════════════
# 3. snscrape native probe (replaces NONZERO_EXIT CLI)
# ════════════════════════════════════════════════════════════════════════

class TestSnscrapeNative:
    def test_capability_is_python_native(self):
        cap = cap_registry.get_tool("snscrape")
        assert cap.invocation.kind == "builtin"
        assert cap.invocation.binary is None
        assert "snscrape" in cap.invocation.builtin_ref
        status = cap_registry.health_check("snscrape", force=True)
        assert status is not None and status.available is True

    def test_public_profile_probes_emit_jsonl(self, monkeypatch):
        async def handler(request):
            url = str(request.url)
            if "gitlab.com/api/v4/users" in url:
                return _response([{"username": "alice", "name": "Alice",
                                   "web_url": "https://gitlab.com/alice"}])
            if "lichess.org/api/user" in url:
                return _response({"username": "alice",
                                  "url": "https://lichess.org/@/alice"})
            if "hacker-news.firebaseio.com" in url:
                return _response({"id": "alice", "karma": 10})
            return _response({"message": "Not Found"}, status=404)

        _install_transport(monkeypatch, handler)
        result = asyncio.run(snscrape_collector.collect(
            {"username": "alice"}, timeout_sec=10, scope=None))
        assert result.exit_code == 0
        assert result.error_code is None
        records = [json.loads(line) for line in result.stdout.splitlines() if line]
        sources = {record["source"] for record in records}
        assert {"gitlab", "lichess", "hackernews"} <= sources
        assert all(record["user"]["username"] == "alice" for record in records)
        parsed = parse_snscrape(result.stdout, "alice")
        profiles = {entity.value for entity in parsed.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert "https://gitlab.com/alice" in profiles
        assert "https://lichess.org/@/alice" in profiles

    def test_no_public_profile_is_clean_empty(self, monkeypatch):
        async def handler(request):
            return _response({"message": "Not Found"}, status=404)

        _install_transport(monkeypatch, handler)
        result = asyncio.run(snscrape_collector.collect(
            {"username": "nobody-9210"}, timeout_sec=10, scope=None))
        assert result.exit_code == 0
        assert result.error_code is None
        assert result.stdout == ""

    def test_runtime_never_reports_nonzero_exit(self, monkeypatch):
        from hub.tools.runtime import RunContext, ToolRuntime
        from hub.models import ScopeConfig

        async def handler(request):
            if "lichess.org/api/user" in str(request.url):
                return _response({"username": "alice",
                                  "url": "https://lichess.org/@/alice"})
            return _response({"message": "Not Found"}, status=404)

        _install_transport(monkeypatch, handler)
        cap = cap_registry.get_tool("snscrape")

        async def run():
            runtime = ToolRuntime()
            try:
                return await runtime.run(
                    cap, {"username": "alice"},
                    RunContext(investigation_id="t", entity_id="e",
                               scope=ScopeConfig(), timeout_override_s=20))
            finally:
                await runtime.aclose()

        result = asyncio.run(run())
        assert result.status.value == "SUCCESS"
        assert result.error_code is None
        assert result.exit_code == 0


# ════════════════════════════════════════════════════════════════════════
# 4. Hypothesis hygiene + Sherlock soft-404 filtering
# ════════════════════════════════════════════════════════════════════════

class TestHypothesisHygiene:
    def test_internal_attributes_do_not_create_corroboration_hypotheses(
            self, store_factory, isolated_mock_registry):
        isolated_mock_registry(
            make_capability("mock_user_tool", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.8))
        store = store_factory()
        investigation = support.bootstrap(store)
        entity = support.entity(store, EntityType.USERNAME, "elv1ntsk",
                                metadata={"provenance": "USER_PROVIDED_SEED"})
        support.set_seeds(store, [entity.entity_id])
        internal = []
        for key, value in (("clue_field", "usernames"),
                           ("clue_source", "structured"),
                           ("provenance", "USER_PROVIDED_SEED"),
                           ("role", "seed")):
            support.claim(store, entity.entity_id, f"HAS_ATTRIBUTE:{key}",
                          object_literal=value, tools=("seed",))
            internal.extend(claim for claim in store.list_claims(support.DEFAULT_INV)
                            if claim.predicate == f"HAS_ATTRIBUTE:{key}")
        meaningful = support.claim(
            store, entity.entity_id, "REGISTERED_ON",
            object_id=support.entity(store, EntityType.SERVICE, "github").entity_id,
            tools=("sherlock",))
        graph = GraphView(store, support.DEFAULT_INV, [entity.entity_id])
        generator = HypothesisGenerator(store)
        generated = generator.generate(investigation, graph, {"mock_user_tool"})
        internal_ids = {claim.claim_id for claim in internal}
        questions = " ".join(h.question.lower() for h in generated)
        for label in ("clue_field", "clue_source", "provenance", "role"):
            assert label not in questions
        assert not any(h.target_claim_id in internal_ids for h in generated)
        # The meaningful single-source lead is still eligible for corroboration.
        assert all(hypothesis.hypothesis_type != HypothesisType.CORROBORATION
                   or hypothesis.target_claim_id not in internal_ids
                   for hypothesis in generated)


class TestSherlockSoft404:
    def test_known_soft404_sites_filtered(self):
        raw = ("[+] 7Cups: https://7cups.com/user/alice\n"
               "[+] F3.cool: https://f3.cool/alice\n"
               "[+] Houzz: https://www.houzz.com/user/alice\n"
               "[+] Envato Forum: https://forums.envato.com/u/alice\n"
               "[+] GitHub: https://github.com/alice\n")
        out = parse_sherlock(raw, "alice")
        services = {entity.value.lower() for entity in out.entities
                    if entity.type is EntityType.SERVICE}
        profiles = {entity.value.lower() for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert services == {"github"}
        assert profiles == {"https://github.com/alice"}
        assert len(out.relations) == 1


# ════════════════════════════════════════════════════════════════════════
# 5. Multi-part suffix + classification sanity (existing capability surface)
# ════════════════════════════════════════════════════════════════════════

def test_email_domain_is_domain_not_public_suffix(store_factory):
    from hub.erkg.ingestion import EvidenceIngestor
    from hub.tools.base import EntityCandidate, ParseOutput

    store = store_factory()
    support.bootstrap(store)
    artifact = support.artifact(store, "seed")
    EvidenceIngestor(store).ingest(
        support.DEFAULT_INV,
        ParseOutput(entities=[EntityCandidate(
            type=EntityType.EMAIL,
            value="elvin.s.tashkin.std@example.edu.az", confidence=0.9)]),
        artifact_id=artifact, tool_id="seed", accepted_types=[],
        timestamp=utc_now())
    domains = {entity.canonical_value for entity in store.list_entities(support.DEFAULT_INV)
               if entity.type is EntityType.DOMAIN}
    assert "example.edu.az" in domains
    assert "edu.az" not in domains
