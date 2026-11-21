"""Phase 16 signal-hygiene tests — full-handle maigret, photon assets, empty attrs, IP pivots."""

from __future__ import annotations

import json

import pytest

from hub.erkg.graph import GraphView
from hub.erkg.ingestion import EvidenceIngestor
from hub.erkg.store import ERKGStore
from hub.investigation.hypotheses import HypothesisGenerator
from hub.investigation.pivot import PivotScorer
from hub.models import EntityType, ExecutionStatus
from hub.tools import capabilities
from hub.tools.builtin.photon_crawler import _extract_from_text
from hub.tools.cooldown import RATE_LIMIT_COOLDOWN_SEC
from hub.tools.parsers import photon_crawler as photon_parser
from hub.tools.parsers import virustotal_lookup as virustotal_parser
from hub.tools.parsers.maigret import parse as parse_maigret
from tests import support
from tests.mock_tools import make_capability


# ════════════════════════════════════════════════════════════════════════
# 1. Maigret full-handle matching
# ════════════════════════════════════════════════════════════════════════

class TestMaigretFullHandle:
    def test_dotted_target_never_matches_prefix_or_generic_pages(self):
        raw = (
            "[+] Calendly: https://calendly.com/108.elv1n\n"
            "[+] GitHub: https://github.com/108\n"
            "[+] Twitter: https://twitter.com/108\n"
            "[+] YouTube: https://www.youtube.com/about\n"
            "[+] Discord: https://discord.com\n"
        )
        out = parse_maigret(raw, target="108.elv1n")
        profiles = {entity.value for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert profiles == {"https://calendly.com/108.elv1n"}
        assert not any("youtube/about" in profile for profile in profiles)
        assert not any(profile.rstrip("/") == "https://discord.com"
                       for profile in profiles)

    def test_root_only_urls_are_rejected(self):
        payload = {"sites": {
            "Discord": {"status": {"is_claimed": True},
                        "url_user": "https://discord.com"},
            "YouTube": {"status": {"is_claimed": True},
                        "url_user": "https://www.youtube.com/about"},
        }}
        out = parse_maigret(json.dumps(payload), target="108.elv1n")
        assert not [entity for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE]

    def test_punctuation_equivalence_kept(self):
        out = parse_maigret(
            "[+] Calendly: https://calendly.com/108_elv1n\n",
            target="108.elv1n")
        profiles = {entity.value for entity in out.entities
                    if entity.type is EntityType.SOCIAL_PROFILE}
        assert profiles == {"https://calendly.com/108_elv1n"}


# ════════════════════════════════════════════════════════════════════════
# 2. Photon static assets, page cap and role mailboxes
# ════════════════════════════════════════════════════════════════════════

ASSET_HTML = """
<html><head>
<link rel="stylesheet" href="/static/bootstrap.min.css">
<script src="/static/jquery-3.5.1.min.js"></script>
</head><body>
<img src="/static/book-icon.svg"><img src="/static/favicon-16x16.png">
<img src="/static/1792671873.JPG"><img src="/static/favicon.ico">
<a href="https://code.jquery.com/jquery-3.5.1.min.js">cdn</a>
<a href="https://fonts.gstatic.com/s/foo.woff2">font</a>
<a href="https://example.edu.az/about">About</a>
<a href="https://example.edu.az/admissions">Admissions</a>
<a href="https://example.edu.az/contact">Contact</a>
<a href="mailto:info@example.edu.az">info</a>
</body></html>
"""


class TestPhotonSignal:
    def test_collector_filters_assets_and_caps_pages(self):
        urls: list[str] = []
        emails: list[str] = []
        subdomains: list[str] = []
        social: list[str] = []
        js: list[str] = []
        buckets: list[str] = []
        page_links = "".join(
            f'<a href="https://example.edu.az/page-{index}">p</a>'
            for index in range(30))
        html = ASSET_HTML + page_links
        _extract_from_text(html, "https://example.edu.az/", "example.edu.az",
                           urls, emails, subdomains, social, js, buckets)
        assert len(urls) <= 15
        lowered = " ".join(urls).lower()
        for suffix in (".svg", ".png", ".jpg", ".ico", ".css", ".js"):
            assert suffix not in lowered
        assert all("code.jquery.com" not in url for url in urls)
        assert all("fonts.gstatic.com" not in url for url in urls)
        assert "info@example.edu.az" in emails

    def test_parser_filters_assets_and_caps_url_entities(self):
        urls = [f"https://example.edu.az/page-{index}" for index in range(30)]
        urls += [
            "https://example.edu.az/static/book-icon.svg",
            "https://example.edu.az/static/bootstrap.min.css",
            "https://example.edu.az/static/app.js",
            "https://example.edu.az/static/favicon-16x16.png",
            "https://example.edu.az/static/1792671873.JPG",
            "https://code.jquery.com/jquery-3.5.1.min.js",
        ]
        payload = {
            "target": "example.edu.az", "base_host": "example.edu.az",
            "urls": urls, "emails": ["info@example.edu.az"],
            "subdomains": ["mail.example.edu.az"],
            "social_profiles": [], "js_endpoints": [
                "https://example.edu.az/static/app.js"],
            "buckets": [],
        }
        out = photon_parser.parse(json.dumps(payload), "example.edu.az")
        url_entities = [entity.value for entity in out.entities
                        if entity.type is EntityType.URL]
        assert len(url_entities) <= 15
        for url in url_entities:
            lowered = url.lower()
            assert not any(lowered.endswith(suffix)
                           for suffix in (".svg", ".png", ".jpg", ".ico",
                                          ".css", ".js"))
            assert "code.jquery.com" not in lowered
        assert any(entity.value == "info@example.edu.az"
                   for entity in out.entities
                   if entity.type is EntityType.EMAIL)


class TestRoleMailboxHypotheses:
    def test_info_mailbox_does_not_create_username(self, store_factory,
                                                   isolated_mock_registry):
        isolated_mock_registry(
            make_capability("mock_username", [EntityType.USERNAME],
                            [EntityType.SOCIAL_PROFILE]))
        store = store_factory()
        investigation = support.bootstrap(store)
        email = support.entity(store, EntityType.EMAIL, "info@example.edu.az",
                               metadata={"provenance": "USER_PROVIDED_SEED"})
        support.claim(store, email.entity_id, "IDENTIFIED_AS",
                      object_literal="info@example.edu.az", tools=("holehe",))
        support.set_seeds(store, [email.entity_id])
        graph = GraphView(store, support.DEFAULT_INV, [email.entity_id])
        generated = HypothesisGenerator(store).generate(
            investigation, graph, available_tool_ids=["mock_username"])
        assert store.get_entity_by_value(support.DEFAULT_INV,
                                         EntityType.USERNAME, "info") is None
        assert not any("info" in (hypothesis.question or "").lower()
                       for hypothesis in generated)


# ════════════════════════════════════════════════════════════════════════
# 3. Empty attributes
# ════════════════════════════════════════════════════════════════════════

VT_EMPTY_PAYLOAD = {
    "target": "example.com", "target_type": "domain",
    "domain": {"value": "example.com", "registrar": "",
               "as_owner": "", "asn": "", "country": "",
               "reputation": 0, "verdict": ""},
    "subdomains": [], "resolutions": [],
    "reputation": 0, "verdict": "",
}


class TestEmptyAttributes:
    def test_virustotal_parser_drops_empty_attributes(self):
        out = virustotal_parser.parse(json.dumps(VT_EMPTY_PAYLOAD),
                                      "example.com")
        for entity in out.entities:
            for key, value in (entity.attributes or {}).items():
                assert value != "" and value is not None, key

    def test_ingestor_never_creates_empty_attribute_claims(self, store_factory):
        from hub.tools.base import EntityCandidate, ParseOutput

        store = store_factory()
        support.bootstrap(store)
        artifact = support.artifact(store, "virustotal_lookup")
        parsed = ParseOutput(entities=[EntityCandidate(
            type=EntityType.DOMAIN, value="example.com", confidence=0.9,
            attributes={"as_owner": "", "asn": "", "country": "",
                        "registrar": " ", "reputation": 0, "keep": "ok"},
            evidence="VT record")])
        EvidenceIngestor(store).ingest(
            support.DEFAULT_INV, parsed, artifact_id=artifact,
            tool_id="virustotal_lookup", accepted_types=[], timestamp=support.utc_now())
        claims = store.list_claims(support.DEFAULT_INV)
        for claim in claims:
            if claim.predicate.startswith("HAS_ATTRIBUTE:"):
                assert claim.object_literal not in {"", None}
                assert not (isinstance(claim.object_literal, str)
                            and not claim.object_literal.strip())
        assert any(claim.predicate == "HAS_ATTRIBUTE:keep" for claim in claims)
        assert any(claim.predicate == "HAS_ATTRIBUTE:reputation" for claim in claims)


# ════════════════════════════════════════════════════════════════════════
# 4. Confirmed-IP infrastructure pivots + cooldown TTL
# ════════════════════════════════════════════════════════════════════════

class TestInfrastructurePivots:
    def test_resolved_ip_tools_rank_before_low_yield_tools(
            self, store_factory, isolated_mock_registry):
        isolated_mock_registry(
            make_capability("dns_lookup", [EntityType.DOMAIN],
                            [EntityType.IP], prior_yield=0.5),
            make_capability("virustotal_lookup", [EntityType.DOMAIN],
                            [EntityType.IP], prior_yield=0.7),
            make_capability("shodan_lookup", [EntityType.IP],
                            [EntityType.SERVICE], prior_yield=0.7),
            make_capability("censys_lookup", [EntityType.IP],
                            [EntityType.SERVICE], prior_yield=0.65),
            make_capability("rdap_lookup", [EntityType.DOMAIN],
                            [EntityType.ORGANIZATION], prior_yield=0.5),
            make_capability("http_headers", [EntityType.DOMAIN],
                            [EntityType.SERVICE], prior_yield=0.45),
            make_capability("darkweb_ahmia", [EntityType.USERNAME],
                            [EntityType.URL], prior_yield=0.4),
            make_capability("pgp_keyserver", [EntityType.USERNAME],
                            [EntityType.EMAIL], prior_yield=0.4),
            make_capability("github_osint", [EntityType.EMAIL],
                            [EntityType.SOCIAL_PROFILE], prior_yield=0.5),
        )
        store = store_factory()
        support.bootstrap(store)
        domain = support.entity(store, EntityType.DOMAIN, "example.edu.az",
                                metadata={"provenance": "EMAIL_DERIVED_DOMAIN"})
        ip = support.entity(store, EntityType.IP, "85.132.26.114")
        username = support.entity(store, EntityType.USERNAME, "108.elv1n",
                                  metadata={"provenance": "USER_PROVIDED_SEED"})
        email = support.entity(store, EntityType.EMAIL, "info@example.edu.az",
                               metadata={"provenance": "USER_PROVIDED_SEED"})
        seeds = [domain.entity_id, username.entity_id, email.entity_id]
        support.set_seeds(store, seeds)
        claim = support.claim(
            store, domain.entity_id, "RESOLVES_TO", object_id=ip.entity_id,
            tools=("dns_lookup", "virustotal_lookup"))
        assert claim.status.value in {"CONFIRMED", "CORROBORATED"}
        graph = GraphView(store, support.DEFAULT_INV, seeds)
        ranking = PivotScorer(min_threshold=0.0).rank(
            graph, [], allowed_tool_ids={
                "dns_lookup", "virustotal_lookup", "shodan_lookup",
                "censys_lookup", "rdap_lookup", "http_headers",
                "darkweb_ahmia", "pgp_keyserver", "github_osint"})
        positions = {candidate.tool_id: index
                     for index, candidate in enumerate(ranking.all_candidates)
                     if candidate.entity_id == ip.entity_id
                     or candidate.entity_id == username.entity_id}
        assert positions["shodan_lookup"] < positions["darkweb_ahmia"]
        assert positions["shodan_lookup"] < positions["pgp_keyserver"]
        assert positions["censys_lookup"] < positions["darkweb_ahmia"]
        assert positions["censys_lookup"] < positions["pgp_keyserver"]


def test_rate_limit_cooldown_is_24_hours():
    assert RATE_LIMIT_COOLDOWN_SEC == 24 * 60 * 60
