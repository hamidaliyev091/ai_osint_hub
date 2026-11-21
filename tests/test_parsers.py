"""Fixture-driven tests for the v2 deterministic tool parsers (Phase 3b).

Every legacy deterministic parser is exercised with:
  1. a realistic fixture from ``tests/fixtures/parsers/<tool>_sample.txt``
     (expected entity types/values, evidence, and the key relations),
  2. empty stdout (must be an empty ParseOutput, never an exception),
  3. malformed/garbage stdout (must not raise).
No network access and no new dependencies.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from hub.models import EdgeType, EntityType
from hub.tools.base import PARSER_CONTRACT_VERSION, ParseOutput

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "parsers"

ALL_TOOLS = [
    "holehe", "maigret", "h8mail", "theharvester", "nmap", "amass", "hashcat",
    "hydra", "gobuster", "ghunt", "phoneinfoga", "sherlock", "snscrape", "whatweb",
]

#: CLI target used to drive the fixture for each tool.
TARGETS = {
    "holehe": "alice@example.com",
    "maigret": "alice",
    "h8mail": "alice@example.com",
    "theharvester": "example.com",
    "nmap": "192.0.2.10",
    "amass": "example.com",
    "hashcat": "5f4dcc3b5aa765d61d8327deb882cf99",
    "hydra": "ssh",
    "gobuster": "http://example.com",
    "ghunt": "alice@example.com",
    "phoneinfoga": "+14155552671",
    "sherlock": "alice",
    "snscrape": "alice",
    "whatweb": "example.com",
}

GARBAGE = (
    "\x1b[31mERROR\x1b[0m <<<>>> \x00\x01\n"
    "{not valid json\n"
    "<nmaprun\n"
    "[+] ???\n"
    "::::\n"
    "%%% garbage that is not tool output %%%\n"
)


def parser(tool: str):
    """Resolve ``hub.tools.parsers.<tool>:parse`` like the capability registry does."""
    module = importlib.import_module(f"hub.tools.parsers.{tool}")
    return module.parse


def fixture(tool: str) -> str:
    return (FIXTURES / f"{tool}_sample.txt").read_text(encoding="utf-8")


def parse_fixture(tool: str) -> ParseOutput:
    return parser(tool)(fixture(tool), target=TARGETS[tool])


def values(out: ParseOutput, entity_type: EntityType) -> set[str]:
    return {entity.value for entity in out.entities if entity.type is entity_type}


def entities_of(out: ParseOutput, entity_type: EntityType):
    return [entity for entity in out.entities if entity.type is entity_type]


def predicates(out: ParseOutput) -> set[EdgeType]:
    return {relation.predicate for relation in out.relations}


# ════════════════════════════════════════════════════════════════════════
# Parser-specific fixture tests
# ════════════════════════════════════════════════════════════════════════

class TestHolehe:
    def test_fixture_positive_registrations_only(self):
        out = parse_fixture("holehe")
        services = {entity.value: entity for entity in entities_of(out, EntityType.SERVICE)}
        assert {"github.com", "twitter.com", "instagram.com"} <= set(services)
        # Negative/error lines ([+], [-] etc.) are not evidence:
        assert "amazon.com" not in services
        assert "spotify.com" not in services
        # No global registered attribute on Service nodes (relationship-only).
        assert all("registered" not in entity.attributes
                   for entity in out.entities if entity.type is EntityType.SERVICE)
        registered = {
            (relation.subject_value, relation.object_value)
            for relation in out.relations
            if relation.predicate is EdgeType.REGISTERED_ON
        }
        assert registered == {
            ("alice@example.com", "github.com"),
            ("alice@example.com", "twitter.com"),
            ("alice@example.com", "instagram.com"),
        }
        assert all(entity.evidence for entity in out.entities)
        assert all(relation.evidence for relation in out.relations)

    def test_negative_and_error_lines_are_ignored(self):
        raw = ("[x] adobe.com\n[-] amazon.com\n[?] unknown\n"
               "[+] positive.example\n")
        out = parser("holehe")(raw, target="alice@example.com")
        services = {entity.value for entity in entities_of(out, EntityType.SERVICE)}
        assert services == {"positive.example"}
        assert len(out.relations) == 1

    def test_banner_credits_never_become_usernames(self):
        raw = ("Twitter : @palenath\n"
               "Github : https://github.com/megadose/holehe\n"
               "For BTC Donations : 1FHDM49QfZX6pJmhjLE5tB2K6CaTLMZpXZ\n"
               "[+] github.com\n"
               "Twitter : @palenath\n"
               "Github : https://github.com/megadose/holehe\n")
        out = parser("holehe")(raw, target="alice@example.com")
        usernames = values(out, EntityType.USERNAME)
        assert "megadose" not in usernames
        assert "palenath" not in usernames

    def test_username_hint_from_profile_url(self):
        raw = "[+] github.com\nprofile: https://github.com/alice42\n"
        out = parser("holehe")(raw, target="alice@example.com")
        assert "alice42" in values(out, EntityType.USERNAME)


class TestMaigret:
    def test_fixture_json_profiles(self):
        out = parse_fixture("maigret")
        profiles = values(out, EntityType.SOCIAL_PROFILE)
        assert "https://github.com/alice" in profiles
        assert "https://twitter.com/alice" in profiles
        assert "https://www.reddit.com" not in profiles  # not claimed
        relations = [r for r in out.relations if r.predicate is EdgeType.REGISTERED_ON]
        assert relations
        assert all(r.subject_value == "alice" for r in relations)
        assert all(r.object_type is EntityType.SOCIAL_PROFILE for r in relations)
        assert all(entity.evidence for entity in out.entities)

    def test_plain_text_fallback(self):
        raw = (
            "[+] GitHub: https://github.com/alice\n"
            "[+] Reddit: https://www.reddit.com/user/alice\n"
            "[-] Example: not found\n"
        )
        out = parser("maigret")(raw, target="alice")
        assert "https://github.com/alice" in values(out, EntityType.SOCIAL_PROFILE)
        assert all(r.predicate is EdgeType.REGISTERED_ON for r in out.relations)
        assert len(out.relations) == 2


class TestH8mail:
    def test_fixture_breach_exposure(self):
        out = parse_fixture("h8mail")
        breaches = {e.value: e for e in entities_of(out, EntityType.BREACH_RECORD)}
        assert {"linkedin (2012)", "adobe (2013)", "collection #1"} <= set(breaches)
        assert breaches["linkedin (2012)"].attributes["credentials_exposed"] is True
        exposed = {
            (r.subject_value, r.object_value)
            for r in out.relations
            if r.predicate is EdgeType.EXPOSED_IN
        }
        assert ("alice@example.com", "linkedin (2012)") in exposed
        mentioned = {
            (r.subject_value, r.object_value)
            for r in out.relations
            if r.predicate is EdgeType.MENTIONED_IN
        }
        assert ("bob@example.com", "adobe (2013)") in mentioned
        assert all(entity.evidence for entity in out.entities)


class TestTheHarvester:
    def test_fixture_entities_and_relations(self):
        out = parse_fixture("theharvester")
        assert {"alice@example.com", "bob@example.com"} <= values(out, EntityType.EMAIL)
        assert {"www.example.com", "mail.example.com", "vpn.example.com"} <= values(
            out, EntityType.SUBDOMAIN)
        assert {"93.184.216.34", "93.184.216.35"} <= values(out, EntityType.IP)
        assert "https://www.example.com/login" in values(out, EntityType.URL)
        assert {EdgeType.MENTIONED_IN, EdgeType.SUBDOMAIN_OF,
                EdgeType.RESOLVES_TO} <= predicates(out)
        resolve = next(r for r in out.relations
                       if r.predicate is EdgeType.RESOLVES_TO
                       and r.subject_value == "mail.example.com")
        assert resolve.object_value == "93.184.216.35"
        assert all(entity.evidence for entity in out.entities)

    def test_unsectioned_fallback(self):
        raw = "contact: alice@example.com\nportal: https://portal.example.com\n"
        out = parser("theharvester")(raw, target="example.com")
        assert "alice@example.com" in values(out, EntityType.EMAIL)
        assert any(r.predicate is EdgeType.MENTIONED_IN for r in out.relations)


class TestNmap:
    def test_fixture_xml_services(self):
        out = parse_fixture("nmap")
        assert "192.0.2.10" in values(out, EntityType.IP)
        assert {"ssh:22/tcp", "http:80/tcp"} <= values(out, EntityType.SERVICE)
        assert {"22/tcp", "80/tcp"} <= values(out, EntityType.PORT)
        assert "443/tcp" not in values(out, EntityType.PORT)  # filtered port
        ssh = next(e for e in out.entities
                   if e.type is EntityType.SERVICE and e.value == "ssh:22/tcp")
        assert ssh.attributes["port"] == 22
        assert ssh.attributes["protocol"] == "tcp"
        assert ssh.attributes["service_name"] == "ssh"
        associated = {
            (r.subject_value, r.object_value)
            for r in out.relations
            if r.predicate is EdgeType.ASSOCIATED_WITH
        }
        assert ("192.0.2.10", "ssh:22/tcp") in associated
        assert ("192.0.2.10", "22/tcp") in associated
        assert all(entity.evidence for entity in out.entities)

    def test_grepable_format(self):
        raw = (
            "# Nmap 7.94 scan initiated Mon Jan  1 00:00:00 2024 as: nmap -oG - -sV 192.0.2.10\n"
            "Host: 192.0.2.10 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/, "
            "80/open/tcp//http//nginx/\n"
            "# Nmap done at Mon Jan  1 00:00:10 2024 -- 1 IP address (1 host up) scanned\n"
        )
        out = parser("nmap")(raw, target="192.0.2.10")
        assert "192.0.2.10" in values(out, EntityType.IP)
        assert {"ssh:22/tcp", "http:80/tcp"} <= values(out, EntityType.SERVICE)
        assert len([r for r in out.relations
                    if r.predicate is EdgeType.ASSOCIATED_WITH]) == 4


class TestAmass:
    def test_fixture_subdomains_and_addresses(self):
        out = parse_fixture("amass")
        assert {"www.example.com", "mail.example.com", "vpn.example.com"} <= values(
            out, EntityType.SUBDOMAIN)
        assert {"93.184.216.34", "93.184.216.35"} <= values(out, EntityType.IP)
        subdomains = {
            (r.subject_value, r.object_value)
            for r in out.relations
            if r.predicate is EdgeType.SUBDOMAIN_OF
        }
        assert ("www.example.com", "example.com") in subdomains
        resolves = {
            (r.subject_value, r.object_value)
            for r in out.relations
            if r.predicate is EdgeType.RESOLVES_TO
        }
        assert ("mail.example.com", "93.184.216.35") in resolves
        assert all(entity.evidence for entity in out.entities)


class TestHashcat:
    def test_fixture_cracked_credentials(self):
        out = parse_fixture("hashcat")
        hashes = entities_of(out, EntityType.HASH)
        assert len(hashes) == 3
        assert {"password", "123456", "hunter2"} <= values(out, EntityType.CREDENTIAL)
        relations = [r for r in out.relations if r.predicate is EdgeType.ASSOCIATED_WITH]
        assert len(relations) == 3
        pair = next(r for r in relations if r.subject_value == "password")
        assert pair.object_value.startswith("5f4dcc3b")
        assert all(e.attributes["cracked"] is True
                   for e in entities_of(out, EntityType.CREDENTIAL))

    def test_status_output_is_ignored(self):
        raw = (
            "Session..........: hashcat\n"
            "Status...........: Cracked\n"
            "Hash.Mode........: 0 (MD5)\n"
            "Time.Started.....: Mon Jan 1 00:00:00 2024\n"
        )
        out = parser("hashcat")(raw, target="")
        assert out.is_empty
        assert out.warnings


class TestHydra:
    def test_fixture_credentials(self):
        out = parse_fixture("hydra")
        assert {"admin:s3cr3t", "root:toor"} <= values(out, EntityType.CREDENTIAL)
        assert "ssh:22/tcp" in values(out, EntityType.SERVICE)
        associations = [
            r for r in out.relations
            if r.predicate is EdgeType.ASSOCIATED_WITH
            and r.subject_value == "admin:s3cr3t"
        ]
        assert associations
        assert associations[0].object_value == "ssh:22/tcp"
        credential = next(e for e in out.entities
                          if e.type is EntityType.CREDENTIAL and e.value == "admin:s3cr3t")
        assert credential.attributes["username"] == "admin"
        assert credential.attributes["password"] == "s3cr3t"
        assert all(entity.evidence for entity in out.entities)


class TestGobuster:
    def test_fixture_urls(self):
        out = parse_fixture("gobuster")
        urls = values(out, EntityType.URL)
        assert {"http://example.com/admin", "http://example.com/login",
                "http://example.com/server-status"} <= urls
        login = next(e for e in out.entities
                     if e.type is EntityType.URL and e.value == "http://example.com/login")
        assert login.attributes["status_code"] == 200
        assert out.relations == []  # no relations are invented for gobuster
        assert all(entity.evidence for entity in out.entities)


class TestGhunt:
    def test_fixture_google_account(self):
        out = parse_fixture("ghunt")
        assert "google" in values(out, EntityType.SERVICE)
        profiles = values(out, EntityType.SOCIAL_PROFILE)
        assert "https://www.youtube.com/@aliceexample" in profiles
        assert not any("photo" in profile for profile in profiles)
        assert "aliceexample" in values(out, EntityType.USERNAME)
        registered = {
            (r.subject_value, r.object_value)
            for r in out.relations
            if r.predicate is EdgeType.REGISTERED_ON
        }
        assert ("alice@example.com", "google") in registered
        assert all(entity.evidence for entity in out.entities)


class TestPhoneinfoga:
    def test_fixture_carrier_and_location(self):
        out = parse_fixture("phoneinfoga")
        assert "+14155552671" in values(out, EntityType.PHONE)
        assert "AT&T Mobility" in values(out, EntityType.ORGANIZATION)
        assert "California, United States" in values(out, EntityType.LOCATION)
        carriers = [r for r in out.relations if r.predicate is EdgeType.REGISTERED_BY]
        locations = [r for r in out.relations if r.predicate is EdgeType.LOCATED_IN]
        assert any(r.object_value == "AT&T Mobility" for r in carriers)
        assert any(r.object_value == "California, United States" for r in locations)
        assert all(r.subject_value == "+14155552671" for r in out.relations)


class TestSherlock:
    def test_fixture_profiles(self):
        out = parse_fixture("sherlock")
        profiles = values(out, EntityType.SOCIAL_PROFILE)
        assert {"https://github.com/alice", "https://twitter.com/alice",
                "https://www.reddit.com/user/alice"} <= profiles
        assert "github" in values(out, EntityType.SERVICE)
        relations = [r for r in out.relations if r.predicate is EdgeType.REGISTERED_ON]
        assert len(relations) == 4
        assert all(r.subject_value == "alice" for r in relations)
        assert all(entity.evidence for entity in out.entities)


class TestSnscrape:
    def test_fixture_posts(self):
        out = parse_fixture("snscrape")
        urls = values(out, EntityType.URL)
        assert any("twitter.com/alice/status/" in url for url in urls)
        assert "alice" in values(out, EntityType.USERNAME)
        relations = [r for r in out.relations if r.predicate is EdgeType.ASSOCIATED_WITH]
        assert relations
        assert all(r.subject_value == "alice" for r in relations)
        assert any(r.object_type is EntityType.URL for r in relations)
        assert all(entity.evidence for entity in out.entities)


class TestWhatweb:
    def test_fixture_technologies(self):
        out = parse_fixture("whatweb")
        services = {entity.value: entity for entity in entities_of(out, EntityType.SERVICE)}
        assert {"nginx", "wordpress", "jquery", "php"} <= set(services)
        assert services["nginx"].attributes["version"] == "1.18.0"
        assert services["wordpress"].attributes["version"] == "6.2"
        assert "http://example.com" in values(out, EntityType.URL)
        associated = {
            (r.subject_type, r.subject_value, r.object_value)
            for r in out.relations
            if r.predicate is EdgeType.ASSOCIATED_WITH
        }
        assert (EntityType.DOMAIN, "example.com", "nginx") in associated
        assert all(relation.evidence for relation in out.relations)


# ════════════════════════════════════════════════════════════════════════
# Cross-parser contract tests
# ════════════════════════════════════════════════════════════════════════

class TestParserContract:
    @pytest.mark.parametrize("tool", ALL_TOOLS)
    def test_empty_stdout_returns_empty_output(self, tool):
        out = parser(tool)("", target=TARGETS[tool])
        assert isinstance(out, ParseOutput)
        assert out.is_empty
        assert out.warnings  # explains why nothing was produced
        assert out.parser_version == PARSER_CONTRACT_VERSION

    @pytest.mark.parametrize("tool", ALL_TOOLS)
    def test_garbage_stdout_never_raises(self, tool):
        out = parser(tool)(GARBAGE, target=TARGETS[tool])
        assert isinstance(out, ParseOutput)
        assert out.parser_version == PARSER_CONTRACT_VERSION

    def test_truncated_fixtures_never_raise(self):
        for tool in ALL_TOOLS:
            raw = fixture(tool)
            for cut in (len(raw) // 3, len(raw) // 2, max(0, len(raw) - 3)):
                out = parser(tool)(raw[:cut], target=TARGETS[tool])
                assert isinstance(out, ParseOutput), tool

    def test_parsers_are_deterministic(self):
        for tool in ALL_TOOLS:
            first = parse_fixture(tool).model_dump()
            second = parse_fixture(tool).model_dump()
            assert first == second, tool

    def test_fixtures_use_canonical_enums_confidence_and_evidence(self):
        for tool in ALL_TOOLS:
            out = parse_fixture(tool)
            assert not out.is_empty, tool  # every fixture must yield findings
            for entity in out.entities:
                assert isinstance(entity.type, EntityType), tool
                assert entity.value, tool
                assert 0.0 <= entity.confidence <= 1.0, tool
                assert entity.evidence, tool
            for relation in out.relations:
                assert isinstance(relation.predicate, EdgeType), tool
                assert isinstance(relation.subject_type, EntityType), tool
                assert isinstance(relation.object_type, EntityType), tool
                assert relation.subject_value and relation.object_value, tool
                assert 0.0 <= relation.confidence <= 1.0, tool
                assert relation.evidence, tool
