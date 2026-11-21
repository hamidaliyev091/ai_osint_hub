"""Deterministic, network-free tests for the 7 native passive collectors (v2).

Every HTTP call is intercepted with ``httpx.MockTransport`` injected by
monkeypatching ``httpx.AsyncClient`` -> the collectors run unchanged against
canned responses. Where a collector performs DNS/SSRF resolution (photon), the
resolver is replaced with a deterministic fake. No test touches the network:
the whole module runs in well under the 10 s budget.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json

import httpx
import pytest

from hub.models import EdgeType, EntityType, ErrorCode, ExecutionMode, ScopeConfig
from hub.tools import capabilities
from hub.tools.base import ParseOutput
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin import (
    darkweb_ahmia,
    github_osint,
    gravatar_lookup,
    pgp_keyserver,
    photon_crawler,
    rdap_lookup,
    wayback_cdx,
)
from hub.tools.parsers import darkweb_ahmia as ahmia_parser
from hub.tools.parsers import github_osint as github_parser
from hub.tools.parsers import gravatar_lookup as gravatar_parser
from hub.tools.parsers import pgp_keyserver as pgp_parser
from hub.tools.parsers import photon_crawler as photon_parser
from hub.tools.parsers import rdap_lookup as rdap_parser
from hub.tools.parsers import wayback_cdx as wayback_parser

NATIVE_TOOL_IDS = [
    "photon_crawler",
    "github_osint",
    "gravatar_lookup",
    "pgp_keyserver",
    "rdap_lookup",
    "wayback_cdx",
    "darkweb_ahmia",
]
ALL_COLLECTORS = [
    photon_crawler,
    github_osint,
    gravatar_lookup,
    pgp_keyserver,
    rdap_lookup,
    wayback_cdx,
    darkweb_ahmia,
]
ALL_PARSERS = [
    photon_parser,
    github_parser,
    gravatar_parser,
    pgp_parser,
    rdap_parser,
    wayback_parser,
    ahmia_parser,
]


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════

def _collect(module, params, timeout_sec=5):
    """Drive an async collector with asyncio.run (pytest-asyncio is absent)."""
    return asyncio.run(module.collect(params, timeout_sec=timeout_sec,
                                      scope=ScopeConfig()))


def _response(payload, status=200, content_type="application/json"):
    return httpx.Response(status,
                          content=json.dumps(payload).encode("utf-8"),
                          headers={"content-type": content_type})


def _text(body, status=200, content_type="text/html"):
    return httpx.Response(status, content=body.encode("utf-8"),
                          headers={"content-type": content_type})


def _install_transport(monkeypatch, handler):
    """Patch httpx.AsyncClient so every collector client uses a mock transport."""
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


async def _forbidden(request):  # pragma: no cover - only fails tests if called
    raise AssertionError(f"unexpected HTTP request to {request.url}")


_BLOCKED_HOSTS = {"127.0.0.1", "localhost", "::1", "169.254.169.254"}


def _allow_safe_hosts(monkeypatch):
    """Patch the photon module's SSRF resolver so tests stay DNS-free."""
    def _safe(host):
        if host in _BLOCKED_HOSTS:
            return False, f"host {host} resolves to non-public address"
        return True, f"host {host} resolves to public address"

    monkeypatch.setattr(photon_crawler, "assert_safe_host", _safe)


# ════════════════════════════════════════════════════════════════════════
# photon_crawler
# ════════════════════════════════════════════════════════════════════════

PHOTON_ROOT_HTML = """<!doctype html><html><head>
<script src="/static/app.js"></script>
<script src=/inline/app.js></script>
<script src="https://cdn.example.com/vendor/lib.js"></script>
</head><body>
<a href="https://example.com/about">About</a>
<a href="/contact?x=1">Contact</a>
<a href="https://twitter.com/examplehq">Twitter</a>
<a href="https://github.com/examplehq">GitHub</a>
<a href="https://cdn.example.com/assets/main.js">JS file</a>
<a href="https://storage.googleapis.com/example-bucket/data.json">GCS</a>
<a href="https://example-bucket.s3.amazonaws.com/file.csv">S3</a>
<a href="mailto:hello@example.com">Mail</a>
<p>Reach admin@example.com for details.</p>
</body></html>"""

PHOTON_ROBOTS_TXT = (
    "User-agent: *\nDisallow: /admin\n"
    "Sitemap: https://example.com/sitemap.xml\n"
    "Contact: security@example.com\n"
)

PHOTON_SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page-one</loc></url>
  <url><loc>https://blog.example.com/post-one</loc></url>
  <url><loc>https://example.com/hidden.php?q=1</loc></url>
</urlset>"""


async def _photon_handler(request):
    host = request.url.host
    path = request.url.path
    if host == "example.com" and path == "/":
        return _text(PHOTON_ROOT_HTML)
    if host == "example.com" and path == "/robots.txt":
        return _text(PHOTON_ROBOTS_TXT, content_type="text/plain")
    if host == "example.com" and path == "/sitemap.xml":
        return _text(PHOTON_SITEMAP_XML, content_type="application/xml")
    return _text("not found", status=404, content_type="text/plain")


async def _photon_redirect_handler(request):
    if request.url.scheme == "http":
        return httpx.Response(301, headers={"location": "https://example.com/"})
    return await _photon_handler(request)


async def _photon_private_redirect_handler(request):
    if request.url.path == "/":
        return httpx.Response(302, headers={"location": "http://127.0.0.1/secret"})
    return _text("should never be fetched")


async def _photon_partial_handler(request):
    if request.url.path == "/sitemap.xml":
        return _text(PHOTON_SITEMAP_XML, content_type="application/xml")
    return _text("not found", status=404, content_type="text/plain")


def test_photon_collector_extracts_artefacts(monkeypatch):
    _allow_safe_hosts(monkeypatch)
    _install_transport(monkeypatch, _photon_handler)

    result = _collect(photon_crawler, {"target": "example.com"})

    assert isinstance(result, BuiltinOutput)
    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["target"] == "example.com"
    assert payload["base_host"] == "example.com"
    assert "https://example.com/" in payload["urls"]
    assert "https://example.com/about" in payload["urls"]
    assert "https://example.com/contact?x=1" in payload["urls"]
    assert "https://example.com/page-one" in payload["urls"]
    assert "https://blog.example.com/post-one" in payload["urls"]
    assert {"hello@example.com", "admin@example.com",
            "security@example.com"} <= set(payload["emails"])
    assert {"blog.example.com", "cdn.example.com"} <= set(payload["subdomains"])
    assert "https://twitter.com/examplehq" in payload["social_profiles"]
    assert "https://github.com/examplehq" in payload["social_profiles"]
    assert "https://cdn.example.com/assets/main.js" in payload["js_endpoints"]
    assert "https://example.com/static/app.js" in payload["js_endpoints"]
    assert "https://example.com/inline/app.js" in payload["js_endpoints"]
    buckets = payload["buckets"]
    assert any("storage.googleapis.com" in url for url in buckets)
    assert any("s3.amazonaws.com" in url for url in buckets)
    evidence = payload["evidence"]
    assert evidence["final_url"] == "https://example.com/"
    assert len(evidence["pages"]) == 3
    assert [page["status"] for page in evidence["pages"]] == [200, 200, 200]
    assert len(payload["urls"]) <= 100

    parsed = photon_parser.parse(result.stdout, "example.com")
    kinds = {entity.type.value for entity in parsed.entities}
    assert {"url", "email", "subdomain", "social_profile", "service"} <= kinds
    email_values = {entity.value for entity in parsed.entities
                    if entity.type is EntityType.EMAIL}
    assert {"hello@example.com", "admin@example.com"} <= email_values
    subdomain_values = {entity.value for entity in parsed.entities
                        if entity.type is EntityType.SUBDOMAIN}
    assert "blog.example.com" in subdomain_values
    assert any(relation.predicate is EdgeType.MENTIONED_IN
               and relation.subject_type is EntityType.EMAIL
               for relation in parsed.relations)
    assert any(relation.predicate is EdgeType.SUBDOMAIN_OF
               for relation in parsed.relations)
    assert all(entity.evidence for entity in parsed.entities)


def test_photon_collector_follows_redirects_safely(monkeypatch):
    _allow_safe_hosts(monkeypatch)
    _install_transport(monkeypatch, _photon_redirect_handler)

    result = _collect(photon_crawler, {"target": "http://example.com/"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["evidence"]["final_url"] == "https://example.com/"
    assert "https://example.com/" in payload["evidence"]["redirect_chain"]
    assert "https://example.com/about" in payload["urls"]


def test_photon_collector_blocks_non_public_target(monkeypatch):
    _install_transport(monkeypatch, _forbidden)

    result = _collect(photon_crawler, {"target": "http://127.0.0.1/"})

    assert result.error_code == ErrorCode.SCOPE_BLOCKED
    assert result.exit_code == -1
    assert "non-public" in (result.error_message + result.stderr)


def test_photon_collector_blocks_redirect_to_private_host(monkeypatch):
    _allow_safe_hosts(monkeypatch)
    _install_transport(monkeypatch, _photon_private_redirect_handler)

    result = _collect(photon_crawler, {"target": "example.com"})

    assert result.error_code == ErrorCode.SCOPE_BLOCKED
    assert result.exit_code == -1


def test_photon_collector_returns_partial_result_on_404(monkeypatch):
    _allow_safe_hosts(monkeypatch)
    _install_transport(monkeypatch, _photon_partial_handler)

    result = _collect(photon_crawler, {"target": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["evidence"]["pages"][0]["status"] == 404
    assert "https://example.com/page-one" in payload["urls"]


def test_photon_parser_never_raises():
    for raw in ["", "   ", "not json", "[]", "{broken", json.dumps({"unknown": 1})]:
        parsed = photon_parser.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings


# ════════════════════════════════════════════════════════════════════════
# github_osint
# ════════════════════════════════════════════════════════════════════════

GITHUB_USER = {
    "login": "octocat",
    "name": "The Octocat",
    "company": "@github",
    "location": "San Francisco",
    "blog": "https://github.blog/",
    "bio": "Builds things",
    "html_url": "https://github.com/octocat",
    "avatar_url": "https://avatars.githubusercontent.com/u/583231",
    "public_repos": 8,
}
GITHUB_REPOS = [
    {
        "full_name": "octocat/hello-world",
        "html_url": "https://github.com/octocat/hello-world",
        "language": "Ruby",
        "description": "My first repo",
        "fork": False,
    }
]
GITHUB_EVENTS = [
    {
        "type": "PushEvent",
        "payload": {
            "commits": [
                {"author": {"email": "octocat@github.com", "name": "The Octocat"}},
                {"author": {"email": "octocat@github.com", "name": "The Octocat"}},
            ]
        },
    }
]
GITHUB_SEARCH = {
    "total_count": 1,
    "items": [{"login": "octocat",
               "html_url": "https://github.com/octocat",
               "avatar_url": "https://avatars.githubusercontent.com/u/583231"}],
}


async def _github_handler(request):
    path = request.url.path
    if path == "/users/octocat":
        return _response(GITHUB_USER)
    if path == "/users/octocat/repos":
        return _response(GITHUB_REPOS)
    if path == "/users/octocat/events/public":
        return _response(GITHUB_EVENTS)
    if path == "/search/users":
        assert "in:email" in request.url.params.get("q", "")
        return _response(GITHUB_SEARCH)
    return _response({"message": "Not Found"}, status=404)


async def _github_rate_limited_handler(request):
    return _response({"message": "API rate limit exceeded"}, status=403)


def test_github_collector_username(monkeypatch):
    _install_transport(monkeypatch, _github_handler)

    result = _collect(github_osint, {"username": "octocat"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["query"] == {"username": "octocat", "email": ""}
    user = payload["user"]
    assert user["login"] == "octocat"
    assert user["name"] == "The Octocat"
    assert user["company"] == "@github"
    assert user["location"] == "San Francisco"
    assert user["public_repos"] == 8
    assert payload["repos"][0]["full_name"] == "octocat/hello-world"
    assert payload["emails"] == [
        {"email": "octocat@github.com", "source": "github:events_commits"}
    ]

    parsed = github_parser.parse(result.stdout, "octocat")
    person = next(entity for entity in parsed.entities
                  if entity.type is EntityType.PERSON)
    assert person.value == "The Octocat"
    assert "octocat" in person.aliases
    assert person.attributes["login"] == "octocat"
    organizations = {entity.value for entity in parsed.entities
                     if entity.type is EntityType.ORGANIZATION}
    assert "github" in organizations
    locations = {entity.value for entity in parsed.entities
                 if entity.type is EntityType.LOCATION}
    assert "San Francisco" in locations
    repositories = {entity.value for entity in parsed.entities
                    if entity.type is EntityType.REPOSITORY}
    assert "octocat/hello-world" in repositories
    emails = {entity.value for entity in parsed.entities
              if entity.type is EntityType.EMAIL}
    assert "octocat@github.com" in emails
    predicates = {relation.predicate for relation in parsed.relations}
    assert EdgeType.OWNS in predicates
    assert EdgeType.HAS_EMAIL in predicates
    assert EdgeType.HAS_USERNAME in predicates
    assert EdgeType.LOCATED_IN in predicates
    assert any(relation.predicate is EdgeType.OWNS
               and relation.subject_value == "The Octocat"
               and relation.object_value == "octocat/hello-world"
               for relation in parsed.relations)
    assert all(entity.evidence for entity in parsed.entities)


def test_github_collector_email_search(monkeypatch):
    _install_transport(monkeypatch, _github_handler)

    result = _collect(github_osint, {"email": "octocat@github.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["query"]["email"] == "octocat@github.com"
    assert [user["login"] for user in payload["users"]] == ["octocat"]
    assert payload["user"]["login"] == "octocat"

    parsed = github_parser.parse(result.stdout, "octocat@github.com")
    queried_emails = {entity.value for entity in parsed.entities
                      if entity.type is EntityType.EMAIL}
    assert "octocat@github.com" in queried_emails
    assert any(relation.predicate is EdgeType.HAS_EMAIL
               and relation.object_value == "octocat@github.com"
               for relation in parsed.relations)


def test_github_collector_rate_limited(monkeypatch):
    _install_transport(monkeypatch, _github_rate_limited_handler)

    result = _collect(github_osint, {"username": "octocat"})

    assert result.error_code == ErrorCode.RATE_LIMITED
    assert result.exit_code == 1
    assert "rate limit" in result.error_message.lower()


def test_github_collector_unknown_user_is_empty_result(monkeypatch):
    async def _not_found_handler(request):
        return _response({"message": "Not Found"}, status=404)

    _install_transport(monkeypatch, _not_found_handler)
    result = _collect(github_osint, {"username": "does-not-exist-xyz"})

    assert result.exit_code == 0 and result.error_code is None
    # Phase 12: a nonexistent username is a clean EMPTY result, never an error
    # and never a stderr traceback masquerading as a profile payload.
    assert result.stdout == ""
    assert "not found" in result.stderr.lower()


def test_github_parser_never_raises():
    for raw in ["", "not json", "[]", "{broken", json.dumps({"query": {}})]:
        parsed = github_parser.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings


# ════════════════════════════════════════════════════════════════════════
# gravatar_lookup
# ════════════════════════════════════════════════════════════════════════

GRAVATAR_EMAIL = "matt@mullenweg.com"
GRAVATAR_MD5 = hashlib.md5(GRAVATAR_EMAIL.encode("utf-8")).hexdigest()
GRAVATAR_SHA256 = hashlib.sha256(GRAVATAR_EMAIL.encode("utf-8")).hexdigest()
GRAVATAR_PROFILE = {
    "entry": [{
        "hash": GRAVATAR_MD5,
        "requestHash": GRAVATAR_MD5,
        "profileUrl": "https://gravatar.com/matt230816",
        "preferredUsername": "matt230816",
        "thumbnailUrl": f"https://1.gravatar.com/avatar/{GRAVATAR_MD5}",
        "displayName": "Matt Mullenweg",
        "aboutMe": "Founder of WordPress.",
        "name": {"formatted": "Matt Mullenweg"},
        "accounts": [{
            "shortname": "twitter",
            "username": "photomatt",
            "url": "https://twitter.com/photomatt",
            "verified": "true",
        }],
    }]
}


async def _gravatar_handler(request):
    if request.url.host == "gravatar.com":
        assert request.url.path == f"/{GRAVATAR_MD5}.json"
        return _response(GRAVATAR_PROFILE)
    return _text("not found", status=404, content_type="text/plain")


async def _gravatar_missing_handler(request):
    if request.url.host == "gravatar.com":
        return _response("User not found", status=404)
    return _text("404 Not Found", status=404, content_type="text/plain")


async def _gravatar_rate_limited_handler(request):
    return _response({"message": "too many requests"}, status=429)


def test_gravatar_collector_existing_profile(monkeypatch):
    _install_transport(monkeypatch, _gravatar_handler)

    result = _collect(gravatar_lookup, {"email": "Matt@Mullenweg.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["email"] == "Matt@Mullenweg.com"
    assert payload["md5"] == GRAVATAR_MD5  # normalised lowercase hash
    assert payload["sha256"] == GRAVATAR_SHA256
    assert payload["exists"] is True
    profile = payload["profile"]
    assert profile["displayName"] == "Matt Mullenweg"
    assert profile["preferredUsername"] == "matt230816"
    assert profile["profileUrl"] == "https://gravatar.com/matt230816"
    assert profile["accounts"][0]["verified"] is True

    parsed = gravatar_parser.parse(result.stdout, "matt@mullenweg.com")
    kinds = {entity.type.value for entity in parsed.entities}
    assert {"email", "person", "username", "social_profile", "service"} <= kinds
    assert any(relation.predicate is EdgeType.REGISTERED_ON
               and relation.subject_type is EntityType.EMAIL
               and relation.object_value == "gravatar"
               for relation in parsed.relations)
    assert any(relation.predicate is EdgeType.HAS_USERNAME
               and relation.subject_type is EntityType.SOCIAL_PROFILE
               and relation.object_value == "matt230816"
               for relation in parsed.relations)
    assert all(entity.evidence for entity in parsed.entities)


def test_gravatar_collector_missing_profile_is_valid_empty_result(monkeypatch):
    _install_transport(monkeypatch, _gravatar_missing_handler)

    result = _collect(gravatar_lookup, {"email": "nobody@example.org"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["exists"] is False
    assert payload["profile"]["displayName"] == ""
    assert payload["profile"]["accounts"] == []

    parsed = gravatar_parser.parse(result.stdout, "nobody@example.org")
    assert any(entity.type is EntityType.EMAIL for entity in parsed.entities)
    assert any("no Gravatar profile" in warning for warning in parsed.warnings)


def test_gravatar_collector_rate_limited(monkeypatch):
    _install_transport(monkeypatch, _gravatar_rate_limited_handler)

    result = _collect(gravatar_lookup, {"email": "someone@example.com"})

    assert result.error_code == ErrorCode.RATE_LIMITED
    assert result.exit_code == 1


def test_gravatar_parser_never_raises():
    for raw in ["", "garbage", "[]", "{broken", json.dumps({"exists": False})]:
        parsed = gravatar_parser.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings


# ════════════════════════════════════════════════════════════════════════
# pgp_keyserver
# ════════════════════════════════════════════════════════════════════════

PGP_MR = "\n".join([
    "info:1:2",
    "pub:93D2B8CD2E9A6D9B:1:4096:1700000000::",
    "uid:John Doe <john@example.com>:1700000001::",
    "uid:Johnny <johnny@example.org>:1700000002::",
    "pub:1122334455667788:1:2048:1600000000::",
])


async def _pgp_primary_handler(request):
    if request.url.host == "keys.openpgp.org":
        return _text(PGP_MR, content_type="text/plain")
    return _text("No key found", status=404, content_type="text/plain")


async def _pgp_fallback_handler(request):
    if request.url.host == "keys.openpgp.org":
        return _text("No key found for email address", status=404,
                     content_type="text/plain")
    if request.url.host == "keyserver.ubuntu.com":
        return _text(PGP_MR, content_type="text/plain")
    return _text("not found", status=404, content_type="text/plain")


async def _pgp_empty_handler(request):
    return _text("No key found", status=404, content_type="text/plain")


def test_pgp_collector_primary_keyserver(monkeypatch):
    _install_transport(monkeypatch, _pgp_primary_handler)

    result = _collect(pgp_keyserver, {"email": "john@example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["source"] == "keys.openpgp.org"
    assert payload["query"]["email"] == "john@example.com"
    assert len(payload["pub"]) == 2
    assert payload["pub"][0]["key_id"] == "93D2B8CD2E9A6D9B"
    assert payload["pub"][0]["bits"] == 4096
    assert [uid["email"] for uid in payload["uids"]] == [
        "john@example.com", "johnny@example.org"]
    assert [uid["name"] for uid in payload["uids"]] == ["John Doe", "Johnny"]
    assert payload["evidence"]["fallback_used"] is False

    parsed = pgp_parser.parse(result.stdout, "john@example.com")
    persons = {entity.value for entity in parsed.entities
               if entity.type is EntityType.PERSON}
    assert {"John Doe", "Johnny"} <= persons
    emails = {entity.value for entity in parsed.entities
              if entity.type is EntityType.EMAIL}
    assert {"john@example.com", "johnny@example.org"} <= emails
    has_email = [relation for relation in parsed.relations
                 if relation.predicate is EdgeType.HAS_EMAIL]
    assert {relation.subject_value for relation in has_email} >= {"John Doe"}
    assert all(entity.evidence for entity in parsed.entities)
    person = next(entity for entity in parsed.entities
                  if entity.type is EntityType.PERSON and entity.value == "John Doe")
    assert person.attributes["pgp_key_ids"][0] == "93D2B8CD2E9A6D9B"


def test_pgp_collector_fallback_keyserver(monkeypatch):
    _install_transport(monkeypatch, _pgp_fallback_handler)

    result = _collect(pgp_keyserver, {"username": "john doe"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["source"] == "keyserver.ubuntu.com"
    assert payload["query"]["username"] == "john doe"
    assert payload["evidence"]["fallback_used"] is True
    assert len(payload["uids"]) == 2


def test_pgp_collector_no_key_is_valid_empty_result(monkeypatch):
    _install_transport(monkeypatch, _pgp_empty_handler)

    result = _collect(pgp_keyserver, {"email": "nokey@example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["pub"] == [] and payload["uids"] == []
    assert payload["source"] == ""

    parsed = pgp_parser.parse(result.stdout, "nokey@example.com")
    assert parsed.is_empty
    assert parsed.warnings


def test_pgp_collector_network_error(monkeypatch):
    async def _failing_handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    _install_transport(monkeypatch, _failing_handler)
    result = _collect(pgp_keyserver, {"email": "john@example.com"})

    assert result.error_code == ErrorCode.SPAWN_ERROR
    assert result.exit_code == 1


def test_pgp_parser_never_raises():
    for raw in ["", "garbage", "[]", "{broken", json.dumps({"pub": []})]:
        parsed = pgp_parser.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings


# ════════════════════════════════════════════════════════════════════════
# rdap_lookup
# ════════════════════════════════════════════════════════════════════════

RDAP_DOMAIN = {
    "objectClassName": "domain",
    "handle": "2336799_DOMAIN_COM-VRSN",
    "ldhName": "EXAMPLE.COM",
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:38Z"},
    ],
    "nameservers": [
        {"ldhName": "A.IANA-SERVERS.NET"},
        {"ldhName": "B.IANA-SERVERS.NET"},
    ],
    "entities": [{
        "handle": "376",
        "roles": ["registrar"],
        "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"],
            ["org", {}, "text", ["RESERVED-Internet Assigned Numbers Authority"]],
            ["email", {}, "text", "abuse@example.net"],
        ]],
        "entities": [{
            "roles": ["abuse"],
            "vcardArray": ["vcard", [
                ["fn", {}, "text", "Abuse Desk"],
                ["email", {}, "text", "abuse-desk@example.net"],
            ]],
        }],
    }],
}


async def _rdap_handler(request):
    if request.url.path == "/domain/example.com":
        return _response(RDAP_DOMAIN)
    return _response({"errorCode": 404, "title": "No RDAP service"}, status=404)


def test_rdap_collector_domain(monkeypatch):
    _install_transport(monkeypatch, _rdap_handler)

    result = _collect(rdap_lookup, {"target": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["target"] == "example.com"
    assert payload["kind"] == "domain"
    assert payload["handle"] == "2336799_DOMAIN_COM-VRSN"
    assert payload["ldth"] == "example.com"
    assert payload["found"] is True
    actions = [event["action"] for event in payload["events"]]
    assert actions == ["registration", "expiration", "changed"]
    assert payload["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    registrar = payload["entities"][0]
    assert registrar["roles"] == ["registrar"]
    assert registrar["org"] == "RESERVED-Internet Assigned Numbers Authority"
    assert registrar["emails"] == ["abuse@example.net"]
    nested = payload["entities"][1]
    assert nested["roles"] == ["abuse"]
    assert nested["emails"] == ["abuse-desk@example.net"]

    parsed = rdap_parser.parse(result.stdout, "example.com")
    domain = next(entity for entity in parsed.entities
                  if entity.type is EntityType.DOMAIN)
    assert domain.value == "example.com"
    assert domain.attributes["registration"] == "1995-08-14T04:00:00Z"
    assert domain.attributes["expiration"] == "2026-08-13T04:00:00Z"
    assert domain.attributes["handle"] == "2336799_DOMAIN_COM-VRSN"
    organizations = {entity.value for entity in parsed.entities
                     if entity.type is EntityType.ORGANIZATION}
    assert "RESERVED-Internet Assigned Numbers Authority" in organizations
    emails = {entity.value for entity in parsed.entities
              if entity.type is EntityType.EMAIL}
    assert {"abuse@example.net", "abuse-desk@example.net"} <= emails
    predicates = {relation.predicate for relation in parsed.relations}
    assert EdgeType.REGISTERED_BY in predicates
    assert EdgeType.HAS_EMAIL in predicates
    assert EdgeType.ASSOCIATED_WITH in predicates
    subdomains = {entity.value for entity in parsed.entities
                  if entity.type is EntityType.SUBDOMAIN}
    assert {"a.iana-servers.net", "b.iana-servers.net"} <= subdomains
    assert all(entity.evidence for entity in parsed.entities)


def test_rdap_collector_404_is_empty_result(monkeypatch):
    _install_transport(monkeypatch, _rdap_handler)

    result = _collect(rdap_lookup, {"target": "no-such-domain-9x7y.example"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["found"] is False
    assert payload["entities"] == []
    assert payload["nameservers"] == []

    parsed = rdap_parser.parse(result.stdout, "no-such-domain-9x7y.example")
    assert any("no RDAP registration record" in warning
               for warning in parsed.warnings)


def test_rdap_collector_rejects_invalid_target(monkeypatch):
    _install_transport(monkeypatch, _forbidden)

    result = _collect(rdap_lookup, {"target": "not a domain!!"})

    assert result.exit_code == 2
    assert result.error_code is None


def test_rdap_parser_never_raises():
    for raw in ["", "garbage", "[]", "{broken", json.dumps({"found": False})]:
        parsed = rdap_parser.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings


# ════════════════════════════════════════════════════════════════════════
# wayback_cdx
# ════════════════════════════════════════════════════════════════════════

WAYBACK_ROWS = [
    ["original", "timestamp", "statuscode", "mimetype"],
    ["http://example.com/", "19980818030244", "200", "text/html"],
    ["http://blog.example.com/post-one", "20100101000000", "200", "text/html"],
    ["http://example.com/about", "20150101000000", "200", "text/html"],
]


def _wayback_handler_factory(seen_params):
    async def handler(request):
        assert request.url.host == "web.archive.org"
        seen_params.append(dict(request.url.params))
        return _response(WAYBACK_ROWS)
    return handler


def test_wayback_collector_rows_and_subdomains(monkeypatch):
    seen: list[dict] = []
    _install_transport(monkeypatch, _wayback_handler_factory(seen))

    result = _collect(wayback_cdx, {"target": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["target"] == "example.com"
    assert payload["query"]["url_param"] == "example.com/*"
    assert [row["url"] for row in payload["rows"]] == [
        "http://example.com/",
        "http://blog.example.com/post-one",
        "http://example.com/about",
    ]
    assert payload["rows"][0]["timestamp"] == "19980818030244"
    assert payload["rows"][0]["status"] == "200"
    assert payload["subdomains"] == ["blog.example.com"]
    # CDX request contract: json output, collapsed, 200-filtered, bounded.
    request_params = seen[0]
    assert request_params["output"] == "json"
    assert request_params["collapse"] == "urlkey"
    assert request_params["limit"] == "100"
    assert request_params["filter"] == "statuscode:200"
    assert "original" in request_params["fl"]

    parsed = wayback_parser.parse(result.stdout, "example.com")
    urls = {entity.value for entity in parsed.entities
            if entity.type is EntityType.URL}
    assert "http://example.com/about" in urls
    subdomains = {entity.value for entity in parsed.entities
                  if entity.type is EntityType.SUBDOMAIN}
    assert subdomains == {"blog.example.com"}
    assert any(relation.predicate is EdgeType.SUBDOMAIN_OF
               and relation.subject_value == "blog.example.com"
               and relation.object_value == "example.com"
               for relation in parsed.relations)
    assert all(entity.evidence for entity in parsed.entities)


def test_wayback_collector_url_target_uses_url_as_given(monkeypatch):
    seen: list[dict] = []
    _install_transport(monkeypatch, _wayback_handler_factory(seen))

    result = _collect(wayback_cdx, {"target": "https://example.com/page"})

    assert result.exit_code == 0
    assert seen[0]["url"] == "https://example.com/page"


def test_wayback_collector_rate_limited(monkeypatch):
    def handler_factory():
        async def handler(request):
            return _response({"message": "rate limited"}, status=429)
        return handler

    _install_transport(monkeypatch, handler_factory())

    result = _collect(wayback_cdx, {"target": "example.com"})

    assert result.error_code == ErrorCode.RATE_LIMITED
    assert result.exit_code == 1


def test_wayback_collector_server_error(monkeypatch):
    async def handler(request):
        return _text("<html>Internet Archive: Temporarily Offline</html>",
                     status=503)

    _install_transport(monkeypatch, handler)
    result = _collect(wayback_cdx, {"target": "example.com"})

    assert result.error_code == ErrorCode.SPAWN_ERROR
    assert result.exit_code == 1


def test_wayback_parser_never_raises():
    for raw in ["", "garbage", "[]", "{broken", json.dumps({"rows": "nope"})]:
        parsed = wayback_parser.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings


# ════════════════════════════════════════════════════════════════════════
# darkweb_ahmia
# ════════════════════════════════════════════════════════════════════════

AHMIA_HOME_HTML = """<!doctype html><html><body>
<form id="searchForm" action="/search/" method="get">
  <input id="id_q" type="search" name="q" title="q">
  <input type="hidden" name="3553da" value="267067">
  <input type="submit" value="Search">
</form></body></html>"""

AHMIA_RESULTS_HTML = """<!doctype html><html><body><ul>
<li class="result"><h4><a href="/search/redirect?search_term=example.com&amp;redirect_url=http%3A%2F%2Fabcdefghijklmnop.onion%2Fpage">Hidden Service Title</a></h4><p>No description</p><cite>abcdefghijklmnop.onion</cite></li>
<li class="result"><h4><a href="/search/redirect?search_term=example.com&amp;redirect_url=http%3A%2F%2Fqrstuvwxyzabcdef.onion%2F">Second Result</a></h4><p>Desc</p><cite>qrstuvwxyzabcdef.onion</cite></li>
</ul></body></html>"""


async def _ahmia_handler(request):
    if request.url.path == "/search/":
        if request.url.params.get("3553da") == "267067":
            return _text(AHMIA_RESULTS_HTML)
        return httpx.Response(302, headers={"location": "/"})
    if request.url.path == "/":
        return _text(AHMIA_HOME_HTML)
    return _text("not found", status=404)


async def _ahmia_blocked_handler(request):
    if request.url.path == "/search/":
        return httpx.Response(302, headers={"location": "/"})
    return _text("<html><body>no search form here</body></html>")


async def _ahmia_rate_limited_handler(request):
    return _text("Forbidden", status=429)


def test_ahmia_collector_token_dance(monkeypatch):
    _install_transport(monkeypatch, _ahmia_handler)

    result = _collect(darkweb_ahmia, {"domain": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["query"] == "example.com"
    assert [onion["url"] for onion in payload["onions"]] == [
        "http://abcdefghijklmnop.onion/page",
        "http://qrstuvwxyzabcdef.onion/",
    ]
    assert payload["onions"][0]["title"] == "Hidden Service Title"
    assert payload["evidence"]["token_used"] is True
    assert payload["evidence"]["result_blocks"] == 2

    parsed = ahmia_parser.parse(result.stdout, "example.com")
    urls = {entity.value for entity in parsed.entities
            if entity.type is EntityType.URL}
    assert "http://abcdefghijklmnop.onion/page" in urls
    services = {entity.value for entity in parsed.entities
                if entity.type is EntityType.SERVICE}
    assert "ahmia" in services
    mentioned = [relation for relation in parsed.relations
                 if relation.predicate is EdgeType.MENTIONED_IN]
    assert len(mentioned) == 2
    assert all(relation.subject_value == "example.com" for relation in mentioned)
    assert all(entity.evidence for entity in parsed.entities)


def test_ahmia_collector_blocked_without_token(monkeypatch):
    _install_transport(monkeypatch, _ahmia_blocked_handler)

    result = _collect(darkweb_ahmia, {"username": "exampleuser"})

    assert result.error_code == ErrorCode.SPAWN_ERROR
    assert result.exit_code == 1
    assert "anti-bot" in result.error_message or "token" in result.error_message


def test_ahmia_collector_rate_limited(monkeypatch):
    _install_transport(monkeypatch, _ahmia_rate_limited_handler)

    result = _collect(darkweb_ahmia, {"email": "user@example.com"})

    assert result.error_code == ErrorCode.RATE_LIMITED
    assert result.exit_code == 1


def test_ahmia_parser_never_raises():
    for raw in ["", "garbage", "[]", "{broken", json.dumps({"onions": "nope"})]:
        parsed = ahmia_parser.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings


# ════════════════════════════════════════════════════════════════════════
# Cross-cutting contracts: timeouts, parameters, registry
# ════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("module,params", [
    (photon_crawler, {"target": "example.com"}),
    (github_osint, {"username": "octocat"}),
    (gravatar_lookup, {"email": "someone@example.com"}),
    (pgp_keyserver, {"email": "someone@example.com"}),
    (rdap_lookup, {"target": "example.com"}),
    (wayback_cdx, {"target": "example.com"}),
    (darkweb_ahmia, {"domain": "example.com"}),
])
def test_collector_maps_timeouts(monkeypatch, module, params):
    async def _timeout_handler(request):
        raise httpx.ReadTimeout("simulated timeout", request=request)

    _allow_safe_hosts(monkeypatch)
    _install_transport(monkeypatch, _timeout_handler)

    result = _collect(module, params)

    assert result.error_code == ErrorCode.TIMEOUT
    assert result.exit_code == -1


@pytest.mark.parametrize("module", ALL_COLLECTORS)
def test_collectors_require_parameters(monkeypatch, module):
    _install_transport(monkeypatch, _forbidden)

    result = _collect(module, {})

    assert result.exit_code == 2
    assert result.error_code is None
    assert "missing required parameter" in result.stderr


def test_all_parsers_tolerate_empty_and_garbage():
    garbage_inputs = ["", "   ", "not json at all", "[]", "{broken",
                      json.dumps({"unexpected": True})]
    for parser_module in ALL_PARSERS:
        for raw in garbage_inputs:
            parsed = parser_module.parse(raw)
            assert isinstance(parsed, ParseOutput)
            assert parsed.warnings, f"{parser_module.__name__} on {raw!r}"
            assert parsed.parser_version


def test_capability_registry_has_seven_passive_builtins():
    from hub.tools.runtime import _load_builtin_collector

    for tool_id in NATIVE_TOOL_IDS:
        capability = capabilities.get_tool(tool_id)
        assert capability is not None, f"{tool_id} is not registered"
        assert capability.execution_mode is ExecutionMode.PASSIVE
        assert capability.invocation.kind == "builtin"
        assert capability.invocation.builtin_ref
        assert capability.invocation.builtin_ref.endswith(":collect")
        assert capability.parser_ref.endswith(":parse")
        assert not capability.authorization_required

        parser = capability.parser()
        assert callable(parser)
        assert isinstance(parser("", ""), ParseOutput)

        collector = _load_builtin_collector(capability.invocation.builtin_ref)
        assert inspect.iscoroutinefunction(collector)

        status = capabilities.health_check(tool_id, force=True)
        assert status is not None
        assert status.available is True
        assert status.kind == "builtin"
        assert status.resolver == "builtin"
