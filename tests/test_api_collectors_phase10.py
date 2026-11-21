"""Deterministic, network-free tests for the Phase-10b credential-backed collectors.

Every HTTP call is intercepted with ``httpx.MockTransport`` injected by
monkeypatching ``httpx.AsyncClient`` (same pattern as
``tests/test_native_collectors_v2.py``) and every credential lookup is served by
a fake ``hub.credentials.get_secret`` (the collectors import it lazily at call
time, so patching the ``hub.credentials`` module attribute is enough).

Covered per collector: canned success payload (required stdout keys,
``auth_status``, auth header/query, bounded lists, no raw key in output),
missing credential -> AUTHORIZATION_REQUIRED, 401/403 -> AUTHORIZATION_REQUIRED,
429 -> RATE_LIMITED, 404 -> valid empty stdout, timeout -> TIMEOUT, and the
parser on the collector stdout (entity types, relations, evidence) plus
never-raises on empty/garbage input. GitHub additionally checks the optional
``Authorization: Bearer`` header, KEYLESS_LIMITED vs CONFIGURED, and that the
existing public-profile behaviour is intact.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

import hub.credentials
from hub.models import EdgeType, EntityType, ErrorCode, ScopeConfig
from hub.tools.base import ParseOutput
from hub.tools.builtin import (
    censys_lookup,
    github_osint,
    hunter_lookup,
    shodan_lookup,
    virustotal_lookup,
)
from hub.tools.parsers import (
    censys_lookup as censys_parser,
    github_osint as github_parser,
    hunter_lookup as hunter_parser,
    shodan_lookup as shodan_parser,
    virustotal_lookup as virustotal_parser,
)

VT_KEY = "vt-fake-key-0123456789"
SHODAN_KEY = "shodan-fake-key-0123456789"
CENSYS_TOKEN = "censys-fake-pat-0123456789"
HUNTER_KEY = "hunter-fake-key-0123456789"
GITHUB_TOKEN = "ghp_fakegithubtoken0123456789"

ALL_COLLECTORS = [virustotal_lookup, shodan_lookup, censys_lookup, hunter_lookup]
ALL_PARSERS = [virustotal_parser, shodan_parser, censys_parser, hunter_parser]


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


def _install_transport(monkeypatch, handler):
    """Patch httpx.AsyncClient so every collector client uses a mock transport."""
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def _set_secrets(monkeypatch, **providers):
    """Serve fake credentials from ``hub.credentials.get_secret`` per test."""
    mapping: dict[tuple[str, str], str] = {}
    for provider, fields in providers.items():
        for field_name, value in fields.items():
            mapping[(provider, field_name)] = value

    def fake_get_secret(provider, field_name=""):
        return mapping.get((provider, field_name), "")

    monkeypatch.setattr(hub.credentials, "get_secret", fake_get_secret)


async def _forbidden(request):  # pragma: no cover - only fails tests if called
    raise AssertionError(f"unexpected HTTP request to {request.url}")


def _assert_no_secret(result, *secrets):
    blob = result.stdout + result.stderr + (result.error_message or "")
    for secret in secrets:
        assert secret not in blob, f"raw credential leaked: {secret!r}"


# ════════════════════════════════════════════════════════════════════════
# VirusTotal — canned payloads + handler
# ════════════════════════════════════════════════════════════════════════

VT_DOMAIN = {
    "data": {
        "id": "example.com",
        "type": "domain",
        "attributes": {
            "registrar": "RESERVED-Internet Assigned Numbers Authority",
            "as_owner": "CLOUDFLARENET",
            "asn": 13335,
            "country": "US",
            "reputation": 0,
            "whois_date": 1149024000,
            "last_analysis_stats": {"harmless": 72, "malicious": 0,
                                    "suspicious": 0, "undetected": 8,
                                    "timeout": 0},
            "categories": {"sophos": "information technology",
                           "forcepoint": "information technology"},
        },
    }
}
VT_SUBDOMAINS = {"data": [
    {"id": "www.example.com", "type": "domain"},
    {"id": "mail.example.com", "type": "domain"},
]}
VT_RESOLUTIONS = {"data": [
    {"attributes": {"host_name": "example.com",
                    "ip_address": "93.184.216.34", "date": 1600000000}},
    {"attributes": {"host_name": "www.example.com",
                    "ip_address": "93.184.216.35", "date": 1600000001}},
]}
VT_IP = {
    "data": {
        "id": "8.8.8.8",
        "type": "ip_address",
        "attributes": {
            "as_owner": "GOOGLE",
            "asn": 15169,
            "country": "US",
            "reputation": 42,
            "last_analysis_stats": {"harmless": 60, "malicious": 1,
                                    "suspicious": 0, "undetected": 5},
        },
    }
}


def _vt_handler(seen: dict):
    async def handler(request):
        assert request.url.host == "www.virustotal.com"
        seen["apikey"] = request.headers.get("x-apikey", "")
        path = request.url.path
        if path == "/api/v3/domains/example.com":
            return _response(VT_DOMAIN)
        if path == "/api/v3/domains/example.com/subdomains":
            assert request.url.params.get("limit") == "40"
            return _response(VT_SUBDOMAINS)
        if path == "/api/v3/domains/example.com/resolutions":
            assert request.url.params.get("limit") == "40"
            return _response(VT_RESOLUTIONS)
        if path == "/api/v3/ip_addresses/8.8.8.8":
            return _response(VT_IP)
        return _response({"error": {"code": "NotFoundError"}}, status=404)
    return handler


def test_virustotal_collector_domain_success(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, virustotal={"api_key": VT_KEY})
    _install_transport(monkeypatch, _vt_handler(seen))

    result = _collect(virustotal_lookup, {"target": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    assert seen["apikey"] == VT_KEY
    _assert_no_secret(result, VT_KEY)
    payload = json.loads(result.stdout)
    assert payload["target"] == "example.com"
    assert payload["target_type"] == "domain"
    assert payload["auth_status"] == "CONFIGURED"
    domain = payload["domain"]
    assert domain["value"] == "example.com"
    assert domain["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert domain["as_owner"] == "CLOUDFLARENET"
    assert domain["asn"] == 13335
    assert domain["country"] == "US"
    assert domain["verdict"] == "harmless"
    assert payload["reputation"] == 0
    assert payload["verdict"] == "harmless"
    assert payload["subdomains"] == ["www.example.com", "mail.example.com"]
    assert [row["ip_address"] for row in payload["resolutions"]] == [
        "93.184.216.34", "93.184.216.35"]
    assert payload["ip"] == {}


def test_virustotal_collector_ip_success(monkeypatch):
    _set_secrets(monkeypatch, virustotal={"api_key": VT_KEY})
    _install_transport(monkeypatch, _vt_handler({}))

    result = _collect(virustotal_lookup, {"ip": "8.8.8.8"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["target_type"] == "ip"
    assert payload["ip"]["as_owner"] == "GOOGLE"
    assert payload["ip"]["asn"] == 15169
    assert payload["ip"]["verdict"] == "malicious"
    assert payload["reputation"] == 42
    assert payload["domain"] == {}
    assert payload["subdomains"] == []


def test_virustotal_parser_entities_relations_evidence(monkeypatch):
    _set_secrets(monkeypatch, virustotal={"api_key": VT_KEY})
    _install_transport(monkeypatch, _vt_handler({}))
    result = _collect(virustotal_lookup, {"target": "example.com"})

    parsed = virustotal_parser.parse(result.stdout, "example.com")
    kinds = {entity.type.value for entity in parsed.entities}
    assert {"domain", "subdomain", "ip", "organization", "service"} <= kinds
    subdomain_values = {entity.value for entity in parsed.entities
                        if entity.type is EntityType.SUBDOMAIN}
    assert {"www.example.com", "mail.example.com"} <= subdomain_values
    assert any(relation.predicate is EdgeType.SUBDOMAIN_OF
               and relation.object_value == "example.com"
               for relation in parsed.relations)
    assert any(relation.predicate is EdgeType.RESOLVES_TO
               and relation.subject_value == "example.com"
               and relation.object_value == "93.184.216.34"
               for relation in parsed.relations)
    assert any(relation.predicate is EdgeType.REGISTERED_BY
               and relation.object_value == "RESERVED-Internet Assigned Numbers Authority"
               for relation in parsed.relations)
    assert any(relation.predicate is EdgeType.ASSOCIATED_WITH
               and relation.object_value == "CLOUDFLARENET"
               for relation in parsed.relations)
    domain = next(entity for entity in parsed.entities
                  if entity.type is EntityType.DOMAIN)
    assert domain.attributes["asn"] == 13335
    assert domain.attributes["verdict"] == "harmless"
    assert all(entity.evidence for entity in parsed.entities)


def test_virustotal_collector_bounded_lists(monkeypatch):
    async def handler(request):
        if request.url.path.endswith("/subdomains"):
            return _response({"data": [{"id": f"host{i}.example.com"}
                                       for i in range(60)]})
        if request.url.path.endswith("/resolutions"):
            return _response({"data": [{"attributes": {
                "host_name": f"host{i}.example.com",
                "ip_address": "93.184.216.34"}} for i in range(60)]})
        return _response(VT_DOMAIN)

    _set_secrets(monkeypatch, virustotal={"api_key": VT_KEY})
    _install_transport(monkeypatch, handler)
    result = _collect(virustotal_lookup, {"target": "example.com"})

    payload = json.loads(result.stdout)
    assert len(payload["subdomains"]) <= 40
    assert len(payload["resolutions"]) <= 40


def test_virustotal_collector_missing_key(monkeypatch):
    _set_secrets(monkeypatch)
    _install_transport(monkeypatch, _forbidden)

    result = _collect(virustotal_lookup, {"target": "example.com"})

    assert result.exit_code == 1
    assert result.error_code == ErrorCode.AUTHORIZATION_REQUIRED
    assert "API key not configured" in result.error_message
    assert "Web UI API Keys drawer" in result.error_message
    assert result.stdout == ""


def test_virustotal_collector_requires_target(monkeypatch):
    _set_secrets(monkeypatch, virustotal={"api_key": VT_KEY})
    _install_transport(monkeypatch, _forbidden)

    result = _collect(virustotal_lookup, {})

    assert result.exit_code == 2
    assert result.error_code is None
    assert "missing required parameter" in result.stderr


def test_virustotal_collector_404_is_valid_empty(monkeypatch):
    async def handler(request):
        return _response({"error": {"code": "NotFoundError"}}, status=404)

    _set_secrets(monkeypatch, virustotal={"api_key": VT_KEY})
    _install_transport(monkeypatch, handler)
    result = _collect(virustotal_lookup, {"target": "no-record.example"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["auth_status"] == "CONFIGURED"
    assert payload["domain"] == {}
    assert payload["subdomains"] == []
    assert payload["resolutions"] == []
    parsed = virustotal_parser.parse(result.stdout, "no-record.example")
    assert any("no VirusTotal record" in warning for warning in parsed.warnings)


# ════════════════════════════════════════════════════════════════════════
# Shodan — canned payloads + handler
# ════════════════════════════════════════════════════════════════════════

SHODAN_HOST = {
    "ip_str": "1.2.3.4",
    "ports": [22, 443],
    "hostnames": ["www.example.com", "mail.example.com"],
    "org": "Example Org",
    "isp": "Example ISP",
    "asn": "AS12345",
    "data": [
        {"port": 443, "transport": "tcp", "module": "https",
         "product": "nginx", "version": "1.18.0",
         "banner": "HTTP/1.1 200 OK\r\nServer: nginx"},
        {"port": 22, "transport": "tcp", "module": "ssh",
         "product": "OpenSSH", "version": "8.9",
         "banner": "SSH-2.0-OpenSSH_8.9"},
    ],
}
SHODAN_DNS = {
    "domain": "example.com",
    "tags": ["cdn"],
    "subdomains": ["www", "mail", "api"],
    "records": [
        {"type": "A", "name": "www", "value": "93.184.216.34",
         "last_seen": "2026-01-01"},
        {"type": "MX", "name": "example.com", "value": "mail.example.com",
         "last_seen": "2026-01-02"},
    ],
}


def _shodan_handler(seen: dict):
    async def handler(request):
        assert request.url.host == "api.shodan.io"
        seen["key"] = request.url.params.get("key", "")
        if request.url.path == "/shodan/host/1.2.3.4":
            return _response(SHODAN_HOST)
        if request.url.path == "/dns/domain/example.com":
            return _response(SHODAN_DNS)
        return _response({"error": "No information available"}, status=404)
    return handler


def test_shodan_collector_ip_success(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, shodan={"api_key": SHODAN_KEY})
    _install_transport(monkeypatch, _shodan_handler(seen))

    result = _collect(shodan_lookup, {"target": "1.2.3.4"})

    assert result.exit_code == 0 and result.error_code is None
    assert seen["key"] == SHODAN_KEY
    _assert_no_secret(result, SHODAN_KEY)
    payload = json.loads(result.stdout)
    assert payload["target"] == "1.2.3.4"
    assert payload["target_type"] == "ip"
    assert payload["auth_status"] == "CONFIGURED"
    assert payload["ip"] == "1.2.3.4"
    assert payload["domain"] == ""
    assert payload["ports"] == [22, 443]
    assert payload["hostnames"] == ["www.example.com", "mail.example.com"]
    assert payload["org"] == "Example Org"
    assert payload["isp"] == "Example ISP"
    assert payload["asn"] == "AS12345"
    assert [item["port"] for item in payload["data"]] == [443, 22]
    assert payload["data"][0]["product"] == "nginx"
    assert payload["data"][0]["banner"].startswith("HTTP/1.1 200 OK")


def test_shodan_collector_domain_success(monkeypatch):
    _set_secrets(monkeypatch, shodan={"api_key": SHODAN_KEY})
    _install_transport(monkeypatch, _shodan_handler({}))

    result = _collect(shodan_lookup, {"domain": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["target_type"] == "domain"
    assert payload["domain"] == "example.com"
    # Shodan returns relative labels; the collector normalises them to FQDNs.
    assert payload["subdomains"] == ["www.example.com", "mail.example.com",
                                     "api.example.com"]
    assert payload["ports"] == []
    assert [record["type"] for record in payload["records"]] == ["A", "MX"]


def test_shodan_parser_entities_relations_evidence(monkeypatch):
    _set_secrets(monkeypatch, shodan={"api_key": SHODAN_KEY})
    _install_transport(monkeypatch, _shodan_handler({}))
    result = _collect(shodan_lookup, {"target": "1.2.3.4"})

    parsed = shodan_parser.parse(result.stdout, "1.2.3.4")
    kinds = {entity.type.value for entity in parsed.entities}
    assert {"ip", "port", "service", "subdomain", "organization"} <= kinds
    port_values = {entity.value for entity in parsed.entities
                   if entity.type is EntityType.PORT}
    assert {"443/tcp", "22/tcp"} <= port_values
    service_values = {entity.value for entity in parsed.entities
                      if entity.type is EntityType.SERVICE}
    assert "nginx:443/tcp" in service_values
    assert "openssh:22/tcp" in service_values
    organization_values = {entity.value for entity in parsed.entities
                           if entity.type is EntityType.ORGANIZATION}
    assert {"Example Org", "Example ISP"} <= organization_values
    assert any(relation.predicate is EdgeType.ASSOCIATED_WITH
               and relation.subject_type is EntityType.IP
               and relation.object_value == "443/tcp"
               for relation in parsed.relations)
    assert all(entity.evidence for entity in parsed.entities)


def test_shodan_parser_domain_subdomains(monkeypatch):
    _set_secrets(monkeypatch, shodan={"api_key": SHODAN_KEY})
    _install_transport(monkeypatch, _shodan_handler({}))
    result = _collect(shodan_lookup, {"domain": "example.com"})

    parsed = shodan_parser.parse(result.stdout, "example.com")
    subdomain_values = {entity.value for entity in parsed.entities
                        if entity.type is EntityType.SUBDOMAIN}
    assert {"www.example.com", "mail.example.com"} <= subdomain_values
    assert any(relation.predicate is EdgeType.SUBDOMAIN_OF
               and relation.subject_value == "www.example.com"
               and relation.object_value == "example.com"
               for relation in parsed.relations)


def test_shodan_collector_bounds_banners(monkeypatch):
    big_banner = "X" * 4000

    async def handler(request):
        services = [{"port": 1000 + index, "transport": "tcp",
                     "module": "http", "product": "nginx",
                     "banner": big_banner} for index in range(25)]
        return _response({"ip_str": "1.2.3.4", "ports": list(range(1000, 1060)),
                          "hostnames": [], "org": "", "isp": "", "asn": "",
                          "data": services})

    _set_secrets(monkeypatch, shodan={"api_key": SHODAN_KEY})
    _install_transport(monkeypatch, handler)
    result = _collect(shodan_lookup, {"target": "1.2.3.4"})

    payload = json.loads(result.stdout)
    assert len(payload["data"]) <= 20
    assert all(len(entry["banner"]) <= 300 for entry in payload["data"])
    assert len(payload["ports"]) <= 40


# ════════════════════════════════════════════════════════════════════════
# Censys Platform — canned payloads + handler
# ════════════════════════════════════════════════════════════════════════

CENSYS_HOST_RESOURCE = {
    "ip": "93.184.216.34",
    "location": {"city": "Norwell", "province": "Massachusetts",
                 "country": "United States", "country_code": "US"},
    "autonomous_system": {"asn": 15133, "name": "EDGECAST",
                          "description": "EDGECAST",
                          "bgp_prefix": "93.184.216.0/24",
                          "country_code": "US"},
    "whois": {"network": "EDGECAST", "organization": "MCI Communications"},
    "dns": {"reverse_dns": "example.com",
            "names": ["example.com", "www.example.com"]},
    "service_count": 2,
    "services": [
        {
            "port": 443,
            "protocol": "HTTPS",
            "transport_protocol": "tcp",
            "cert": {
                "parsed": {
                    "subject": {"common_name": "example.com"},
                    "issuer": {"organization": ["DigiCert Inc"]},
                    "names": ["example.com", "*.example.com",
                              "www.example.com"],
                },
                "fingerprint_sha256": "cert-fingerprint-01",
            },
            "software": [{"vendor": "Acme", "product": "nginx"}],
        },
        {
            "port": 22,
            "protocol": "SSH",
            "transport_protocol": "tcp",
            "software": [{"vendor": "OpenBSD", "product": "OpenSSH"}],
        },
    ],
}


def _censys_host_payload(ip="93.184.216.34", resource=None):
    body = {"result": {"resource": resource or CENSYS_HOST_RESOURCE}}
    if ip != "93.184.216.34":
        body["result"]["resource"] = {**CENSYS_HOST_RESOURCE, "ip": ip}
    return body


def _censys_handler(seen: dict):
    async def handler(request):
        assert request.url.host == "api.platform.censys.io"
        seen.setdefault("auth", []).append(request.headers.get("authorization", ""))
        if request.method == "POST" and request.url.path == "/v3/global/search/query":
            seen["post_body"] = json.loads(request.content or b"{}")
            return _response({"error": "requires organization ID"}, status=403)
        if request.url.path == "/v3/global/asset/host/93.184.216.34":
            return _response(_censys_host_payload())
        if request.url.path == "/v3/global/asset/host/8.8.8.8":
            return _response(_censys_host_payload(
                ip="8.8.8.8",
                resource={**CENSYS_HOST_RESOURCE, "ip": "8.8.8.8"}))
        return _response({"error": "not found"}, status=404)
    return handler


def test_censys_collector_ip_success(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, censys={"token": CENSYS_TOKEN})
    _install_transport(monkeypatch, _censys_handler(seen))

    result = _collect(censys_lookup, {"target": "8.8.8.8"})

    assert result.exit_code == 0 and result.error_code is None
    assert seen["auth"] and seen["auth"][0] == f"Bearer {CENSYS_TOKEN}"
    _assert_no_secret(result, CENSYS_TOKEN)
    payload = json.loads(result.stdout)
    assert payload["target"] == "8.8.8.8"
    assert payload["target_type"] == "ip"
    assert payload["auth_status"] == "CONFIGURED"
    assert payload["asn"] == "AS15133"
    assert payload["organization"] == "EDGECAST"
    assert len(payload["hosts"]) == 1
    host = payload["hosts"][0]
    assert host["ip"] == "8.8.8.8"
    assert host["asn"] == "AS15133"
    assert host["organization"] == "EDGECAST"
    assert host["location"].startswith("Norwell")
    assert [service["port"] for service in host["services"]] == [443, 22]
    assert host["services"][0]["service_name"] == "nginx"
    assert host["services"][0]["transport_protocol"] == "tcp"
    assert "www.example.com" in host["services"][0]["cert_names"]
    assert host["certificates"][0]["fingerprint_sha256"] == "cert-fingerprint-01"
    assert payload["subdomains"] == []


def test_censys_collector_domain_success(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, censys={"token": CENSYS_TOKEN})
    _install_transport(monkeypatch, _censys_handler(seen))
    monkeypatch.setattr(censys_lookup, "_resolve_ips",
                        lambda domain: ["93.184.216.34"])

    result = _collect(censys_lookup, {"domain": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["target"] == "example.com"
    assert payload["target_type"] == "domain"
    assert "www.example.com" in payload["subdomains"]
    assert "example.com" not in payload["subdomains"]
    assert payload["hosts"][0]["ip"] == "93.184.216.34"
    assert seen.get("post_body") is None


def test_censys_collector_domain_search_fallback_403(monkeypatch):
    """No DNS resolution -> optional platform search; free-tier 403 is a warning."""
    seen: dict = {}
    _set_secrets(monkeypatch, censys={"token": CENSYS_TOKEN})
    _install_transport(monkeypatch, _censys_handler(seen))
    monkeypatch.setattr(censys_lookup, "_resolve_ips", lambda domain: [])

    result = _collect(censys_lookup, {"domain": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["auth_status"] == "CONFIGURED"
    assert payload["hosts"] == []
    assert payload["subdomains"] == []
    assert payload["services"] == []
    assert seen["post_body"] == {"query": "cert.names: example.com",
                                 "page_size": 25}
    assert any("search unavailable" in warning for warning in payload["warnings"])
    parsed = censys_parser.parse(result.stdout, "example.com")
    assert parsed.is_empty
    assert parsed.warnings


def test_censys_collector_legacy_credentials_rejected(monkeypatch):
    _set_secrets(monkeypatch, censys={"api_id": "legacy-id",
                                      "api_secret": "legacy-secret"})
    _install_transport(monkeypatch, _forbidden)

    result = _collect(censys_lookup, {"target": "8.8.8.8"})

    assert result.exit_code == 1
    assert result.error_code == ErrorCode.AUTHORIZATION_REQUIRED
    assert "legacy API decommissioned" in result.error_message
    assert "CENSYS_TOKEN" in result.error_message


def test_censys_collector_missing_key(monkeypatch):
    _set_secrets(monkeypatch)
    _install_transport(monkeypatch, _forbidden)

    result = _collect(censys_lookup, {"target": "8.8.8.8"})

    assert result.exit_code == 1
    assert result.error_code == ErrorCode.AUTHORIZATION_REQUIRED
    assert "API key not configured" in result.error_message


def test_censys_collector_404_is_valid_empty(monkeypatch):
    _set_secrets(monkeypatch, censys={"token": CENSYS_TOKEN})

    async def handler(request):
        return _response({"error": "not found"}, status=404)

    _install_transport(monkeypatch, handler)
    result = _collect(censys_lookup, {"target": "203.0.113.9"})

    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["auth_status"] == "CONFIGURED"
    assert payload["hosts"] == []
    assert payload["services"] == []


def test_censys_collector_bounds_services(monkeypatch):
    resource = {
        **CENSYS_HOST_RESOURCE,
        "services": [{"port": 1000 + index, "transport_protocol": "tcp",
                      "software": [{"vendor": "Acme", "product": "nginx"}],
                      "cert": {"parsed": {
                          "subject": {"common_name": "example.com"},
                          "names": [f"host{i}.example.com" for i in range(50)]},
                          "fingerprint_sha256": f"fp-{index}"}}
                     for index in range(30)],
    }

    async def handler(request):
        return _response({"result": {"resource": resource}})

    _set_secrets(monkeypatch, censys={"token": CENSYS_TOKEN})
    _install_transport(monkeypatch, handler)
    result = _collect(censys_lookup, {"target": "8.8.8.8"})

    payload = json.loads(result.stdout)
    assert len(payload["services"]) <= 25
    assert all(len(service["cert_names"]) <= 40 for service in payload["services"])


def test_censys_parser_entities_relations_evidence(monkeypatch):
    _set_secrets(monkeypatch, censys={"token": CENSYS_TOKEN})
    _install_transport(monkeypatch, _censys_handler({}))
    result = _collect(censys_lookup, {"target": "8.8.8.8"})

    parsed = censys_parser.parse(result.stdout, "8.8.8.8")
    kinds = {entity.type.value for entity in parsed.entities}
    assert {"ip", "port", "service", "organization"} <= kinds
    port_values = {entity.value for entity in parsed.entities
                   if entity.type is EntityType.PORT}
    assert {"443/tcp", "22/tcp"} <= port_values
    service_values = {entity.value for entity in parsed.entities
                      if entity.type is EntityType.SERVICE}
    assert "nginx:443/tcp" in service_values
    assert "openssh:22/tcp" in service_values
    ip_entity = next(entity for entity in parsed.entities
                     if entity.type is EntityType.IP)
    assert ip_entity.attributes["asn"] == "AS15133"
    assert ip_entity.attributes["organization"] == "EDGECAST"
    organizations = {entity.value for entity in parsed.entities
                     if entity.type is EntityType.ORGANIZATION}
    assert "EDGECAST" in organizations
    assert any(relation.predicate is EdgeType.ASSOCIATED_WITH
               and relation.subject_type is EntityType.IP
               and relation.object_value == "443/tcp"
               for relation in parsed.relations)
    assert all(entity.evidence for entity in parsed.entities)


def test_censys_parser_domain_subdomains(monkeypatch):
    _set_secrets(monkeypatch, censys={"token": CENSYS_TOKEN})
    _install_transport(monkeypatch, _censys_handler({}))
    monkeypatch.setattr(censys_lookup, "_resolve_ips",
                        lambda domain: ["93.184.216.34"])
    result = _collect(censys_lookup, {"domain": "example.com"})

    parsed = censys_parser.parse(result.stdout, "example.com")
    subdomain_values = {entity.value for entity in parsed.entities
                        if entity.type is EntityType.SUBDOMAIN}
    assert {"www.example.com", "example.com"} & subdomain_values
    assert any(relation.predicate is EdgeType.SUBDOMAIN_OF
               and relation.object_value == "example.com"
               for relation in parsed.relations)
    assert all(entity.evidence for entity in parsed.entities)


# ════════════════════════════════════════════════════════════════════════
# Hunter.io — canned payloads + handler
# ════════════════════════════════════════════════════════════════════════

HUNTER_DOMAIN_SEARCH = {
    "data": {
        "domain": "example.com",
        "organization": "Example Inc",
        "pattern": "{first}.{last}",
        "emails": [
            {"value": "john.doe@example.com", "type": "personal",
             "confidence": 97, "first_name": "John", "last_name": "Doe",
             "position": "CEO",
             "linkedin": "https://www.linkedin.com/in/johndoe",
             "phone_number": "+1 555 0100"},
            {"value": "jane@example.com", "type": "generic",
             "confidence": 70, "first_name": "Jane", "last_name": "",
             "position": "CTO",
             "linkedin": "https://www.linkedin.com/in/janedoe",
             "phone_number": ""},
        ],
    },
    "meta": {"results": 2},
}
HUNTER_EMAIL_VERIFICATION = {
    "data": {
        "status": "valid",
        "result": "deliverable",
        "score": 97,
        "email": "john.doe@example.com",
        "regexp": True,
        "disposable": False,
        "webmail": False,
    },
    "meta": {"results": 1},
}


def _hunter_handler(seen: dict):
    async def handler(request):
        assert request.url.host == "api.hunter.io"
        seen["api_key"] = request.url.params.get("api_key", "")
        if request.url.path == "/v2/domain-search":
            seen["domain"] = request.url.params.get("domain")
            seen["limit"] = request.url.params.get("limit")
            return _response(HUNTER_DOMAIN_SEARCH)
        if request.url.path == "/v2/email-verifier":
            seen["email"] = request.url.params.get("email")
            return _response(HUNTER_EMAIL_VERIFICATION)
        return _response({"errors": [{"id": "not_found"}]}, status=404)
    return handler


def test_hunter_collector_domain_success(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, hunter={"api_key": HUNTER_KEY})
    _install_transport(monkeypatch, _hunter_handler(seen))

    result = _collect(hunter_lookup, {"domain": "example.com"})

    assert result.exit_code == 0 and result.error_code is None
    assert seen == {"api_key": HUNTER_KEY, "domain": "example.com", "limit": "10"}
    _assert_no_secret(result, HUNTER_KEY)
    payload = json.loads(result.stdout)
    assert payload["target"] == "example.com"
    assert payload["target_type"] == "domain"
    assert payload["auth_status"] == "CONFIGURED"
    assert payload["domain"] == "example.com"
    assert payload["organization"] == "Example Inc"
    assert [email["value"] for email in payload["emails"]] == [
        "john.doe@example.com", "jane@example.com"]
    john = payload["emails"][0]
    assert john["first_name"] == "John"
    assert john["last_name"] == "Doe"
    assert john["confidence"] == 97
    assert john["linkedin"] == "https://www.linkedin.com/in/johndoe"
    assert payload["verification"] == {}


def test_hunter_parser_entities_relations_evidence(monkeypatch):
    _set_secrets(monkeypatch, hunter={"api_key": HUNTER_KEY})
    _install_transport(monkeypatch, _hunter_handler({}))
    result = _collect(hunter_lookup, {"domain": "example.com"})

    parsed = hunter_parser.parse(result.stdout, "example.com")
    kinds = {entity.type.value for entity in parsed.entities}
    assert {"email", "person", "organization", "social_profile"} <= kinds
    persons = {entity.value for entity in parsed.entities
               if entity.type is EntityType.PERSON}
    assert "John Doe" in persons
    emails = {entity.value for entity in parsed.entities
              if entity.type is EntityType.EMAIL}
    assert {"john.doe@example.com", "jane@example.com"} <= emails
    social = {entity.value for entity in parsed.entities
              if entity.type is EntityType.SOCIAL_PROFILE}
    assert "https://www.linkedin.com/in/johndoe" in social
    assert any(relation.predicate is EdgeType.HAS_EMAIL
               and relation.subject_value == "John Doe"
               and relation.object_value == "john.doe@example.com"
               for relation in parsed.relations)
    assert any(relation.predicate is EdgeType.ASSOCIATED_WITH
               and relation.subject_type is EntityType.EMAIL
               and relation.object_value == "example.com"
               for relation in parsed.relations)
    john = next(entity for entity in parsed.entities
                if entity.type is EntityType.PERSON and entity.value == "John Doe")
    assert john.attributes["position"] == "CEO"
    assert all(entity.evidence for entity in parsed.entities)


def test_hunter_collector_email_verification(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, hunter={"api_key": HUNTER_KEY})
    _install_transport(monkeypatch, _hunter_handler(seen))

    result = _collect(hunter_lookup, {"email": "john.doe@example.com"})

    assert result.exit_code == 0 and result.error_code is None
    assert seen["email"] == "john.doe@example.com"
    payload = json.loads(result.stdout)
    assert payload["target_type"] == "email"
    assert payload["domain"] == "example.com"
    assert payload["verification"] == {
        "status": "valid", "result": "deliverable", "score": 97,
        "regexp": True, "disposable": False, "webmail": False,
    }
    parsed = hunter_parser.parse(result.stdout, "john.doe@example.com")
    email_entity = next(entity for entity in parsed.entities
                        if entity.type is EntityType.EMAIL)
    assert email_entity.value == "john.doe@example.com"
    assert email_entity.attributes["verification"]["status"] == "valid"
    assert any(relation.predicate is EdgeType.ASSOCIATED_WITH
               and relation.subject_value == "john.doe@example.com"
               and relation.object_value == "example.com"
               for relation in parsed.relations)


def test_hunter_collector_bounds_emails(monkeypatch):
    async def handler(request):
        emails = [{"value": f"user{index}@example.com", "confidence": 90}
                  for index in range(30)]
        return _response({"data": {"domain": "example.com",
                                   "organization": "Example Inc",
                                   "emails": emails}})

    _set_secrets(monkeypatch, hunter={"api_key": HUNTER_KEY})
    _install_transport(monkeypatch, handler)
    result = _collect(hunter_lookup, {"domain": "example.com"})

    assert len(json.loads(result.stdout)["emails"]) <= 25


# ════════════════════════════════════════════════════════════════════════
# GitHub — optional token auth
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
GITHUB_REPOS = [{"full_name": "octocat/hello-world",
                 "html_url": "https://github.com/octocat/hello-world",
                 "language": "Ruby", "description": "My first repo",
                 "fork": False}]
GITHUB_EVENTS = [{"type": "PushEvent", "payload": {"commits": [
    {"author": {"email": "octocat@github.com", "name": "The Octocat"}}]}}]
GITHUB_SEARCH = {"total_count": 1,
                 "items": [{"login": "octocat",
                            "html_url": "https://github.com/octocat",
                            "avatar_url": "https://avatars.githubusercontent.com/u/583231"}]}


def _github_handler(seen: dict):
    async def handler(request):
        seen.setdefault("paths", []).append(request.url.path)
        seen.setdefault("authorizations", []).append(
            request.headers.get("authorization", ""))
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
    return handler


def test_github_collector_sends_bearer_token(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, github={"token": GITHUB_TOKEN})
    _install_transport(monkeypatch, _github_handler(seen))

    result = _collect(github_osint, {"username": "octocat"})

    assert result.exit_code == 0 and result.error_code is None
    assert seen["authorizations"] and all(
        value == f"Bearer {GITHUB_TOKEN}" for value in seen["authorizations"])
    _assert_no_secret(result, GITHUB_TOKEN)
    payload = json.loads(result.stdout)
    assert payload["auth_status"] == "CONFIGURED"
    # Existing public-profile behaviour stays intact.
    assert payload["query"] == {"username": "octocat", "email": ""}
    assert payload["user"]["login"] == "octocat"
    assert payload["repos"][0]["full_name"] == "octocat/hello-world"
    assert payload["emails"] == [{"email": "octocat@github.com",
                                  "source": "github:events_commits"}]

    parsed = github_parser.parse(result.stdout, "octocat")
    assert any(entity.type is EntityType.PERSON for entity in parsed.entities)
    assert any(relation.predicate is EdgeType.OWNS for relation in parsed.relations)


def test_github_collector_keyless_has_no_auth_header(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch)
    _install_transport(monkeypatch, _github_handler(seen))

    result = _collect(github_osint, {"username": "octocat"})

    assert result.exit_code == 0 and result.error_code is None
    assert seen["authorizations"] and all(
        not value for value in seen["authorizations"])
    payload = json.loads(result.stdout)
    assert payload["auth_status"] == "KEYLESS_LIMITED"
    assert payload["user"]["login"] == "octocat"


def test_github_collector_email_search_uses_token(monkeypatch):
    seen: dict = {}
    _set_secrets(monkeypatch, github={"token": GITHUB_TOKEN})
    _install_transport(monkeypatch, _github_handler(seen))

    result = _collect(github_osint, {"email": "octocat@github.com"})

    assert result.exit_code == 0 and result.error_code is None
    assert all(value == f"Bearer {GITHUB_TOKEN}"
               for value in seen["authorizations"])
    payload = json.loads(result.stdout)
    assert payload["query"]["email"] == "octocat@github.com"
    assert [user["login"] for user in payload["users"]] == ["octocat"]


@pytest.mark.parametrize("status", [401, 403, 429])
def test_github_collector_rate_limited(monkeypatch, status):
    async def handler(request):
        return _response({"message": "API rate limit exceeded"}, status=status)

    _set_secrets(monkeypatch, github={"token": GITHUB_TOKEN})
    _install_transport(monkeypatch, handler)
    result = _collect(github_osint, {"username": "octocat"})

    assert result.error_code == ErrorCode.RATE_LIMITED
    assert result.exit_code == 1
    assert "rate limit" in result.error_message.lower()
    assert GITHUB_TOKEN not in (result.error_message or "") + result.stderr


# ════════════════════════════════════════════════════════════════════════
# Cross-cutting contracts: auth/status mapping, timeouts, target validation,
# parser robustness
# ════════════════════════════════════════════════════════════════════════

_CREDENTIALS = {
    virustotal_lookup: {"virustotal": {"api_key": VT_KEY}},
    shodan_lookup: {"shodan": {"api_key": SHODAN_KEY}},
    censys_lookup: {"censys": {"token": CENSYS_TOKEN}},
    hunter_lookup: {"hunter": {"api_key": HUNTER_KEY}},
}
_PARAMS = {
    virustotal_lookup: {"target": "example.com"},
    shodan_lookup: {"target": "1.2.3.4"},
    censys_lookup: {"target": "8.8.8.8"},
    hunter_lookup: {"domain": "example.com"},
}


@pytest.mark.parametrize("module", ALL_COLLECTORS)
@pytest.mark.parametrize("status,expected", [
    (401, ErrorCode.AUTHORIZATION_REQUIRED),
    (403, ErrorCode.AUTHORIZATION_REQUIRED),
    (429, ErrorCode.RATE_LIMITED),
    (500, ErrorCode.SPAWN_ERROR),
])
def test_api_collector_status_mapping(monkeypatch, module, status, expected):
    async def handler(request):
        return _response({"error": "rejected"}, status=status)

    _set_secrets(monkeypatch, **_CREDENTIALS[module])
    _install_transport(monkeypatch, handler)
    result = _collect(module, _PARAMS[module])

    assert result.error_code == expected, module.__name__
    assert result.exit_code in {1, -1}
    _assert_no_secret(result, VT_KEY, SHODAN_KEY, CENSYS_TOKEN, HUNTER_KEY)


@pytest.mark.parametrize("module", ALL_COLLECTORS)
def test_api_collector_missing_key(monkeypatch, module):
    _set_secrets(monkeypatch)
    _install_transport(monkeypatch, _forbidden)

    result = _collect(module, _PARAMS[module])

    assert result.exit_code == 1
    assert result.error_code == ErrorCode.AUTHORIZATION_REQUIRED
    assert "API key not configured" in result.error_message
    assert result.stdout == ""


@pytest.mark.parametrize("module", ALL_COLLECTORS)
def test_api_collector_requires_parameters(monkeypatch, module):
    _set_secrets(monkeypatch, **_CREDENTIALS[module])
    _install_transport(monkeypatch, _forbidden)

    result = _collect(module, {})

    assert result.exit_code == 2
    assert result.error_code is None
    assert "missing required parameter" in result.stderr


@pytest.mark.parametrize("module", ALL_COLLECTORS)
def test_api_collector_maps_timeouts(monkeypatch, module):
    async def handler(request):
        raise httpx.ReadTimeout("simulated timeout", request=request)

    _set_secrets(monkeypatch, **_CREDENTIALS[module])
    _install_transport(monkeypatch, handler)
    result = _collect(module, _PARAMS[module])

    assert result.error_code == ErrorCode.TIMEOUT
    assert result.exit_code == -1


@pytest.mark.parametrize("module", ALL_COLLECTORS)
def test_api_collector_rejects_invalid_target(monkeypatch, module):
    _set_secrets(monkeypatch, **_CREDENTIALS[module])
    _install_transport(monkeypatch, _forbidden)

    result = _collect(module, {"target": "not a valid target!!",
                               "email": "not-an-email"})

    assert result.exit_code == 2
    assert result.error_code is None
    assert "invalid target" in result.stderr


@pytest.mark.parametrize("parser_module", ALL_PARSERS)
def test_api_parsers_never_raise(parser_module):
    garbage_inputs = ["", "   ", "not json at all", "[]", "{broken",
                      json.dumps({"unexpected": True}), json.dumps([1, 2, 3])]
    for raw in garbage_inputs:
        parsed = parser_module.parse(raw)
        assert isinstance(parsed, ParseOutput)
        assert parsed.warnings, f"{parser_module.__name__} on {raw!r}"
        assert parsed.parser_version
