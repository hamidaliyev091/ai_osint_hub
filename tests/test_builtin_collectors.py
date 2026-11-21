"""Tests for the three python-native passive collectors and their parsers.

Network access is fully monkeypatched: DNS resolution, httpx and the TLS
handshake are replaced with deterministic fakes. Collector timeout contract:
collectors *return* ``BuiltinOutput(error_code=TIMEOUT)`` rather than raising;
the runtime additionally maps any raised ``asyncio.TimeoutError`` to TIMEOUT.
"""

from __future__ import annotations

import asyncio
import json
import socket
import types

from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
import hub.tools.builtin.dns_lookup as dns_collector
import hub.tools.builtin.http_headers as http_collector
import hub.tools.builtin.tls_cert as tls_collector
from hub.tools.parsers import dns_lookup as dns_parser
from hub.tools.parsers import http_headers as http_parser
from hub.tools.parsers import tls_cert as tls_parser


def _collect(module, params, timeout_sec=2):
    """Drive an async collector with asyncio.run (pytest-asyncio is absent)."""
    return asyncio.run(module.collect(params, timeout_sec=timeout_sec, scope=ScopeConfig()))


# ════════════════════════════════════════════════════════════════════════
# Parser fixtures
# ════════════════════════════════════════════════════════════════════════

DNS_RAW = json.dumps({
    "target": "example.com",
    "addresses": [
        {"ip": "93.184.216.34", "family": "AF_INET"},
        {"ip": "2606:2800:220:1:248:1893:25c8:1946", "family": "AF_INET6"},
    ],
})

HTTP_RAW = json.dumps({
    "url": "https://example.com/",
    "status_code": 200,
    "headers": {
        "server": "nginx/1.25.3",
        "content-type": "text/html; charset=utf-8",
        "strict-transport-security": "max-age=31536000",
    },
    "server": "nginx/1.25.3",
    "content_type": "text/html; charset=utf-8",
    "title": "Example Domain",
})

TLS_RAW = json.dumps({
    "host": "example.com",
    "version": "TLSv1.3",
    "subject": {"commonName": "example.com"},
    "issuer": {"organizationName": "DigiCert Inc", "commonName": "R3"},
    "subjectAltName": [
        ["DNS", "example.com"],
        ["DNS", "www.example.com"],
        ["DNS", "*.api.example.com"],
        ["IP Address", "93.184.216.34"],
    ],
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Apr  1 00:00:00 2026 GMT",
})


# ── DNS parser ──────────────────────────────────────────────────────────

def test_dns_parser_extracts_ip_entities_and_relations():
    output = dns_parser.parse(DNS_RAW, "example.com")

    ip_values = {entity.value for entity in output.entities}
    assert ip_values == {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}
    assert all(entity.type.value == "ip" for entity in output.entities)
    assert all(entity.evidence for entity in output.entities)
    assert len(output.relations) == 2
    for relation in output.relations:
        assert relation.predicate.value == "RESOLVES_TO"
        assert relation.subject_value == "example.com"
        assert relation.subject_type.value == "domain"
        assert relation.object_type.value == "ip"
        assert relation.evidence
    assert output.warnings == []


def test_dns_parser_never_raises():
    assert dns_parser.parse("").is_empty
    assert dns_parser.parse("not json at all").warnings
    assert dns_parser.parse("[]").warnings
    assert dns_parser.parse(json.dumps({"target": "x.com", "addresses": "nope"})).warnings


# ── HTTP parser ─────────────────────────────────────────────────────────

def test_http_parser_extracts_url_service_and_relation():
    output = http_parser.parse(HTTP_RAW, "example.com")

    by_type = {entity.type.value: entity for entity in output.entities}
    assert by_type["url"].value == "https://example.com/"
    assert by_type["url"].attributes["status_code"] == 200
    assert by_type["service"].value == "nginx/1.25.3"
    assert by_type["service"].attributes["status_code"] == 200
    assert by_type["url"].evidence
    assert by_type["service"].evidence

    assert len(output.relations) == 1
    relation = output.relations[0]
    assert relation.predicate.value == "MENTIONED_IN"
    assert relation.subject_value == "https://example.com/"
    assert relation.object_value == "example.com"
    assert relation.object_type.value == "domain"


def test_http_parser_never_raises():
    assert http_parser.parse("").is_empty
    assert http_parser.parse("<<<not json>>>").warnings
    assert http_parser.parse(json.dumps({"status_code": 200})).is_empty


# ── TLS parser ──────────────────────────────────────────────────────────

def test_tls_parser_extracts_subdomains_organization_and_relation():
    output = tls_parser.parse(TLS_RAW, "example.com")

    subdomains = {entity.value for entity in output.entities
                  if entity.type.value == "subdomain"}
    # Wildcard SAN is canonicalised to its parent name.
    assert subdomains == {"example.com", "www.example.com", "api.example.com"}
    organizations = [entity for entity in output.entities
                     if entity.type.value == "organization"]
    assert [entity.value for entity in organizations] == ["DigiCert Inc"]
    assert all(entity.evidence for entity in output.entities)

    assert len(output.relations) == 1
    relation = output.relations[0]
    assert relation.predicate.value == "ASSOCIATED_WITH"
    assert relation.subject_value == "example.com"
    assert relation.object_type.value == "organization"
    assert relation.object_value == "DigiCert Inc"


def test_tls_parser_never_raises():
    assert tls_parser.parse("").is_empty
    assert tls_parser.parse("garbage").warnings
    assert tls_parser.parse(json.dumps({"host": "x"})).warnings


# ════════════════════════════════════════════════════════════════════════
# DNS collector
# ════════════════════════════════════════════════════════════════════════

def test_dns_collector_success(monkeypatch):
    def _fake_resolve(target):
        assert target == "example.com"
        return [("93.184.216.34", "AF_INET"),
                ("2606:2800:220:1:248:1893:25c8:1946", "AF_INET6")]

    monkeypatch.setattr(dns_collector, "_resolve_blocking", _fake_resolve)
    result = _collect(dns_collector, {"target": "example.com"})

    assert isinstance(result, BuiltinOutput)
    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["target"] == "example.com"
    assert [record["ip"] for record in payload["addresses"]] == [
        "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946",
    ]
    # Collector output is directly consumable by its parser.
    parsed = dns_parser.parse(result.stdout, "example.com")
    assert len(parsed.entities) == 2


def test_dns_collector_missing_target():
    result = _collect(dns_collector, {})
    assert result.exit_code == 2
    assert result.error_code is None
    assert "target" in (result.error_message or result.stderr)


def test_dns_collector_resolution_failure(monkeypatch):
    def _fake_resolve(target):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(dns_collector, "_resolve_blocking", _fake_resolve)
    result = _collect(dns_collector, {"target": "does-not-exist.invalid"})
    assert result.exit_code == 1
    assert result.error_code is None
    assert "failed" in result.error_message


def test_dns_collector_timeout(monkeypatch):
    import time as time_module

    def _slow_resolve(target):
        time_module.sleep(0.3)
        return [("93.184.216.34", "AF_INET")]

    monkeypatch.setattr(dns_collector, "_resolve_blocking", _slow_resolve)
    result = _collect(dns_collector, {"target": "slow.example.com"}, timeout_sec=0.05)
    assert result.error_code == ErrorCode.TIMEOUT
    assert result.exit_code == -1


# ════════════════════════════════════════════════════════════════════════
# HTTP collector
# ════════════════════════════════════════════════════════════════════════

class _FakeHTTPError(Exception):
    pass


class _FakeTimeout(_FakeHTTPError):
    pass


class _FakeResponse:
    status_code = 200
    headers = {
        "server": "nginx/1.25.3",
        "content-type": "text/html; charset=utf-8",
    }

    async def aiter_bytes(self):
        yield b"<html><head><title>Example Domain</title></head><body>x</body></html>"


class _FakeStream:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *args):
        return False


class _FakeAsyncClient:
    def __init__(self, response=None, **kwargs):
        self._response = response or _FakeResponse()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def stream(self, method, url):
        return _FakeStream(self._response)


def _fake_httpx(client_factory):
    return types.SimpleNamespace(
        AsyncClient=client_factory,
        Timeout=lambda value: value,
        HTTPError=_FakeHTTPError,
        TimeoutException=_FakeTimeout,
    )


def test_http_collector_success(monkeypatch):
    monkeypatch.setattr(http_collector, "assert_safe_host", lambda host: (True, "public"))
    monkeypatch.setattr(http_collector, "httpx", _fake_httpx(_FakeAsyncClient))

    result = _collect(http_collector, {"target": "example.com"})
    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["url"] == "https://example.com/"
    assert payload["status_code"] == 200
    assert payload["server"] == "nginx/1.25.3"
    assert payload["headers"]["server"] == "nginx/1.25.3"
    assert payload["content_type"].startswith("text/html")
    assert payload["title"] == "Example Domain"

    parsed = http_parser.parse(result.stdout, "example.com")
    assert any(entity.type.value == "url" for entity in parsed.entities)
    assert any(relation.predicate.value == "MENTIONED_IN" for relation in parsed.relations)


def test_http_collector_accepts_url_target(monkeypatch):
    monkeypatch.setattr(http_collector, "assert_safe_host", lambda host: (True, "public"))
    monkeypatch.setattr(http_collector, "httpx", _fake_httpx(_FakeAsyncClient))
    result = _collect(http_collector, {"target": "https://example.com/path?q=1"})
    assert json.loads(result.stdout)["url"] == "https://example.com/"


def test_http_collector_blocks_non_public_host_without_network(monkeypatch):
    # 169.254.169.254 is rejected by the SSRF guard before any client is built;
    # replace httpx with an exploding object to prove no request is attempted.
    def _explode(*args, **kwargs):
        raise AssertionError("http collector must not open a connection")

    monkeypatch.setattr(http_collector, "httpx", types.SimpleNamespace(
        AsyncClient=_explode,
        Timeout=lambda value: value,
        HTTPError=_FakeHTTPError,
        TimeoutException=_FakeTimeout,
    ))
    result = _collect(http_collector, {"target": "169.254.169.254"})
    assert result.error_code == ErrorCode.SCOPE_BLOCKED
    assert result.exit_code == -1


def test_http_collector_timeout(monkeypatch):
    monkeypatch.setattr(http_collector, "assert_safe_host", lambda host: (True, "public"))

    class _TimeoutClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, method, url):
            raise _FakeTimeout("read timed out")

    monkeypatch.setattr(http_collector, "httpx", _fake_httpx(_TimeoutClient))
    result = _collect(http_collector, {"target": "example.com"})
    assert result.error_code == ErrorCode.TIMEOUT
    assert result.exit_code == -1


def test_http_collector_connect_error(monkeypatch):
    monkeypatch.setattr(http_collector, "assert_safe_host", lambda host: (True, "public"))

    class _FailingClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            raise _FakeHTTPError("connection refused")

        async def __aexit__(self, *args):
            return False

        def stream(self, method, url):
            raise AssertionError("unreachable")

    monkeypatch.setattr(http_collector, "httpx", _fake_httpx(_FailingClient))
    result = _collect(http_collector, {"target": "example.com"})
    assert result.exit_code == 1
    assert result.error_code is None
    assert "failed" in result.error_message


# ════════════════════════════════════════════════════════════════════════
# TLS collector
# ════════════════════════════════════════════════════════════════════════

def _fake_certificate(host):
    return {
        "host": host,
        "version": "TLSv1.3",
        "subject": {"commonName": "example.com"},
        "issuer": {"organizationName": "DigiCert Inc", "commonName": "R3"},
        "subjectAltName": [["DNS", "example.com"], ["DNS", "www.example.com"]],
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Apr  1 00:00:00 2026 GMT",
    }


def test_tls_collector_success(monkeypatch):
    monkeypatch.setattr(tls_collector, "assert_safe_host", lambda host: (True, "public"))
    monkeypatch.setattr(tls_collector, "_peer_cert_payload",
                        lambda host, timeout_sec: _fake_certificate(host))

    result = _collect(tls_collector, {"target": "example.com"})
    assert result.exit_code == 0 and result.error_code is None
    payload = json.loads(result.stdout)
    assert payload["host"] == "example.com"
    assert payload["version"] == "TLSv1.3"
    assert payload["issuer"]["organizationName"] == "DigiCert Inc"
    assert payload["subjectAltName"] == [["DNS", "example.com"], ["DNS", "www.example.com"]]

    parsed = tls_parser.parse(result.stdout, "example.com")
    assert {entity.value for entity in parsed.entities
            if entity.type.value == "subdomain"} == {"example.com", "www.example.com"}
    assert any(entity.type.value == "organization" for entity in parsed.entities)
    assert any(relation.predicate.value == "ASSOCIATED_WITH"
               for relation in parsed.relations)


def test_tls_collector_blocks_non_public_host(monkeypatch):
    def _never_handshake(host, timeout_sec):
        raise AssertionError("tls collector must not connect to a non-public host")

    monkeypatch.setattr(tls_collector, "_peer_cert_payload", _never_handshake)
    result = _collect(tls_collector, {"target": "127.0.0.1"})
    assert result.error_code == ErrorCode.SCOPE_BLOCKED
    assert result.exit_code == -1


def test_tls_collector_handshake_failure(monkeypatch):
    import ssl

    monkeypatch.setattr(tls_collector, "assert_safe_host", lambda host: (True, "public"))

    def _failing_handshake(host, timeout_sec):
        raise ssl.SSLError("certificate verify failed")

    monkeypatch.setattr(tls_collector, "_peer_cert_payload", _failing_handshake)
    result = _collect(tls_collector, {"target": "example.com"})
    assert result.exit_code == 1
    assert result.error_code is None
    assert "TLS handshake failed" in result.error_message


def test_tls_collector_timeout(monkeypatch):
    import time as time_module

    monkeypatch.setattr(tls_collector, "assert_safe_host", lambda host: (True, "public"))

    def _slow_handshake(host, timeout_sec):
        time_module.sleep(0.3)
        return _fake_certificate(host)

    monkeypatch.setattr(tls_collector, "_peer_cert_payload", _slow_handshake)
    result = _collect(tls_collector, {"target": "example.com"}, timeout_sec=0.05)
    assert result.error_code == ErrorCode.TIMEOUT
    assert result.exit_code == -1
