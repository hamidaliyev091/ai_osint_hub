"""Censys Platform API passive collector (host services, certificates, org/ASN).

The legacy ``search.censys.io/api/v2`` endpoints are decommissioned, so this
collector talks to the current Censys Platform API with a Platform personal
access token: ``Authorization: Bearer <CENSYS_TOKEN>`` against
``https://api.platform.censys.io``.

* IP targets: ``GET /v3/global/asset/host/{ip}`` (services, software, TLS
  certificate names, autonomous system, whois organization, reverse DNS).
* Domain targets: resolve the domain's A records (``socket.getaddrinfo``,
  bounded to two unique IPs) and fetch the host asset for each. When no host
  asset can be collected, the free-tier global search endpoint
  (``POST /v3/global/search/query``) is tried once; its expected 403/404 for
  unprovisioned accounts is recorded as a warning, not a failure.

A credential pair consisting only of the legacy ``api_id``/``api_secret`` is
reported as decommissioned instead of being used. The token never appears in
URLs, stdout, stderr or error messages; all lists/text are bounded.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from typing import Any
from urllib.parse import quote

import httpx

from hub.credentials import CONFIGURED
from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import (
    MAX_JSON_BYTES,
    FetchResult,
    decode_json,
    failure_output,
    fetch,
    header_map,
    make_client,
    read_limited,
)

__all__ = ["collect"]

CENSYS_API = "https://api.platform.censys.io"
HOST_ASSET_PATH = "/v3/global/asset/host"
SEARCH_PATH = "/v3/global/search/query"
MAX_HOSTS = 2
MAX_SERVICES = 25
MAX_CERTIFICATES = 25
MAX_CERT_NAMES = 40
MAX_DNS_NAMES = 25
MAX_SUBDOMAINS = 40
MAX_NOTES = 20
MAX_TEXT = 300
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_MISSING_KEY_MESSAGE = (
    "Censys API key not configured; use the Web UI API Keys drawer "
    "or 'python -m hub.cli auth set'"
)
_LEGACY_KEY_MESSAGE = (
    "Censys legacy API decommissioned; configure a Censys Platform PAT "
    "(CENSYS_TOKEN)"
)


def _credentials() -> tuple[str, str, str]:
    """Resolve credentials at call time (tests patch ``hub.credentials.get_secret``)."""
    from hub.credentials import get_secret

    return (
        get_secret("censys", "token"),
        get_secret("censys", "api_id"),
        get_secret("censys", "api_secret"),
    )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_int(value: object, default: int = -1) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _target_of(params: dict) -> str:
    data = params or {}
    for key in ("target", "ip", "domain"):
        value = _as_text(data.get(key))
        if value:
            return value
    return ""


def _classify_target(target: str) -> tuple[str, str]:
    """Return ``("domain"|"ip", normalised)`` or ``("", "")`` when invalid."""
    text = _as_text(target)
    if not text:
        return "", ""
    if "://" in text:
        try:
            from urllib.parse import urlsplit

            text = urlsplit(text).hostname or ""
        except ValueError:
            text = ""
    text = text.strip().strip("[]").strip().lower().rstrip(".")
    if not text:
        return "", ""
    try:
        return "ip", str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if _DOMAIN_RE.match(text):
        return "domain", text
    return "", ""


def _unique_strings(values: object, limit: int, *, strip_wildcard: bool = False
                    ) -> list[str]:
    names: list[str] = []
    if not isinstance(values, list):
        return names
    for value in values:
        text = _as_text(value).lower().rstrip(".")
        if strip_wildcard and text.startswith("*."):
            text = text[2:]
        if not text or "*" in text or text in names:
            continue
        names.append(text)
        if len(names) >= limit:
            break
    return names


def _asn_text(value: object) -> str:
    """Normalise a Censys ASN (int or ``AS123``) to the ``AS123`` string form."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return f"AS{value}"
    text = _as_text(value)
    if not text:
        return ""
    digits = text.upper().removeprefix("AS")
    return f"AS{digits}" if digits.isdigit() else text[:MAX_TEXT]


def _organisation(as_info: dict, whois: dict) -> str:
    for source in (as_info.get("description"), as_info.get("name"),
                   whois.get("organization"), whois.get("network")):
        text = _as_text(source)
        if text:
            return text[:MAX_TEXT]
    return ""


def _location_text(location: object) -> str:
    if not isinstance(location, dict):
        return ""
    parts = [_as_text(location.get(key)) for key in
             ("city", "province", "country", "country_code")]
    return ", ".join(part for part in parts if part)[:MAX_TEXT]


def _certificate_from_cert(cert: object) -> dict | None:
    """Normalise a platform ``cert`` object into fingerprint/names/subject_cn."""
    if not isinstance(cert, dict):
        return None
    parsed = cert.get("parsed")
    parsed = parsed if isinstance(parsed, dict) else {}
    names = _unique_strings(parsed.get("names") or cert.get("names"),
                            MAX_CERT_NAMES, strip_wildcard=True)
    subject = parsed.get("subject")
    subject = subject if isinstance(subject, dict) else {}
    subject_cn = _as_text(subject.get("common_name") or subject.get("commonName"))
    if not subject_cn:
        subject_dn = _as_text(parsed.get("subject_dn") or cert.get("subject_dn"))
        for part in subject_dn.split(","):
            if part.strip().upper().startswith("CN="):
                subject_cn = part.strip()[3:].strip()
                break
    fingerprint = _as_text(cert.get("fingerprint_sha256")
                           or parsed.get("fingerprint_sha256"))
    if not names and not subject_cn and not fingerprint:
        return None
    return {
        "fingerprint_sha256": fingerprint[:128],
        "names": names,
        "subject_cn": subject_cn[:MAX_TEXT],
    }


def _service_entry(item: object) -> tuple[dict | None, list[dict]]:
    """Normalise one platform service dict (+ its certificate, if any)."""
    if not isinstance(item, dict):
        return None, []
    port = _as_int(item.get("port"))
    if port < 0:
        return None, []
    transport = _as_text(item.get("transport_protocol")
                         or item.get("transport") or item.get("protocol")
                         or "tcp").lower() or "tcp"
    service_name = ""
    software = item.get("software")
    if isinstance(software, list) and software:
        first = software[0] if isinstance(software[0], dict) else {}
        service_name = _as_text(first.get("product") or first.get("vendor"))
    if not service_name:
        service_name = _as_text(item.get("protocol") or item.get("service_name"))
    certificates: list[dict] = []
    cert = _certificate_from_cert(item.get("cert"))
    if cert is not None:
        certificates.append(cert)
    tls = item.get("tls")
    if isinstance(tls, dict):
        for key in ("certificates", "cert"):
            value = tls.get(key)
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                certificate = _certificate_from_cert(entry)
                if certificate is not None:
                    certificates.append(certificate)
        if not certificates:
            certificate = _certificate_from_cert(tls)
            if certificate is not None:
                certificates.append(certificate)
    cert_names = [name for certificate in certificates
                  for name in certificate.get("names", [])]
    cert_subject_cn = next((certificate.get("subject_cn") for certificate
                            in certificates if certificate.get("subject_cn")), "")
    service = {
        "port": port,
        "transport_protocol": transport,
        "service_name": service_name[:MAX_TEXT],
        "cert_names": _unique_strings(cert_names, MAX_CERT_NAMES)[:MAX_CERT_NAMES],
        "cert_subject_cn": _as_text(cert_subject_cn)[:MAX_TEXT],
    }
    return service, certificates


def _unique_certificates(certificates: list[dict]) -> list[dict]:
    result: list[dict] = []
    seen: set[str] = set()
    for certificate in certificates:
        key = (certificate.get("fingerprint_sha256")
               or certificate.get("subject_cn")
               or ",".join(certificate.get("names", [])))
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(certificate)
        if len(result) >= MAX_CERTIFICATES:
            break
    return result


def _host_resource(data: object) -> dict:
    """Unwrap a platform host-asset response to its ``resource`` mapping."""
    if not isinstance(data, dict):
        return {}
    result = data.get("result")
    if isinstance(result, dict):
        resource = result.get("resource")
        if isinstance(resource, dict):
            return resource
        return result
    resource = data.get("resource")
    return resource if isinstance(resource, dict) else {}


def _host_payload(resource: dict, fallback_ip: str) -> dict:
    ip = _as_text(resource.get("ip") or fallback_ip) or fallback_ip
    as_info = resource.get("autonomous_system")
    as_info = as_info if isinstance(as_info, dict) else {}
    whois = resource.get("whois")
    whois = whois if isinstance(whois, dict) else {}
    dns = resource.get("dns")
    dns = dns if isinstance(dns, dict) else {}
    asn = _asn_text(as_info.get("asn") or as_info.get("as_number"))
    organisation = _organisation(as_info, whois)
    names = _unique_strings(dns.get("names") if isinstance(dns.get("names"), list)
                            else [], MAX_DNS_NAMES)
    reverse_dns = _as_text(dns.get("reverse_dns"))[:MAX_TEXT]
    services: list[dict] = []
    certificates: list[dict] = []
    raw_services = resource.get("services")
    if isinstance(raw_services, list):
        for item in raw_services:
            service, service_certificates = _service_entry(item)
            if service is not None:
                services.append(service)
            certificates.extend(service_certificates)
    return {
        "ip": ip,
        "location": _location_text(resource.get("location")),
        "asn": asn,
        "organization": organisation,
        "names": names,
        "reverse_dns": reverse_dns,
        "services": services[:MAX_SERVICES],
        "certificates": _unique_certificates(certificates),
    }


def _empty_payload(target: str, kind: str) -> dict:
    return {
        "target": target,
        "target_type": kind,
        "auth_status": CONFIGURED,
        "host": {},
        "hosts": [],
        "services": [],
        "certificates": [],
        "subdomains": [],
        "asn": "",
        "organization": "",
        "errors": [],
        "warnings": [],
    }


def _status_error(result: FetchResult) -> BuiltinOutput | None:
    if result.error:
        return failure_output("censys_lookup", result)
    status = int(result.status_code)
    if status in {401, 403}:
        message = f"Censys rejected the Platform API token (HTTP {status})"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.AUTHORIZATION_REQUIRED,
                             error_message=message)
    if status == 429:
        message = "Censys Platform API rate limit reached (HTTP 429)"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.RATE_LIMITED, error_message=message)
    if not 200 <= status < 300:
        message = f"Censys Platform API returned HTTP {status}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.SPAWN_ERROR, error_message=message)
    return None


async def _post_json(client, url: str, payload: dict) -> FetchResult:
    """Bounded ``POST`` helper mirroring :func:`hub.tools.builtin._http.fetch`."""
    try:
        async with client.stream("POST", url, json=payload) as response:
            body = await read_limited(response, MAX_JSON_BYTES)
            return FetchResult(
                url=str(response.url),
                status_code=int(response.status_code),
                headers=header_map(response),
                body=body,
                truncated=len(body) >= MAX_JSON_BYTES,
            )
    except httpx.TimeoutException as exc:
        return FetchResult(url=url,
                           error=f"request timed out: {type(exc).__name__}: {exc}",
                           error_code=ErrorCode.TIMEOUT)
    except httpx.HTTPError as exc:
        return FetchResult(url=url,
                           error=f"HTTP request failed: {type(exc).__name__}: {exc}",
                           error_code=ErrorCode.SPAWN_ERROR)


class _ApiError(Exception):
    """Raised when a platform call must abort the whole lookup (auth/rate/transport)."""

    def __init__(self, output: BuiltinOutput) -> None:
        super().__init__(output.error_message or output.stderr)
        self.output = output


async def _fetch_host(client, ip: str, notes: dict[str, list[str]],
                      *, primary: bool) -> dict:
    """Fetch and normalise one platform host asset ({} when unavailable)."""
    result = await fetch(client, f"{CENSYS_API}{HOST_ASSET_PATH}/{quote(ip, safe='')}",
                         max_bytes=MAX_JSON_BYTES)
    if result.error:
        if primary:
            raise _ApiError(failure_output("censys_lookup", result))
        notes["errors"].append(f"host {ip}: {result.error}"[:MAX_TEXT])
        return {}
    status = int(result.status_code)
    if status == 404:
        notes["warnings"].append(f"host {ip}: no Censys Platform asset (HTTP 404)"
                                 [:MAX_TEXT])
        return {}
    error = _status_error(result)
    if error is not None:
        if status in {401, 403, 429} or primary:
            raise _ApiError(error)
        notes["warnings"].append(
            f"host {ip}: Censys Platform API HTTP {status}"[:MAX_TEXT])
        return {}
    try:
        data = decode_json(result.body)
    except ValueError as exc:
        notes["errors"].append(f"host {ip}: invalid JSON ({exc})"[:MAX_TEXT])
        return {}
    resource = _host_resource(data)
    if not resource:
        notes["warnings"].append(f"host {ip}: empty Censys asset response"[:MAX_TEXT])
        return {}
    return _host_payload(resource, ip)


def _resolve_ips(domain: str) -> list[str]:
    """Blocking A/AAAA resolution used through ``asyncio.to_thread`` (bounded)."""
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror):
        return []
    ips: list[str] = []
    for info in infos:
        try:
            address = str(ipaddress.ip_address(info[4][0]))
        except (IndexError, TypeError, ValueError):
            continue
        if address not in ips:
            ips.append(address)
        if len(ips) >= MAX_HOSTS:
            break
    return ips


def _aggregate(hosts: list[dict], target: str, kind: str,
               notes: dict[str, list[str]]) -> dict:
    payload = _empty_payload(target, kind)
    payload["hosts"] = hosts
    payload["host"] = hosts[0] if hosts else {}
    services: list[dict] = []
    certificates: list[dict] = []
    names: list[str] = []
    asn = ""
    organization = ""
    for host in hosts:
        for service in host.get("services", []):
            if len(services) < MAX_SERVICES:
                services.append(service)
        for certificate in host.get("certificates", []):
            if len(certificates) < MAX_CERTIFICATES:
                certificates.append(certificate)
            names.extend(certificate.get("names", []))
        names.extend(host.get("names", []))
        if not asn:
            asn = _as_text(host.get("asn"))
        if not organization:
            organization = _as_text(host.get("organization"))
    base_domain = target if kind == "domain" else ""
    subdomains: list[str] = []
    if base_domain:
        for name in names:
            clean = name[2:] if name.startswith("*.") else name
            if (clean == base_domain or not clean.endswith("." + base_domain)):
                continue
            if clean not in subdomains:
                subdomains.append(clean)
            if len(subdomains) >= MAX_SUBDOMAINS:
                break
    payload.update({
        "services": services,
        "certificates": _unique_certificates(certificates),
        "subdomains": subdomains,
        "asn": asn,
        "organization": organization,
    })
    payload["errors"] = notes["errors"][:MAX_NOTES]
    payload["warnings"] = notes["warnings"][:MAX_NOTES]
    return payload


async def _platform_search(client, domain: str, notes: dict[str, list[str]]) -> list[str]:
    """Optional free-tier certificate search; 403/404 is ignored (warning only)."""
    result = await _post_json(client, f"{CENSYS_API}{SEARCH_PATH}",
                              {"query": f"cert.names: {domain}",
                               "page_size": MAX_CERTIFICATES})
    if result.error:
        notes["warnings"].append(f"platform search: {result.error}"[:MAX_TEXT])
        return []
    status = int(result.status_code)
    if status in {401, 403, 404, 405}:
        notes["warnings"].append(
            f"platform search unavailable (HTTP {status}); using host assets only"
            [:MAX_TEXT])
        return []
    if not 200 <= status < 300:
        notes["warnings"].append(f"platform search returned HTTP {status}"[:MAX_TEXT])
        return []
    try:
        data = decode_json(result.body)
    except ValueError:
        notes["warnings"].append("platform search returned invalid JSON"[:MAX_TEXT])
        return []
    names: list[str] = []
    for hit in _search_hits(data):
        for name in _hit_names(hit):
            if name not in names:
                names.append(name)
            if len(names) >= MAX_CERT_NAMES:
                return names
    return names


def _search_hits(data: object) -> list[dict]:
    if not isinstance(data, dict):
        return []
    result = data.get("result")
    for container in (result, data):
        if not isinstance(container, dict):
            continue
        hits = container.get("hits")
        if isinstance(hits, list):
            return [hit for hit in hits if isinstance(hit, dict)]
    return []


def _hit_names(hit: dict) -> list[str]:
    cert = hit.get("cert")
    cert = cert if isinstance(cert, dict) else hit
    parsed = cert.get("parsed")
    parsed = parsed if isinstance(parsed, dict) else {}
    return _unique_strings(parsed.get("names") or cert.get("names"),
                           MAX_CERT_NAMES, strip_wildcard=True)


async def _lookup_ip(client, ip: str) -> BuiltinOutput:
    notes: dict[str, list[str]] = {"errors": [], "warnings": []}
    host = await _fetch_host(client, ip, notes, primary=True)
    payload = _aggregate([host] if host else [], ip, "ip", notes)
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True),
                         stderr="; ".join(payload["warnings"])[:1000], exit_code=0)


async def _lookup_domain(client, domain: str) -> BuiltinOutput:
    notes: dict[str, list[str]] = {"errors": [], "warnings": []}
    ips = await asyncio.to_thread(_resolve_ips, domain)
    hosts: list[dict] = []
    for ip in ips[:MAX_HOSTS]:
        host = await _fetch_host(client, ip, notes, primary=False)
        if host:
            hosts.append(host)
    search_names: list[str] = []
    if not hosts:
        search_names = await _platform_search(client, domain, notes)
        if not ips:
            notes["warnings"].append(
                f"no A/AAAA records resolved for {domain}; result is empty"[:MAX_TEXT])
    payload = _aggregate(hosts, domain, "domain", notes)
    if search_names:
        if len(payload["certificates"]) < MAX_CERTIFICATES:
            payload["certificates"].append({
                "fingerprint_sha256": "",
                "names": search_names[:MAX_CERT_NAMES],
                "subject_cn": "",
            })
        for name in search_names[:MAX_CERT_NAMES]:
            clean = name[2:] if name.startswith("*.") else name
            if clean == domain or not clean.endswith("." + domain):
                continue
            if clean not in payload["subdomains"] and len(payload["subdomains"]) < MAX_SUBDOMAINS:
                payload["subdomains"].append(clean)
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True),
                         stderr="; ".join(payload["warnings"])[:1000], exit_code=0)


async def _execute(kind: str, value: str, token: str, timeout_sec: int) -> BuiltinOutput:
    client = make_client(
        timeout_sec=timeout_sec,
        follow_redirects=True,
        headers={"Accept": "application/json",
                 "Authorization": f"Bearer {token}"},
    )
    try:
        async with client:
            if kind == "domain":
                return await _lookup_domain(client, value)
            return await _lookup_ip(client, value)
    except _ApiError as exc:
        return exc.output


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up Censys Platform host/certificate data for an IP address or domain."""
    _ = scope  # only api.platform.censys.io is contacted; target is never fetched
    token, api_id, api_secret = _credentials()
    if not token:
        message = _LEGACY_KEY_MESSAGE if (api_id and api_secret) else _MISSING_KEY_MESSAGE
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.AUTHORIZATION_REQUIRED,
                             error_message=message)
    target = _target_of(params)
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="censys_lookup requires a non-empty 'target' IP or domain",
        )
    kind, value = _classify_target(target)
    if not kind:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid target: {target!r}",
            error_message=f"censys_lookup requires an IP or domain target, got {target!r}",
        )
    try:
        return await asyncio.wait_for(
            _execute(kind, value, token, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"censys_lookup timed out after {timeout_sec}s for {value}"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
