"""Shodan API passive collector (host services, DNS subdomains, org/ASN).

Requires the ``SHODAN_API_KEY`` secret, sent as the ``key`` query parameter. The
raw key is scrubbed from every error string this module emits (it is never
serialised into stdout). IP lookups read ``/shodan/host/{ip}`` (open ports,
banners, hostnames, org/ISP/ASN); domain lookups read ``/dns/domain/{domain}``
(subdomains + DNS records). A 404 / "no information" response is a valid empty
result. Banner text and every list are bounded before serialisation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from urllib.parse import quote

from hub.credentials import CONFIGURED
from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import (
    MAX_JSON_BYTES,
    decode_json,
    failure_output,
    fetch,
    make_client,
)

__all__ = ["collect"]

SHODAN_API = "https://api.shodan.io"
MAX_PORTS = 40
MAX_HOSTNAMES = 40
MAX_SUBDOMAINS = 40
MAX_RECORDS = 40
MAX_BANNERS = 20
MAX_BANNER_CHARS = 300
MAX_TEXT = 200
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_MISSING_KEY_MESSAGE = (
    "Shodan API key not configured; use the Web UI API Keys drawer "
    "or 'python -m hub.cli auth set'"
)


def _api_key() -> str:
    """Resolve the key at call time (tests patch ``hub.credentials.get_secret``)."""
    from hub.credentials import get_secret

    return get_secret("shodan", "api_key")


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _scrub(text: str, secret: str) -> str:
    """Remove the API key from any message that could have embedded it."""
    if secret:
        return text.replace(secret, "[REDACTED]")
    return text


def _scrubbed(output: BuiltinOutput, secret: str) -> BuiltinOutput:
    return BuiltinOutput(
        stdout=_scrub(output.stdout, secret),
        stderr=_scrub(output.stderr, secret),
        exit_code=output.exit_code,
        error_code=output.error_code,
        error_message=_scrub(output.error_message, secret),
    )


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


def _unique_strings(values: object, limit: int, *, lower: bool = True) -> list[str]:
    result: list[str] = []
    if not isinstance(values, list):
        return result
    for value in values[:limit]:
        text = _as_text(value)
        if not text:
            continue
        if lower:
            text = text.lower()
        if text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _fqdn(name: str, base_domain: str) -> str:
    """Shodan DNS subdomains may be relative labels; normalise to a FQDN."""
    name = name.strip().lower().rstrip(".")
    if not name:
        return ""
    if not base_domain or name == base_domain or name.endswith("." + base_domain):
        return name
    if "." not in name:
        return f"{name}.{base_domain}"
    return name


def _banner_entry(item: dict) -> dict | None:
    port = _as_int(item.get("port"), default=-1)
    if port < 0:
        return None
    transport = _as_text(item.get("transport") or item.get("transport_protocol")
                         or "tcp").lower() or "tcp"
    module = _as_text(item.get("module"))[:MAX_TEXT]
    product = _as_text(item.get("product"))[:MAX_TEXT]
    version = _as_text(item.get("version"))[:MAX_TEXT]
    raw_banner = item.get("banner")
    if not isinstance(raw_banner, str) or not raw_banner.strip():
        raw_banner = item.get("data")
    banner = _as_text(raw_banner)[:MAX_BANNER_CHARS]
    return {
        "port": port,
        "transport": transport,
        "module": module,
        "product": product,
        "version": version,
        "banner": banner,
    }


def _empty_payload(target: str, kind: str) -> dict:
    return {
        "target": target,
        "target_type": kind,
        "auth_status": CONFIGURED,
        "ip": "",
        "domain": "",
        "ports": [],
        "hostnames": [],
        "subdomains": [],
        "records": [],
        "org": "",
        "isp": "",
        "asn": "",
        "data": [],
    }


def _status_error(result, secret: str) -> BuiltinOutput | None:
    if result.error:
        return _scrubbed(failure_output("shodan_lookup", result), secret)
    status = int(result.status_code)
    if status in {401, 403}:
        message = f"Shodan rejected the API key (HTTP {status})"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.AUTHORIZATION_REQUIRED,
                             error_message=message)
    if status == 429:
        message = "Shodan API rate limit reached (HTTP 429)"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.RATE_LIMITED, error_message=message)
    if not 200 <= status < 300:
        message = f"Shodan API returned HTTP {status}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.SPAWN_ERROR, error_message=message)
    return None


def _lookup_ip_payload(data: object, ip: str) -> dict:
    payload = _empty_payload(ip, "ip")
    if not isinstance(data, dict):
        return payload
    payload["ip"] = _as_text(data.get("ip_str") or data.get("ip") or ip) or ip
    payload["org"] = _as_text(data.get("org"))[:MAX_TEXT]
    payload["isp"] = _as_text(data.get("isp"))[:MAX_TEXT]
    payload["asn"] = _as_text(data.get("asn"))[:MAX_TEXT]
    payload["hostnames"] = _unique_strings(data.get("hostnames"), MAX_HOSTNAMES)

    raw_services = data.get("data")
    if isinstance(raw_services, list):
        entries: list[dict] = []
        for item in raw_services[:MAX_BANNERS]:
            entry = _banner_entry(item) if isinstance(item, dict) else None
            if entry is not None:
                entries.append(entry)
        payload["data"] = entries
    ports = _unique_ints(data.get("ports"), MAX_PORTS)
    if not ports:
        ports = _unique_ints([entry["port"] for entry in payload["data"]], MAX_PORTS)
    payload["ports"] = ports
    return payload


def _unique_ints(values: object, limit: int) -> list[int]:
    result: list[int] = []
    if not isinstance(values, list):
        return result
    for value in values:
        number = _as_int(value, default=-1)
        if number < 0 or number in result:
            continue
        result.append(number)
        if len(result) >= limit:
            break
    return result


def _lookup_domain_payload(data: object, domain: str) -> dict:
    payload = _empty_payload(domain, "domain")
    if not isinstance(data, dict):
        return payload
    base = _as_text(data.get("domain") or domain).lower().rstrip(".") or domain
    payload["domain"] = base
    payload["subdomains"] = [
        name for name in (_fqdn(item, base)
                          for item in _unique_strings(data.get("subdomains"),
                                                       MAX_SUBDOMAINS))
        if name
    ][:MAX_SUBDOMAINS]
    raw_records = data.get("records")
    records: list[dict] = []
    if isinstance(raw_records, list):
        for item in raw_records[:MAX_RECORDS]:
            if not isinstance(item, dict):
                continue
            record_type = _as_text(item.get("type")).upper()[:20]
            value = _as_text(item.get("value"))[:MAX_BANNER_CHARS]
            name = _as_text(item.get("name"))
            last_seen = _as_text(item.get("last_seen"))
            if not record_type and not value:
                continue
            records.append({"type": record_type, "name": name, "value": value,
                            "last_seen": last_seen})
    payload["records"] = records
    return payload


async def _execute(kind: str, value: str, api_key: str, timeout_sec: int) -> BuiltinOutput:
    encoded_key = quote(api_key, safe="")
    if kind == "ip":
        url = (f"{SHODAN_API}/shodan/host/{quote(value, safe='')}"
               f"?key={encoded_key}")
        endpoint = "Shodan host API"
    else:
        url = (f"{SHODAN_API}/dns/domain/{quote(value, safe='')}"
               f"?key={encoded_key}")
        endpoint = "Shodan DNS API"
    client = make_client(timeout_sec=timeout_sec, follow_redirects=True,
                         headers={"Accept": "application/json"})
    async with client:
        result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    error = _status_error(result, api_key)
    if error is not None:
        return error
    if result.status_code == 404:
        payload = _empty_payload(value, kind)
        return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)
    try:
        data = decode_json(result.body)
    except ValueError as exc:
        message = f"{endpoint} response could not be parsed: {exc}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.PARSE_ERROR, error_message=message)
    if not isinstance(data, dict):
        return BuiltinOutput(stdout=json.dumps(_empty_payload(value, kind),
                                               sort_keys=True), exit_code=0)
    if data.get("error"):
        # Shodan reports "No information available" as a 200 with an error field.
        payload = _empty_payload(value, kind)
        return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True),
                             stderr=_as_text(data.get("error"))[:1000], exit_code=0)
    payload = (_lookup_ip_payload(data, value) if kind == "ip"
               else _lookup_domain_payload(data, value))
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up Shodan host/DNS data for an IP address or domain."""
    _ = scope  # only api.shodan.io is contacted; target is never fetched
    api_key = _api_key()
    if not api_key:
        return BuiltinOutput(exit_code=1, stderr=_MISSING_KEY_MESSAGE,
                             error_code=ErrorCode.AUTHORIZATION_REQUIRED,
                             error_message=_MISSING_KEY_MESSAGE)
    target = _target_of(params)
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="shodan_lookup requires a non-empty 'target' IP or domain",
        )
    kind, value = _classify_target(target)
    if not kind:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid target: {target!r}",
            error_message=f"shodan_lookup requires an IP or domain target, got {target!r}",
        )
    try:
        return await asyncio.wait_for(
            _execute(kind, value, api_key, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"shodan_lookup timed out after {timeout_sec}s for {value}"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
