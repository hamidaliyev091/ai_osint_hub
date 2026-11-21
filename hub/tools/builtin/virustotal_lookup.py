"""VirusTotal API v3 passive collector (domains, subdomains, IP reputation).

Requires the ``VIRUSTOTAL_API_KEY`` secret, sent as the ``x-apikey`` header (the
key never appears in URLs, stdout, stderr or error messages). Domain lookups
combine the domain object with its ``subdomains`` and ``resolutions`` endpoints;
IP lookups read the ``ip_addresses`` object. A 404 (no record) is a valid empty
result. Only the documented public API hosts are contacted; the target itself is
never fetched, and the response payloads are bounded before serialisation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from typing import Any
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

VT_API = "https://www.virustotal.com/api/v3"
MAX_SUBDOMAINS = 40
MAX_RESOLUTIONS = 40
MAX_CATEGORIES = 20
MAX_STATS_KEYS = 20
MAX_TEXT = 300
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_MISSING_KEY_MESSAGE = (
    "VirusTotal API key not configured; use the Web UI API Keys drawer "
    "or 'python -m hub.cli auth set'"
)


def _api_key() -> str:
    """Resolve the key at call time (tests patch ``hub.credentials.get_secret``)."""
    from hub.credentials import get_secret

    return get_secret("virustotal", "api_key")


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _target_of(params: dict) -> str:
    data = params or {}
    for key in ("target", "domain", "ip"):
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


def _verdict(stats: dict) -> str:
    """Deterministic verdict from a VirusTotal ``last_analysis_stats`` mapping."""
    malicious = _as_int(stats.get("malicious"))
    suspicious = _as_int(stats.get("suspicious"))
    if malicious:
        return "malicious"
    if suspicious:
        return "suspicious"
    if stats:
        return "harmless"
    return ""


def _normalise_stats(raw: object) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    stats: dict[str, int] = {}
    for key, value in raw.items():
        if len(stats) >= MAX_STATS_KEYS:
            break
        name = _as_text(key)
        if name:
            stats[name] = _as_int(value)
    return stats


def _normalise_categories(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    categories: dict[str, str] = {}
    for key, value in raw.items():
        if len(categories) >= MAX_CATEGORIES:
            break
        source = _as_text(key)
        category = _as_text(value)
        if source and category:
            categories[source] = category
    return categories


def _normalise_asn(value: object) -> object:
    asn = _as_int(value, default=-1)
    return asn if asn >= 0 else _as_text(value)


def _record(data: object, value: str, kind: str) -> dict:
    """Flatten a VirusTotal object's attributes into the bounded payload record."""
    attributes: dict = {}
    if isinstance(data, dict):
        raw = data.get("data")
        if isinstance(raw, dict) and isinstance(raw.get("attributes"), dict):
            attributes = raw["attributes"]
    stats = _normalise_stats(attributes.get("last_analysis_stats"))
    record: dict[str, Any] = {
        "value": _as_text(attributes.get("id") or attributes.get("value")) or value,
        "registrar": _as_text(attributes.get("registrar"))[:MAX_TEXT],
        "as_owner": _as_text(attributes.get("as_owner"))[:MAX_TEXT],
        "asn": _normalise_asn(attributes.get("asn")),
        "country": _as_text(attributes.get("country")),
        "reputation": _as_int(attributes.get("reputation")),
        "last_analysis_stats": stats,
        "whois_date": attributes.get("whois_date") or attributes.get("whois_timestamp")
        or "",
        "categories": _normalise_categories(attributes.get("categories")),
        "verdict": _verdict(stats),
    }
    if kind == "domain" and not record["value"]:
        record["value"] = value
    return record


def _empty_payload(target: str, kind: str) -> dict:
    return {
        "target": target,
        "target_type": kind,
        "auth_status": CONFIGURED,
        "domain": {},
        "ip": {},
        "subdomains": [],
        "resolutions": [],
        "reputation": 0,
        "verdict": "",
    }


def _paste(record: dict, kind: str, payload: dict) -> dict:
    payload["domain" if kind == "domain" else "ip"] = record
    payload["reputation"] = _as_int(record.get("reputation"))
    payload["verdict"] = _as_text(record.get("verdict"))
    return payload


def _status_error(result) -> BuiltinOutput | None:
    """Map a failed main API response to its classified output (None when 2xx/404)."""
    if result.error:
        return failure_output("virustotal_lookup", result)
    status = int(result.status_code)
    if status == 404:
        return None  # caller turns "no record" into a valid empty result
    if status in {401, 403}:
        message = f"VirusTotal rejected the API key (HTTP {status})"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.AUTHORIZATION_REQUIRED,
                             error_message=message)
    if status == 429:
        message = "VirusTotal API rate limit reached (HTTP 429)"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.RATE_LIMITED, error_message=message)
    if not 200 <= status < 300:
        message = f"VirusTotal API returned HTTP {status}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.SPAWN_ERROR, error_message=message)
    return None


def _secondary_names(payload: object) -> list[str]:
    """Extract bounded domain ids from a VirusTotal ``data`` list response."""
    names: list[str] = []
    items = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return names
    for item in items[:MAX_SUBDOMAINS]:
        if not isinstance(item, dict):
            continue
        name = _as_text(item.get("id") or item.get("value"))
        if name and name not in names:
            names.append(name)
    return names


def _secondary_resolutions(payload: object) -> list[dict]:
    resolutions: list[dict] = []
    items = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return resolutions
    for item in items[:MAX_RESOLUTIONS]:
        if not isinstance(item, dict):
            continue
        attributes = item.get("attributes")
        attributes = attributes if isinstance(attributes, dict) else item
        host_name = _as_text(attributes.get("host_name"))
        ip_address = _as_text(attributes.get("ip_address"))
        date = attributes.get("date") or ""
        if not host_name and not ip_address:
            continue
        resolutions.append({"host_name": host_name, "ip_address": ip_address,
                            "date": date})
    return resolutions


async def _secondary_json(client, url: str) -> object:
    result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    if not result.ok or not 200 <= int(result.status_code) < 300:
        return None
    try:
        return decode_json(result.body)
    except ValueError:
        return None


async def _lookup_domain(client, domain: str) -> BuiltinOutput:
    encoded = quote(domain, safe="")
    result = await fetch(client, f"{VT_API}/domains/{encoded}",
                         max_bytes=MAX_JSON_BYTES)
    error = _status_error(result)
    if error is not None:
        return error
    if result.status_code == 404:
        return BuiltinOutput(stdout=json.dumps(_empty_payload(domain, "domain"),
                                               sort_keys=True), exit_code=0)
    try:
        data = decode_json(result.body)
    except ValueError as exc:
        message = f"VirusTotal domain response could not be parsed: {exc}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.PARSE_ERROR, error_message=message)

    payload = _paste(_record(data, domain, "domain"), "domain",
                     _empty_payload(domain, "domain"))
    payload["subdomains"] = _secondary_names(
        await _secondary_json(
            client, f"{VT_API}/domains/{encoded}/subdomains?limit={MAX_SUBDOMAINS}"))
    payload["resolutions"] = _secondary_resolutions(
        await _secondary_json(
            client, f"{VT_API}/domains/{encoded}/resolutions?limit={MAX_RESOLUTIONS}"))
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def _lookup_ip(client, ip: str) -> BuiltinOutput:
    result = await fetch(client, f"{VT_API}/ip_addresses/{quote(ip, safe='')}",
                         max_bytes=MAX_JSON_BYTES)
    error = _status_error(result)
    if error is not None:
        return error
    if result.status_code == 404:
        return BuiltinOutput(stdout=json.dumps(_empty_payload(ip, "ip"),
                                               sort_keys=True), exit_code=0)
    try:
        data = decode_json(result.body)
    except ValueError as exc:
        message = f"VirusTotal IP response could not be parsed: {exc}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.PARSE_ERROR, error_message=message)
    payload = _paste(_record(data, ip, "ip"), "ip", _empty_payload(ip, "ip"))
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def _execute(kind: str, value: str, api_key: str, timeout_sec: int) -> BuiltinOutput:
    client = make_client(
        timeout_sec=timeout_sec,
        follow_redirects=True,
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    async with client:
        if kind == "domain":
            return await _lookup_domain(client, value)
        return await _lookup_ip(client, value)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up a domain or IP address through the VirusTotal API v3."""
    _ = scope  # only www.virustotal.com is contacted; target is never fetched
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
            error_message="virustotal_lookup requires a non-empty 'target' domain or IP",
        )
    kind, value = _classify_target(target)
    if not kind:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid target: {target!r}",
            error_message=f"virustotal_lookup requires a domain or IP target, got {target!r}",
        )
    try:
        return await asyncio.wait_for(
            _execute(kind, value, api_key, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"virustotal_lookup timed out after {timeout_sec}s for {value}"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
