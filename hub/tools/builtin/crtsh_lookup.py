"""Zero-auth Certificate Transparency (crt.sh) collector.

Queries ``https://crt.sh/?q=%.{domain}&output=json`` via bounded HTTP fetch,
validating the target domain syntax strictly (no target host is contacted).
Handles rate limiting (HTTP 429) and transient gateway/timeout errors
(502/503/504/timeout) gracefully as classified :class:`BuiltinOutput` values.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import quote

from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import (
    MAX_JSON_BYTES,
    decode_json,
    extract_host,
    failure_output,
    fetch,
    make_client,
)

__all__ = ["collect"]

CRTSH_BASE = "https://crt.sh/"
MAX_ENTRIES = 150
MAX_SUBDOMAINS = 200
MAX_ISSUERS = 50

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$"
)
_ORG_RE = re.compile(r"(?:^|,\s*)O=([^,/\n]+)")


def _normalise_domain(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        text = extract_host(text)
    text = text.strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if text.startswith("www."):
        text = text[4:]
    if not _DOMAIN_RE.match(text):
        return ""
    return text


def _extract_issuer_org(issuer_name: str) -> str:
    text = str(issuer_name or "").strip()
    if not text:
        return ""
    match = _ORG_RE.search(text)
    if match:
        return match.group(1).strip().strip('"')
    return ""


async def _execute(domain: str, timeout_sec: int) -> BuiltinOutput:
    url = f"{CRTSH_BASE}?q=%.{quote(domain, safe='')}&output=json"
    client = make_client(
        timeout_sec=timeout_sec,
        follow_redirects=False,
        headers={"Accept": "application/json"},
    )
    async with client:
        result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)

    if result.error:
        return failure_output("crtsh_lookup", result)
    if result.status_code == 429:
        msg = "crt.sh rate-limited the lookup (HTTP 429)"
        return BuiltinOutput(
            exit_code=1,
            stderr=msg,
            error_code=ErrorCode.RATE_LIMITED,
            error_message=msg,
        )
    if result.status_code in {502, 503, 504}:
        msg = f"crt.sh upstream unavailable/timed out (HTTP {result.status_code})"
        return BuiltinOutput(
            exit_code=-1,
            stderr=msg,
            error_code=ErrorCode.TIMEOUT,
            error_message=msg,
        )
    if result.status_code == 404:
        payload = {
            "domain": domain,
            "subdomains": [],
            "issuer_orgs": [],
            "entries": [],
            "found": False,
        }
        return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)
    if not 200 <= result.status_code < 300:
        msg = f"crt.sh returned HTTP {result.status_code} for {domain}"
        return BuiltinOutput(
            exit_code=1,
            stderr=msg,
            error_code=ErrorCode.SPAWN_ERROR,
            error_message=msg,
        )

    try:
        raw = decode_json(result.body)
    except ValueError as exc:
        msg = f"crt.sh response could not be parsed: {exc}"
        return BuiltinOutput(
            exit_code=1,
            stderr=msg,
            error_code=ErrorCode.PARSE_ERROR,
            error_message=msg,
        )

    if not isinstance(raw, list):
        msg = "crt.sh response was not a JSON array"
        return BuiltinOutput(
            exit_code=1,
            stderr=msg,
            error_code=ErrorCode.PARSE_ERROR,
            error_message=msg,
        )

    subdomains: list[str] = []
    seen_subs: set[str] = set()
    issuer_orgs: list[str] = []
    seen_orgs: set[str] = set()
    entries: list[dict] = []

    for item in raw[:MAX_ENTRIES]:
        if not isinstance(item, dict):
            continue
        name_value = str(item.get("name_value") or "")
        common_name = str(item.get("common_name") or "")
        issuer_name = str(item.get("issuer_name") or "")
        org = _extract_issuer_org(issuer_name)
        if org and org.lower() not in seen_orgs and len(issuer_orgs) < MAX_ISSUERS:
            seen_orgs.add(org.lower())
            issuer_orgs.append(org)

        raw_names = [line.strip() for line in name_value.splitlines() if line.strip()]
        if common_name.strip():
            raw_names.append(common_name.strip())
        item_sans: list[str] = []
        for raw_name in raw_names:
            wildcard = raw_name.startswith("*.")
            host = raw_name[2:] if wildcard else raw_name
            host = host.strip().lower().rstrip(".")
            if not host or not _HOST_RE.match(host):
                continue
            if host not in item_sans:
                item_sans.append(host)
            if host not in seen_subs and len(subdomains) < MAX_SUBDOMAINS:
                seen_subs.add(host)
                subdomains.append(host)

        entries.append({
            "id": item.get("id"),
            "common_name": common_name.strip().lower(),
            "sans": item_sans[:30],
            "issuer_name": issuer_name,
            "issuer_org": org,
            "not_before": str(item.get("not_before") or ""),
            "not_after": str(item.get("not_after") or ""),
        })

    payload = {
        "domain": domain,
        "subdomains": subdomains,
        "issuer_orgs": issuer_orgs,
        "entries": entries,
        "found": bool(subdomains or issuer_orgs or entries),
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Query crt.sh Certificate Transparency logs for a domain."""
    _ = scope  # crt.sh is the only host contacted; domain syntax is validated
    raw = str((params or {}).get("domain") or (params or {}).get("target") or "").strip()
    if not raw:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: domain",
            error_message="crtsh_lookup requires a non-empty 'domain'",
        )
    domain = _normalise_domain(raw)
    if not domain:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid domain: {raw!r}",
            error_message=f"crtsh_lookup requires a valid domain, got {raw!r}",
        )
    try:
        return await asyncio.wait_for(_execute(domain, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        msg = f"crtsh_lookup timed out after {timeout_sec}s for {domain}"
        return BuiltinOutput(
            exit_code=-1,
            stderr=msg,
            error_code=ErrorCode.TIMEOUT,
            error_message=msg,
        )
