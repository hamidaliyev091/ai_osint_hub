"""Zero-auth ASN / BGP / RIR network intelligence collector.

Queries RIPEstat public JSON (``stat.ripe.net``) with clean fallback to
BGPView public JSON (``api.bgpview.io``). IP targets are validated with
:func:`hub.security.policy.is_public_ip` / :func:`assert_safe_host` so private,
loopback, link-local and cloud-metadata addresses are always blocked.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from urllib.parse import quote

from hub.models import ErrorCode, ScopeConfig
from hub.security.policy import assert_safe_host, is_public_ip
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import (
    MAX_JSON_BYTES,
    decode_json,
    failure_output,
    fetch,
    make_client,
)

__all__ = ["collect"]

RIPESTAT_NETINFO = "https://stat.ripe.net/data/network-info/data.json?resource="
RIPESTAT_AS_OVERVIEW = "https://stat.ripe.net/data/as-overview/data.json?resource="
RIPESTAT_WHOIS = "https://stat.ripe.net/data/whois/data.json?resource="
BGPVIEW_IP = "https://api.bgpview.io/ip/"
BGPVIEW_ASN = "https://api.bgpview.io/asn/"

_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)


def _classify_target(raw: str) -> tuple[str, str]:
    text = str(raw or "").strip().strip("[]")
    if not text:
        return "", ""
    try:
        return "ip", str(ipaddress.ip_address(text))
    except ValueError:
        pass
    match = _ASN_RE.match(text)
    if match:
        num = int(match.group(1))
        if num > 0:
            return "asn", f"AS{num}"
    return "", ""


def _normalise_asn_str(value: object) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    if text.startswith("AS"):
        text = text[2:]
    return f"AS{text}" if text.isdigit() else ""


def _extract_ripestat_whois_fields(whois_data: dict) -> tuple[str, str, str]:
    """Return (org, country, rir) from RIPEstat whois records."""
    org = ""
    country = ""
    rir = ""
    records = whois_data.get("records")
    if not isinstance(records, list):
        return org, country, rir
    for rec in records:
        if not isinstance(rec, list):
            continue
        for entry in rec:
            if not isinstance(entry, dict):
                continue
            key = str(entry.get("key") or "").strip().lower()
            val = str(entry.get("value") or "").strip()
            if not val:
                continue
            if key in {"as-name", "org-name", "owner", "descr", "netname"} and not org:
                org = val
            elif key == "country" and not country:
                country = val.upper()
            elif key == "source" and not rir:
                rir = val.upper()
    if not rir:
        auth = str(whois_data.get("authority") or "").strip().upper()
        if auth:
            rir = auth
    return org, country, rir


async def _query_ripestat(client, kind: str, value: str) -> tuple[dict | None, BuiltinOutput | None]:
    if kind == "ip":
        url = f"{RIPESTAT_NETINFO}{quote(value, safe='')}"
        res = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
        if res.error:
            return None, failure_output("asn_bgp_lookup", res)
        if res.status_code == 429:
            return None, BuiltinOutput(
                exit_code=1, stderr="RIPEstat rate limited",
                error_code=ErrorCode.RATE_LIMITED, error_message="RIPEstat HTTP 429",
            )
        if res.status_code in {502, 503, 504}:
            return None, BuiltinOutput(
                exit_code=-1, stderr=f"RIPEstat HTTP {res.status_code}",
                error_code=ErrorCode.TIMEOUT, error_message=f"RIPEstat HTTP {res.status_code}",
            )
        if not 200 <= res.status_code < 300:
            return None, None
        try:
            body = decode_json(res.body)
        except ValueError:
            return None, None
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            return None, None
        asns = [_normalise_asn_str(a) for a in (data.get("asns") or [])]
        asns = [a for a in asns if a]
        prefix = str(data.get("prefix") or "").strip()
        prefixes = [prefix] if prefix else []
        org = ""
        country = ""
        rir = ""
        if asns:
            as_res = await fetch(client, f"{RIPESTAT_AS_OVERVIEW}{quote(asns[0], safe='')}",
                                 max_bytes=MAX_JSON_BYTES)
            if not as_res.error and 200 <= as_res.status_code < 300:
                try:
                    as_json = decode_json(as_res.body)
                    as_data = as_json.get("data") if isinstance(as_json, dict) else None
                    if isinstance(as_data, dict):
                        org = str(as_data.get("holder") or "").strip()
                        block = as_data.get("block") or {}
                        if isinstance(block, dict):
                            rir = str(block.get("name") or block.get("desc") or "").strip()
                except ValueError:
                    pass
        if not org or not country:
            w_res = await fetch(client, f"{RIPESTAT_WHOIS}{quote(value, safe='')}",
                                max_bytes=MAX_JSON_BYTES)
            if not w_res.error and 200 <= w_res.status_code < 300:
                try:
                    w_json = decode_json(w_res.body)
                    w_data = w_json.get("data") if isinstance(w_json, dict) else None
                    if isinstance(w_data, dict):
                        w_org, w_country, w_rir = _extract_ripestat_whois_fields(w_data)
                        org = org or w_org
                        country = country or w_country
                        rir = rir or w_rir
                except ValueError:
                    pass
        if not (asns or prefixes or org):
            return None, None
        return {
            "target": value,
            "kind": "ip",
            "asns": asns,
            "prefixes": prefixes,
            "org": org,
            "country": country,
            "rir": rir,
            "source": "ripestat",
            "found": True,
        }, None

    # kind == "asn"
    url = f"{RIPESTAT_AS_OVERVIEW}{quote(value, safe='')}"
    res = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    if res.error:
        return None, failure_output("asn_bgp_lookup", res)
    if res.status_code == 429:
        return None, BuiltinOutput(
            exit_code=1, stderr="RIPEstat rate limited",
            error_code=ErrorCode.RATE_LIMITED, error_message="RIPEstat HTTP 429",
        )
    if res.status_code in {502, 503, 504}:
        return None, BuiltinOutput(
            exit_code=-1, stderr=f"RIPEstat HTTP {res.status_code}",
            error_code=ErrorCode.TIMEOUT, error_message=f"RIPEstat HTTP {res.status_code}",
        )
    if not 200 <= res.status_code < 300:
        return None, None
    try:
        body = decode_json(res.body)
    except ValueError:
        return None, None
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        return None, None
    holder = str(data.get("holder") or "").strip()
    block = data.get("block") or {}
    rir = str(block.get("name") or block.get("desc") or "").strip() if isinstance(block, dict) else ""
    announced = bool(data.get("announced", True))
    if not holder and not announced:
        return None, None
    return {
        "target": value,
        "kind": "asn",
        "asns": [value],
        "prefixes": [],
        "org": holder,
        "country": "",
        "rir": rir,
        "source": "ripestat",
        "found": bool(holder or announced),
    }, None


async def _query_bgpview(client, kind: str, value: str) -> tuple[dict | None, BuiltinOutput | None]:
    if kind == "ip":
        url = f"{BGPVIEW_IP}{quote(value, safe='')}"
    else:
        asn_num = value[2:] if value.upper().startswith("AS") else value
        url = f"{BGPVIEW_ASN}{quote(asn_num, safe='')}"
    res = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    if res.error:
        return None, failure_output("asn_bgp_lookup", res)
    if res.status_code == 429:
        return None, BuiltinOutput(
            exit_code=1, stderr="BGPView rate limited",
            error_code=ErrorCode.RATE_LIMITED, error_message="BGPView HTTP 429",
        )
    if res.status_code in {502, 503, 504}:
        return None, BuiltinOutput(
            exit_code=-1, stderr=f"BGPView HTTP {res.status_code}",
            error_code=ErrorCode.TIMEOUT, error_message=f"BGPView HTTP {res.status_code}",
        )
    if not 200 <= res.status_code < 300:
        return None, None
    try:
        body = decode_json(res.body)
    except ValueError:
        return None, None
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        return None, None

    asns: list[str] = []
    prefixes: list[str] = []
    org = ""
    country = ""
    rir = ""

    if kind == "ip":
        rir_alloc = data.get("rir_allocation") or {}
        if isinstance(rir_alloc, dict):
            rir = str(rir_alloc.get("rir_name") or "").strip()
            country = str(rir_alloc.get("country_code") or "").strip().upper()
        for item in data.get("prefixes") or []:
            if not isinstance(item, dict):
                continue
            pfx = str(item.get("prefix") or "").strip()
            if pfx and pfx not in prefixes:
                prefixes.append(pfx)
            asn_obj = item.get("asn") or {}
            if isinstance(asn_obj, dict):
                asn_str = _normalise_asn_str(asn_obj.get("asn"))
                if asn_str and asn_str not in asns:
                    asns.append(asn_str)
                org = org or str(asn_obj.get("description") or asn_obj.get("name") or "").strip()
                country = country or str(asn_obj.get("country_code") or "").strip().upper()
    else:
        asn_str = _normalise_asn_str(data.get("asn") or value)
        if asn_str:
            asns.append(asn_str)
        org = str(data.get("description_short") or data.get("name") or "").strip()
        country = str(data.get("country_code") or "").strip().upper()
        rir_alloc = data.get("rir_allocation") or {}
        if isinstance(rir_alloc, dict):
            rir = str(rir_alloc.get("rir_name") or "").strip()

    if not (asns or prefixes or org):
        return None, None
    return {
        "target": value,
        "kind": kind,
        "asns": asns,
        "prefixes": prefixes,
        "org": org,
        "country": country,
        "rir": rir,
        "source": "bgpview",
        "found": True,
    }, None


async def _execute(kind: str, value: str, timeout_sec: int) -> BuiltinOutput:
    client = make_client(
        timeout_sec=timeout_sec,
        follow_redirects=False,
        headers={"Accept": "application/json"},
    )
    async with client:
        payload, err = await _query_ripestat(client, kind, value)
        if payload is not None:
            return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)
        bgp_payload, bgp_err = await _query_bgpview(client, kind, value)
        if bgp_payload is not None:
            return BuiltinOutput(stdout=json.dumps(bgp_payload, sort_keys=True), exit_code=0)
        if err is not None:
            return err
        if bgp_err is not None:
            return bgp_err

    empty = {
        "target": value,
        "kind": kind,
        "asns": [],
        "prefixes": [],
        "org": "",
        "country": "",
        "rir": "",
        "source": "ripestat",
        "found": False,
    }
    return BuiltinOutput(stdout=json.dumps(empty, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up ASN/BGP/RIR metadata for a public IP address or ASN."""
    raw = str(
        (params or {}).get("ip")
        or (params or {}).get("asn")
        or (params or {}).get("target")
        or ""
    ).strip()
    if not raw:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: ip or asn",
            error_message="asn_bgp_lookup requires an 'ip' or 'asn' parameter",
        )
    kind, value = _classify_target(raw)
    if not kind:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid IP or ASN target: {raw!r}",
            error_message=f"asn_bgp_lookup requires an IP address or ASN, got {raw!r}",
        )
    if kind == "ip":
        if scope.block_private_addresses and not is_public_ip(value):
            msg = f"SSRF guard blocked non-public IP {value!r}"
            return BuiltinOutput(
                exit_code=-1,
                stderr=msg,
                error_code=ErrorCode.SCOPE_BLOCKED,
                error_message=msg,
            )
        safe, reason = await asyncio.to_thread(assert_safe_host, value)
        if not safe:
            return BuiltinOutput(
                exit_code=-1,
                stderr=reason,
                error_code=ErrorCode.SCOPE_BLOCKED,
                error_message=reason,
            )
    try:
        return await asyncio.wait_for(_execute(kind, value, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        msg = f"asn_bgp_lookup timed out after {timeout_sec}s for {value}"
        return BuiltinOutput(
            exit_code=-1,
            stderr=msg,
            error_code=ErrorCode.TIMEOUT,
            error_message=msg,
        )
