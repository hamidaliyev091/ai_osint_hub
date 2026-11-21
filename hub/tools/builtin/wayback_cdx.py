"""Zero-auth Internet Archive CDX collector (historical archived URLs).

Queries the public Wayback Machine CDX API for a domain (``<domain>/*`` prefix)
or URL target, collapsed by URL key, limited to 100 rows and filtered to
HTTP-200 captures. Only ``web.archive.org`` is contacted; no archive page is
downloaded. Subdomains of the target domain are derived from the archived URLs.
"""

from __future__ import annotations

import asyncio
import json
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

CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
MAX_ROWS = 100
MAX_SUBDOMAINS = 100


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _url_param(target: str) -> str:
    """Domain targets become a prefix query; URL targets are used as given."""
    text = target.strip()
    if "://" in text:
        return text
    return f"{text.rstrip('/')}/*"


def _base_host(target: str) -> str:
    text = target.strip()
    if "://" not in text:
        text = f"https://{text.lstrip('/')}"
    return extract_host(text)


def _row_from_mapping(record: dict) -> dict:
    return {
        "url": _as_text(record.get("original") or record.get("url")),
        "timestamp": _as_text(record.get("timestamp")),
        "status": _as_text(record.get("statuscode") or record.get("status")),
        "mimetype": _as_text(record.get("mimetype")),
    }


def _parse_rows(data: object) -> list[dict]:
    """Normalise CDX JSON (list-of-lists with header row, or list-of-objects)."""
    rows: list[dict] = []
    if isinstance(data, dict):
        nested = data.get("rows")
        data = nested if isinstance(nested, list) else []
    if not isinstance(data, list) or not data:
        return rows
    if isinstance(data[0], dict):
        for record in data[:MAX_ROWS]:
            if isinstance(record, dict):
                rows.append(_row_from_mapping(record))
        return rows
    if isinstance(data[0], list):
        header = [_as_text(column).lower() for column in data[0]]
        for record in data[1:MAX_ROWS + 1]:
            if isinstance(record, list):
                rows.append(_row_from_mapping(dict(zip(header, record))))
    return rows


def _subdomains(rows: list[dict], base_host: str) -> list[str]:
    subdomains: list[str] = []
    if not base_host:
        return subdomains
    for row in rows:
        host = extract_host(row.get("url", ""))
        if not host or host == base_host or not host.endswith("." + base_host):
            continue
        if host not in subdomains:
            subdomains.append(host)
        if len(subdomains) >= MAX_SUBDOMAINS:
            break
    return subdomains


async def _execute(target: str, timeout_sec: int) -> BuiltinOutput:
    url_param = _url_param(target)
    url = (
        f"{CDX_ENDPOINT}?url={quote(url_param, safe='')}"
        "&output=json&collapse=urlkey&limit=100"
        "&fl=original,timestamp,statuscode,mimetype&filter=statuscode:200"
    )
    client = make_client(timeout_sec=timeout_sec, follow_redirects=True,
                         headers={"Accept": "application/json"})
    async with client:
        result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    if result.error:
        return failure_output("wayback_cdx", result)
    if result.status_code in {403, 429}:
        message = f"web.archive.org rate-limited the CDX query (HTTP {result.status_code})"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.RATE_LIMITED, error_message=message)
    if result.status_code >= 500:
        message = f"web.archive.org CDX API is unavailable (HTTP {result.status_code})"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.SPAWN_ERROR, error_message=message)

    rows: list[dict] = []
    notes: list[str] = []
    if 200 <= result.status_code < 300:
        if result.body.strip():
            try:
                rows = _parse_rows(decode_json(result.body))
            except ValueError as exc:
                notes.append(f"CDX response could not be parsed: {exc}")
    else:
        notes.append(f"CDX API returned HTTP {result.status_code}")

    base_host = _base_host(target)
    payload = {
        "target": target,
        "query": {"url_param": url_param, "endpoint": CDX_ENDPOINT},
        "rows": rows,
        "subdomains": _subdomains(rows, base_host),
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True),
                         stderr="; ".join(notes)[:1000], exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """List archived URLs for a domain/URL through the Wayback CDX API."""
    _ = scope  # web.archive.org is the only host contacted
    target = str((params or {}).get("target") or "").strip()
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="wayback_cdx requires a non-empty 'target'",
        )
    try:
        return await asyncio.wait_for(_execute(target, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"wayback_cdx timed out after {timeout_sec}s for {target}"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
