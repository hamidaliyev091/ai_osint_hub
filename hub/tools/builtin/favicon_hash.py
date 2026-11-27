"""Zero-auth favicon MurmurHash3 + SHA-256 collector (SSRF-guarded).

Fetches ``/favicon.ico`` (and falls back to ``<link rel="icon">`` in the root
HTML) via :func:`hub.tools.builtin._http.fetch_safe`, validating every hop
with :func:`hub.security.policy.assert_safe_host`. Computes the pure-Python
signed 32-bit MurmurHash3 of the base64-encoded icon (Shodan
``http.favicon.hash`` format) alongside its SHA-256 digest.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from html import unescape
from urllib.parse import urljoin, urlsplit

from hub.models import ErrorCode, ScopeConfig
from hub.security.policy import assert_safe_host
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import (
    MAX_BODY_BYTES,
    extract_host,
    failure_output,
    fetch_safe,
    make_client,
    origin_of,
)

__all__ = ["collect", "mmh3_x86_32", "shodan_favicon_hash"]

MAX_ICON_BYTES = 2 * 1024 * 1024
_LINK_TAG_RE = re.compile(r"<link\b([^>]*)>", re.IGNORECASE)
_REL_RE = re.compile(r"""rel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)
_HREF_RE = re.compile(r"""href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)


def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3_x86_32 returning a signed 32-bit integer."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    nblocks = length // 4
    for idx in range(nblocks):
        k1 = int.from_bytes(data[idx * 4 : (idx + 1) * 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


def shodan_favicon_hash(raw_bytes: bytes) -> int:
    """Compute Shodan ``http.favicon.hash`` (signed 32-bit mmh3 of base64 lines)."""
    encoded = base64.encodebytes(raw_bytes)
    return mmh3_x86_32(encoded, seed=0)


def _normalise_target(target: str) -> tuple[str, str]:
    text = str(target or "").strip()
    if not text:
        return "", ""
    if "://" in text:
        url = text
        host = extract_host(text)
    else:
        host = extract_host(text)
        url = f"https://{text.strip('/')}/"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", ""
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return "", ""
    if not parts.path:
        url = url + "/"
    return url, host


def _extract_icon_href(html_text: str) -> str:
    for match in _LINK_TAG_RE.finditer(html_text):
        attrs = match.group(1) or ""
        rel_m = _REL_RE.search(attrs)
        if not rel_m:
            continue
        rel = (rel_m.group(1) or rel_m.group(2) or rel_m.group(3) or "").lower()
        if "icon" not in rel.split():
            if "icon" not in rel:
                continue
        href_m = _HREF_RE.search(attrs)
        if not href_m:
            continue
        href = unescape(href_m.group(1) or href_m.group(2) or href_m.group(3) or "").strip()
        if href and not href.startswith("data:"):
            return href
    return ""


def _looks_like_html(content_type: str, body: bytes) -> bool:
    ctype = (content_type or "").lower()
    if "text/html" in ctype or "application/xhtml" in ctype:
        return True
    head = body[:256].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html"))


async def _execute(target: str, root_url: str, base_host: str, timeout_sec: int) -> BuiltinOutput:
    client = make_client(timeout_sec=timeout_sec, follow_redirects=False)
    async with client:
        origin = origin_of(root_url) or f"https://{base_host}"
        ico_url = f"{origin}/favicon.ico"
        ico_res = await fetch_safe(
            client, ico_url, validate=assert_safe_host, max_bytes=MAX_ICON_BYTES
        )
        if ico_res.error_code == ErrorCode.SCOPE_BLOCKED:
            return failure_output("favicon_hash blocked by SSRF guard", ico_res)

        chosen = None
        if (
            ico_res.ok
            and 200 <= ico_res.status_code < 300
            and ico_res.body
            and not _looks_like_html(ico_res.headers.get("content-type", ""), ico_res.body)
        ):
            chosen = ico_res
        else:
            root_res = await fetch_safe(
                client, root_url, validate=assert_safe_host, max_bytes=MAX_BODY_BYTES
            )
            if root_res.error_code == ErrorCode.SCOPE_BLOCKED:
                return failure_output("favicon_hash blocked by SSRF guard", root_res)
            if root_res.ok and root_res.body:
                html_text = root_res.body.decode("utf-8", errors="replace")
                href = _extract_icon_href(html_text)
                if href:
                    icon_url = urljoin(root_res.url or root_url, href)
                    link_res = await fetch_safe(
                        client, icon_url, validate=assert_safe_host, max_bytes=MAX_ICON_BYTES
                    )
                    if link_res.error_code == ErrorCode.SCOPE_BLOCKED:
                        return failure_output("favicon_hash blocked by SSRF guard", link_res)
                    if (
                        link_res.ok
                        and 200 <= link_res.status_code < 300
                        and link_res.body
                        and not _looks_like_html(link_res.headers.get("content-type", ""), link_res.body)
                    ):
                        chosen = link_res
            if chosen is None and ico_res.error:
                return failure_output("favicon_hash", ico_res)

    if chosen is None:
        empty = {
            "target": target,
            "base_host": base_host,
            "url": ico_url,
            "found": False,
            "mmh3": None,
            "sha256": "",
            "bytes": 0,
            "content_type": "",
        }
        return BuiltinOutput(stdout=json.dumps(empty, sort_keys=True), exit_code=0)

    mmh3_val = shodan_favicon_hash(chosen.body)
    sha256_val = hashlib.sha256(chosen.body).hexdigest()
    payload = {
        "target": target,
        "base_host": base_host,
        "url": chosen.url or ico_url,
        "found": True,
        "mmh3": mmh3_val,
        "sha256": sha256_val,
        "bytes": len(chosen.body),
        "content_type": chosen.headers.get("content-type", ""),
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Fetch a site's favicon and compute Shodan-compatible MurmurHash3 + SHA-256."""
    _ = scope  # SSRF guard + runtime policy enforce host scope
    target = str((params or {}).get("target") or (params or {}).get("url") or "").strip()
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="favicon_hash requires a non-empty 'target'",
        )
    root_url, base_host = _normalise_target(target)
    if not root_url or not base_host:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid target: {target!r}",
            error_message=f"favicon_hash received an invalid target: {target!r}",
        )
    safe, reason = await asyncio.to_thread(assert_safe_host, base_host)
    if not safe:
        return BuiltinOutput(
            exit_code=-1,
            stderr=reason,
            error_code=ErrorCode.SCOPE_BLOCKED,
            error_message=reason,
        )
    try:
        return await asyncio.wait_for(
            _execute(target, root_url, base_host, timeout_sec), timeout=timeout_sec
        )
    except (asyncio.TimeoutError, TimeoutError):
        msg = f"favicon_hash timed out after {timeout_sec}s for {base_host}"
        return BuiltinOutput(
            exit_code=-1,
            stderr=msg,
            error_code=ErrorCode.TIMEOUT,
            error_message=msg,
        )
