"""Python-native passive HTTP header collector — SSRF-guarded, https only."""

from __future__ import annotations

import asyncio
import html
import json
import re
from urllib.parse import urlsplit

import httpx

from hub.models import ErrorCode, ScopeConfig
from hub.security.policy import assert_safe_host
from hub.tools.builtin import BuiltinOutput

__all__ = ["collect"]

DEFAULT_TIMEOUT_SEC = 20
USER_AGENT = "ai-osint-hub/2.0 (passive header collector; +https)"
MAX_BODY_BYTES = 64 * 1024
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_host(target: str) -> str:
    """Reduce a URL or ``host[:port]`` target to a bare hostname."""
    text = str(target or "").strip()
    if not text:
        return ""
    if "://" in text:
        try:
            return (urlsplit(text).hostname or "").lower()
        except ValueError:
            return ""
    if text.startswith("["):
        end = text.find("]")
        return text[1:end].lower() if end > 0 else ""
    if text.count(":") == 1:
        head, _, tail = text.rpartition(":")
        if tail.isdigit():
            text = head
    return text.strip().strip("[]").strip().lower().rstrip(".")


def _title_from_body(body: bytes, content_type: str) -> str:
    if not body or "html" not in (content_type or "").lower():
        return ""
    text = body.decode("utf-8", errors="replace")
    match = _TITLE_RE.search(text)
    if not match:
        return ""
    return re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()[:300]


async def _collect_host(host: str, timeout_sec: int) -> BuiltinOutput:
    safe, reason = await asyncio.to_thread(assert_safe_host, host)
    if not safe:
        return BuiltinOutput(exit_code=-1, stderr=reason, error_code=ErrorCode.SCOPE_BLOCKED,
                             error_message=reason)

    url = f"https://{host}/"
    body = bytearray()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_sec),
            follow_redirects=False,
            headers={"user-agent": USER_AGENT, "accept": "text/html,*/*"},
        ) as client:
            async with client.stream("GET", url) as response:
                headers = {str(key).lower(): str(value)
                           for key, value in response.headers.items()}
                content_type = headers.get("content-type", "")
                if "html" in content_type.lower():
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) >= MAX_BODY_BYTES:
                            break
                status_code = int(response.status_code)
    except httpx.TimeoutException as exc:
        message = f"HTTP request timed out after {timeout_sec}s for {host}: {exc}"
        return BuiltinOutput(exit_code=-1, stderr=str(exc), error_code=ErrorCode.TIMEOUT,
                             error_message=message)
    except httpx.HTTPError as exc:
        message = f"HTTP request failed for {host}: {type(exc).__name__}: {exc}"
        return BuiltinOutput(exit_code=1, stderr=str(exc), error_message=message)

    payload = {
        "url": url,
        "status_code": status_code,
        "headers": headers,
        "server": headers.get("server", ""),
        "content_type": content_type,
        "title": _title_from_body(bytes(body), content_type),
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """GET ``https://<target>/`` with redirects disabled; bounded by timeout."""
    _ = scope  # host allow/deny lists are enforced by the runtime policy gate
    target = str((params or {}).get("target") or "").strip()
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="http_headers requires a non-empty 'target'",
        )
    host = _extract_host(target)
    if not host:
        return BuiltinOutput(exit_code=2, stderr=f"invalid target host: {target!r}",
                             error_message=f"http_headers received an invalid target: {target!r}")
    try:
        return await asyncio.wait_for(_collect_host(host, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"HTTP header collection timed out after {timeout_sec}s for {host}"
        return BuiltinOutput(exit_code=-1, stderr=message, error_code=ErrorCode.TIMEOUT,
                             error_message=message)
