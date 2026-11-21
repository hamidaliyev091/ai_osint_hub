"""Shared HTTP plumbing for the python-native passive collectors.

Every collector is zero-auth, https-first and *never raises*: network failures are
returned as classified :class:`BuiltinOutput` values by the collector wrapper.
This module only centralises the repetitive bits:

* a single User-Agent / timeout / client factory,
* bounded response-body reads (collectors must not slurp unbounded pages),
* :func:`fetch_safe` — the manual redirect loop used by target-site crawlers.
  Redirects are *not* followed by httpx; every hop is resolved manually and its
  host validated with :func:`hub.security.policy.assert_safe_host` **before** the
  request is issued, capped at three hops (SSRF guard).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

import httpx

from hub.models import ErrorCode
from hub.security.policy import assert_safe_host
from hub.tools.builtin import BuiltinOutput

__all__ = [
    "USER_AGENT",
    "MAX_BODY_BYTES",
    "MAX_JSON_BYTES",
    "REDIRECT_STATUSES",
    "MAX_REDIRECT_HOPS",
    "FetchResult",
    "timeout_of",
    "make_client",
    "extract_host",
    "origin_of",
    "header_map",
    "read_limited",
    "fetch",
    "fetch_safe",
    "decode_json",
    "failure_output",
]

USER_AGENT = "AI-OSINT-Hub/2.0 (+https://github.com/hamidaliyev091/ai_osint_hub)"
#: Bound for page/text bodies (photon crawler: root, robots.txt, sitemap.xml).
MAX_BODY_BYTES = 200 * 1024
#: Bound for JSON API payloads (GitHub events/repos can be a few hundred KB).
MAX_JSON_BYTES = 4 * 1024 * 1024
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECT_HOPS = 3
_ALLOWED_SCHEMES = frozenset({"http", "https"})


def timeout_of(timeout_sec: int) -> httpx.Timeout:
    """Timeout with a tighter connect bound, matching the collector contract."""
    total = max(1, int(timeout_sec or 1))
    return httpx.Timeout(total, connect=min(10, total))


def make_client(*, timeout_sec: int, follow_redirects: bool = False,
                headers: dict[str, str] | None = None) -> httpx.AsyncClient:
    """Build the shared httpx client (https, single User-Agent, bounded timeouts)."""
    merged = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        merged.update({str(key): str(value) for key, value in headers.items()})
    return httpx.AsyncClient(
        timeout=timeout_of(timeout_sec),
        follow_redirects=follow_redirects,
        headers=merged,
    )


def extract_host(value: str) -> str:
    """Reduce a URL, ``host[:port]`` or bare host to a lowercase hostname."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        try:
            return (urlsplit(text).hostname or "").strip().lower().rstrip(".")
        except ValueError:
            return ""
    return text.strip().strip("[]").strip().lower().rstrip(".")


def origin_of(url: str) -> str:
    """Return ``scheme://netloc`` for an absolute URL (or "")."""
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return ""
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def header_map(response: httpx.Response) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in response.headers.items()}


async def read_limited(response: httpx.Response, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` of the response body (stream friendly)."""
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) >= max_bytes:
            break
    return bytes(body[:max_bytes])


@dataclass
class FetchResult:
    """One bounded HTTP fetch (possibly after safe manual redirects)."""

    url: str = ""
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    hops: list[str] = field(default_factory=list)
    error: str = ""
    error_code: ErrorCode | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.error


async def fetch(client: httpx.AsyncClient, url: str,
                *, max_bytes: int = MAX_JSON_BYTES) -> FetchResult:
    """Plain bounded GET; redirect policy comes from the client configuration."""
    try:
        async with client.stream("GET", url) as response:
            body = await read_limited(response, max_bytes)
            return FetchResult(
                url=str(response.url),
                status_code=int(response.status_code),
                headers=header_map(response),
                body=body,
                truncated=len(body) >= max_bytes,
            )
    except httpx.TimeoutException as exc:
        return FetchResult(url=url,
                           error=f"request timed out: {type(exc).__name__}: {exc}",
                           error_code=ErrorCode.TIMEOUT)
    except httpx.HTTPError as exc:
        return FetchResult(url=url,
                           error=f"HTTP request failed: {type(exc).__name__}: {exc}",
                           error_code=ErrorCode.SPAWN_ERROR)


async def fetch_safe(client: httpx.AsyncClient, url: str,
                     *, validate: Callable[[str], tuple[bool, str]] = assert_safe_host,
                     max_hops: int = MAX_REDIRECT_HOPS,
                     max_bytes: int = MAX_BODY_BYTES) -> FetchResult:
    """GET ``url`` following redirects manually, validating every hop's host.

    ``client`` must be created with ``follow_redirects=False``. Redirects are
    only followed for http(s) and only after ``validate(host)`` allows the hop.
    """
    current = str(url or "")
    hops: list[str] = []
    for hop in range(max_hops + 1):
        host = extract_host(current)
        if not host:
            return FetchResult(url=current, hops=hops,
                               error=f"invalid URL: {current!r}",
                               error_code=ErrorCode.SPAWN_ERROR)
        safe, reason = await asyncio.to_thread(validate, host)
        if not safe:
            return FetchResult(url=current, hops=hops,
                               error=f"SSRF guard blocked host {host!r}: {reason}",
                               error_code=ErrorCode.SCOPE_BLOCKED)
        try:
            async with client.stream("GET", current) as response:
                status = int(response.status_code)
                headers = header_map(response)
                final_url = str(response.url)
                location = headers.get("location", "")
                if status in REDIRECT_STATUSES and location and hop < max_hops:
                    target = urljoin(final_url, location)
                    if urlsplit(target).scheme.lower() not in _ALLOWED_SCHEMES:
                        return FetchResult(
                            url=final_url, status_code=status, headers=headers, hops=hops,
                            error=f"refusing non-http redirect to {target!r}",
                            error_code=ErrorCode.SCOPE_BLOCKED,
                        )
                    hops.append(target)
                    current = target
                    continue
                body = await read_limited(response, max_bytes)
                return FetchResult(url=final_url, status_code=status, headers=headers,
                                   body=body, hops=hops,
                                   truncated=len(body) >= max_bytes)
        except httpx.TimeoutException as exc:
            return FetchResult(url=current, hops=hops,
                               error=f"request timed out: {type(exc).__name__}: {exc}",
                               error_code=ErrorCode.TIMEOUT)
        except httpx.HTTPError as exc:
            return FetchResult(url=current, hops=hops,
                               error=f"HTTP request failed: {type(exc).__name__}: {exc}",
                               error_code=ErrorCode.SPAWN_ERROR)
    return FetchResult(url=current, hops=hops,
                       error=f"too many redirects (more than {max_hops})",
                       error_code=ErrorCode.SPAWN_ERROR)


def decode_json(body: bytes) -> Any:
    """Decode a JSON response body; raises ``ValueError`` on empty/invalid data."""
    text = (body or b"").decode("utf-8", errors="replace").strip()
    if not text:
        raise ValueError("empty response body")
    try:
        return json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid JSON response: {exc}") from None


def failure_output(label: str, result: FetchResult, *, extra: str = "") -> BuiltinOutput:
    """Map a failed :class:`FetchResult` to a classified :class:`BuiltinOutput`."""
    code = result.error_code or ErrorCode.SPAWN_ERROR
    message = f"{label}: {result.error or 'request failed'}"
    if extra:
        message = f"{message}; {extra}"
    exit_code = -1 if code in {ErrorCode.TIMEOUT, ErrorCode.SCOPE_BLOCKED} else 1
    return BuiltinOutput(exit_code=exit_code, stderr=result.error or message,
                         error_code=code, error_message=message)
