"""Zero-auth Ahmia dark-web index collector (clearnet, no Tor daemon needed).

Searches the public Ahmia clearnet index for a domain, e-mail address or
username and extracts the ``.onion`` service URLs mentioned in the results.

Ahmia answers a bare ``/search/?q=...`` request with a redirect to its homepage
and requires the dynamic hidden form token from that homepage (anti-bot
measure). The collector therefore retries once with the token, which keeps it a
plain HTTPS client: no Tor, no cookies, no JavaScript. Network errors, 403/429
and unexpected redirects are surfaced as classified failures.
"""

from __future__ import annotations

import asyncio
import json
import re
from html import unescape
from urllib.parse import quote, unquote, urlsplit

from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import failure_output, fetch, make_client

__all__ = ["collect"]

AHMIA_HOME = "https://ahmia.fi/"
AHMIA_SEARCH = "https://ahmia.fi/search/"
MAX_HTML_BYTES = 4 * 1024 * 1024
MAX_RESULTS = 50

_RESULT_BLOCK_RE = re.compile(r'<li\s+class="result">(.*?)</li>', re.IGNORECASE | re.DOTALL)
_REDIRECT_URL_RE = re.compile(r'redirect_url=([^&"\'>\s]+)', re.IGNORECASE)
_ANCHOR_RE = re.compile(r'<a\b[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
_ONION_URL_RE = re.compile(
    r'https?://([a-z2-7]{16,56}\.onion)(?:[/?#][^\s"\'<>]*)?', re.IGNORECASE)
_ONION_HOST_RE = re.compile(r'\b([a-z2-7]{16,56}\.onion)\b', re.IGNORECASE)
_HIDDEN_INPUT_RE = re.compile(r'<input\b[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
_TAG_RE = re.compile(r'<[^>]+>')
_ATTR_TEMPLATE = r'(?:^|\s){name}\s*=\s*["\']([^"\']*)["\']'


def _attr(tag: str, name: str) -> str:
    match = re.search(_ATTR_TEMPLATE.format(name=re.escape(name)), tag, re.IGNORECASE)
    return unescape(match.group(1)).strip() if match else ""


def _extract_search_token(html: str) -> tuple[str, str]:
    """Find Ahmia's dynamic hidden anti-bot input (name != ``q``)."""
    for match in _HIDDEN_INPUT_RE.finditer(html):
        tag = match.group(0)
        name = _attr(tag, "name")
        value = _attr(tag, "value")
        if name and value and name.lower() != "q":
            return name, value
    return "", ""


def _result_url(block: str) -> str:
    redirect = _REDIRECT_URL_RE.search(block)
    if redirect:
        candidate = unquote(unescape(redirect.group(1))).strip()
        if candidate:
            return candidate
    match = _ONION_URL_RE.search(block)
    if match:
        return f"http://{match.group(1).lower()}"
    match = _ONION_HOST_RE.search(block)
    if match:
        return f"http://{match.group(1).lower()}"
    return ""


def _result_title(block: str) -> str:
    match = _ANCHOR_RE.search(block)
    if not match:
        return ""
    title = unescape(_TAG_RE.sub(" ", match.group(1)))
    return re.sub(r"\s+", " ", title).strip()[:300]


def _result_snippet(block: str) -> str:
    text = unescape(_TAG_RE.sub(" ", block))
    return re.sub(r"\s+", " ", text).strip()[:500]


def _matches_target(title: str, snippet: str, url: str, target: str,
                    mode: str) -> bool:
    """Exact identifier match for e-mail/username searches (never @domain only)."""
    target = (target or "").strip().lower()
    if not target or mode not in {"email", "username"}:
        return True
    haystack = f"{title} {snippet} {url}".lower()
    if mode == "email":
        if target in haystack:
            return True
        local = target.split("@", 1)[0]
        return len(local) >= 5 and local in haystack
    return target in haystack


def _parse_results(html: str, target: str = "",
                   mode: str = "domain") -> tuple[list[dict], int]:
    onions: list[dict] = []
    seen: set[str] = set()
    blocks = _RESULT_BLOCK_RE.findall(html or "")
    for block in blocks:
        if len(onions) >= MAX_RESULTS:
            break
        url = _result_url(block)
        if not url or url in seen:
            continue
        title = _result_title(block)
        snippet = _result_snippet(block)
        if not _matches_target(title, snippet, url, target, mode):
            continue
        seen.add(url)
        onions.append({"url": url, "title": title, "snippet": snippet})
    return onions, len(blocks)


def _is_search_page(url: str) -> bool:
    try:
        return "/search" in (urlsplit(url).path or "").lower()
    except ValueError:
        return False


def _rate_limited(status: int) -> BuiltinOutput:
    message = f"Ahmia rate-limited the search (HTTP {status})"
    return BuiltinOutput(exit_code=1, stderr=message,
                         error_code=ErrorCode.RATE_LIMITED, error_message=message)


def _unavailable(message: str) -> BuiltinOutput:
    return BuiltinOutput(exit_code=1, stderr=message,
                         error_code=ErrorCode.SPAWN_ERROR, error_message=message)


async def _execute(params: dict, timeout_sec: int) -> BuiltinOutput:
    domain = str(params.get("domain") or "").strip()
    email = str(params.get("email") or "").strip()
    username = str(params.get("username") or "").strip()
    clue = domain or email or username
    match_mode = "email" if email else ("username" if username else "domain")
    search_url = f"{AHMIA_SEARCH}?q={quote(clue, safe='')}"

    client = make_client(timeout_sec=timeout_sec, follow_redirects=True,
                         headers={"Accept": "text/html,application/xhtml+xml"})
    async with client:
        result = await fetch(client, search_url, max_bytes=MAX_HTML_BYTES)
        if result.error:
            return failure_output("darkweb_ahmia", result)
        if result.status_code in {403, 429}:
            return _rate_limited(result.status_code)

        token_used = False
        html = ""
        final_url = result.url or search_url
        status = result.status_code
        if 200 <= status < 300 and _is_search_page(final_url):
            html = result.body.decode("utf-8", errors="replace")
        else:
            if not 200 <= status < 300:
                return _unavailable(
                    f"Ahmia search returned HTTP {status} (index unavailable)")
            # The search redirected away (usually to the homepage): fetch the
            # homepage to obtain the dynamic hidden token, then retry once.
            home = await fetch(client, AHMIA_HOME, max_bytes=MAX_HTML_BYTES)
            if home.error:
                return failure_output("darkweb_ahmia homepage token", home)
            if not 200 <= home.status_code < 300:
                return _unavailable(
                    f"Ahmia homepage returned HTTP {home.status_code}; search blocked")
            token_name, token_value = _extract_search_token(
                home.body.decode("utf-8", errors="replace"))
            if not token_name:
                return _unavailable(
                    "Ahmia search redirected away and no anti-bot token was found")
            retry_url = (
                f"{AHMIA_SEARCH}?q={quote(clue, safe='')}"
                f"&{quote(token_name, safe='')}={quote(token_value, safe='')}"
            )
            retry = await fetch(client, retry_url, max_bytes=MAX_HTML_BYTES)
            if retry.error:
                return failure_output("darkweb_ahmia search retry", retry)
            if retry.status_code in {403, 429}:
                return _rate_limited(retry.status_code)
            if not 200 <= retry.status_code < 300:
                return _unavailable(
                    f"Ahmia search retry returned HTTP {retry.status_code}")
            if not _is_search_page(retry.url):
                return _unavailable(
                    "Ahmia redirected the search away from its results page")
            html = retry.body.decode("utf-8", errors="replace")
            final_url = retry.url
            status = retry.status_code
            token_used = True

    onions, block_count = _parse_results(html, clue, match_mode)
    payload = {
        "query": clue,
        "onions": onions,
        "evidence": {
            "search_url": final_url,
            "status": status,
            "token_used": token_used,
            "result_blocks": block_count,
            "onion_count": len(onions),
            "html_bytes": len(html),
            "params": {"domain": domain, "email": email, "username": username},
            "match_mode": match_mode,
        },
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Search the Ahmia clearnet index for ``.onion`` mentions of the target."""
    _ = scope  # ahmia.fi is a fixed passive source; no Tor connection is made
    params = params or {}
    domain = str(params.get("domain") or "").strip()
    email = str(params.get("email") or "").strip()
    username = str(params.get("username") or "").strip()
    if not domain and not email and not username:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: domain, email or username",
            error_message="darkweb_ahmia requires one of 'domain', 'email' or 'username'",
        )
    try:
        return await asyncio.wait_for(_execute(params, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"darkweb_ahmia timed out after {timeout_sec}s"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
