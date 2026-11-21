"""Python-native passive site crawler (Photon-style) — SSRF-guarded.

Fetches the root page plus ``/robots.txt`` and ``/sitemap.xml`` of a public web
target (each body bounded to ~200 KB) and extracts links, e-mail addresses,
subdomains, social profiles, JavaScript endpoints and cloud-storage buckets.

Redirects are handled manually: httpx never follows them (``follow_redirects``
is disabled) and every hop's host is validated with
:func:`hub.security.policy.assert_safe_host` before it is requested (max 3
hops), so a public page cannot bounce the collector into private address space.

A 2xx/404/robots.txt failure still yields a successful *partial* result; only a
total transport failure is reported as a collection error. The collector never
raises.
"""

from __future__ import annotations

import asyncio
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

__all__ = ["collect"]

MAX_ITEMS = 100
PAGE_URL_LIMIT = 15
_STATIC_EXTENSIONS = {
    "css", "js", "mjs", "map", "svg", "png", "jpg", "jpeg", "gif", "ico",
    "webp", "avif", "bmp", "woff", "woff2", "ttf", "eot", "otf", "mp4",
    "mp3", "pdf", "zip",
}
_CDN_ASSET_HOSTS = {
    "code.jquery.com", "cdnjs.cloudflare.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "cdn.jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com",
}

_HREF_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'`=<>]+))""",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_MAILTO_RE = re.compile(r"mailto:([^\"'?\s>]+)", re.IGNORECASE)
_S3_REGION_RE = re.compile(r"^s3[.-][a-z0-9-]+\.amazonaws\.com$", re.IGNORECASE)

SOCIAL_HOSTS = (
    "github.com", "gitlab.com", "twitter.com", "x.com", "instagram.com",
    "facebook.com", "fb.com", "linkedin.com", "youtube.com", "youtu.be",
    "tiktok.com", "t.me", "telegram.me", "discord.gg", "reddit.com",
    "medium.com", "threads.net", "mastodon.social", "keybase.io", "about.me",
    "twitch.tv", "pinterest.com", "snapchat.com", "vk.com",
)
BUCKET_HOST_SUFFIXES = (
    "s3.amazonaws.com", ".storage.googleapis.com",
    ".blob.core.windows.net", ".digitaloceanspaces.com",
)
_IMAGE_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "woff",
    "woff2", "ttf", "eot", "mp4", "webm", "pdf", "avif",
}


def _normalise_target(target: str) -> tuple[str, str]:
    """Return ``(root_url, base_host)`` for a domain or URL target."""
    text = str(target or "").strip()
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


def _append(bucket: list[str], value: str) -> None:
    if value and value not in bucket and len(bucket) < MAX_ITEMS:
        bucket.append(value)


def _append_page(urls: list[str], value: str) -> None:
    """Keep at most PAGE_URL_LIMIT high-signal HTML page URLs."""
    if value and value not in urls and len(urls) < PAGE_URL_LIMIT:
        urls.append(value)


def _is_static_asset(host: str, path: str) -> bool:
    lowered_path = (path or "").lower().rstrip(".")
    extension = lowered_path.rsplit(".", 1)[-1] if "." in lowered_path else ""
    if extension in _STATIC_EXTENSIONS:
        return True
    host = (host or "").lower()
    return any(host == cdn or host.endswith("." + cdn)
               for cdn in _CDN_ASSET_HOSTS)


def _valid_email(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text or text.count("@") != 1:
        return False
    _, _, domain = text.partition("@")
    tld = domain.rsplit(".", 1)[-1]
    return bool(domain) and "." in domain and tld not in _IMAGE_TLDS


def _is_social(host: str) -> bool:
    return any(host == entry or host.endswith("." + entry) for entry in SOCIAL_HOSTS)


def _is_bucket(host: str) -> bool:
    if any(host == suffix.lstrip(".") or host.endswith(suffix)
           for suffix in BUCKET_HOST_SUFFIXES):
        return True
    return bool(_S3_REGION_RE.match(host))


def _extract_from_text(text: str, page_url: str, base_host: str,
                       urls: list[str], emails: list[str], subdomains: list[str],
                       social: list[str], js_endpoints: list[str],
                       buckets: list[str]) -> None:
    """Extract every observable artefact from one fetched page/body."""
    page_url = page_url or f"https://{base_host}/"
    for match in _MAILTO_RE.finditer(text):
        candidate = unescape(match.group(1)).strip().lower()
        if _valid_email(candidate):
            _append(emails, candidate)
    for match in _EMAIL_RE.finditer(text):
        candidate = match.group(0).strip().lower()
        if _valid_email(candidate):
            _append(emails, candidate)

    raw_candidates = [
        match.group(1) or match.group(2) or match.group(3) or ""
        for match in _HREF_RE.finditer(text)
    ]
    raw_candidates.extend(match.group(0) for match in _URL_RE.finditer(text))
    for raw in raw_candidates:
        cleaned = unescape(raw).strip().strip("'\"<> ")
        if not cleaned or cleaned.startswith(("#", "javascript:", "data:", "tel:")):
            continue
        if cleaned.lower().startswith("mailto:"):
            candidate = cleaned[7:].split("?")[0].strip().lower()
            if _valid_email(candidate):
                _append(emails, candidate)
            continue
        try:
            parts = urlsplit(urljoin(page_url, cleaned))
        except ValueError:
            continue
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            continue
        host = (parts.hostname or "").strip().lower().rstrip(".")
        full_url = parts._replace(fragment="").geturl()
        path = (parts.path or "").lower()

        if path.endswith(".js"):
            _append(js_endpoints, full_url)
        if _is_social(host):
            _append(social, full_url)
        if _is_bucket(host):
            _append(buckets, full_url)
        if base_host and host != base_host and host.endswith("." + base_host):
            _append(subdomains, host)
        # Never emit static theme/media/script assets as URL entities; only
        # high-signal internal HTML pages up to the per-run cap.
        if _is_static_asset(host, path):
            continue
        if base_host and (host == base_host or host.endswith("." + base_host)):
            _append_page(urls, full_url)


async def _crawl(target: str, root_url: str, base_host: str, timeout_sec: int) -> BuiltinOutput:
    client = make_client(timeout_sec=timeout_sec, follow_redirects=False)
    async with client:
        root = await fetch_safe(client, root_url, validate=assert_safe_host,
                                max_bytes=MAX_BODY_BYTES)
        if root.error_code == ErrorCode.SCOPE_BLOCKED:
            return failure_output("photon_crawler root fetch blocked by SSRF guard", root)
        base_origin = origin_of(root.url) or origin_of(root_url)
        robots_url = f"{base_origin}/robots.txt" if base_origin else "/robots.txt"
        sitemap_url = f"{base_origin}/sitemap.xml" if base_origin else "/sitemap.xml"
        robots = await fetch_safe(client, robots_url, validate=assert_safe_host,
                                  max_bytes=MAX_BODY_BYTES)
        sitemap = await fetch_safe(client, sitemap_url, validate=assert_safe_host,
                                   max_bytes=MAX_BODY_BYTES)

    pages = [(root_url, root), (robots_url, robots), (sitemap_url, sitemap)]
    errors = [result for _, result in pages if result.error]
    if len(errors) == len(pages):
        return failure_output("photon_crawler: all page fetches failed", root)

    urls: list[str] = []
    root_page = root.url or root_url
    if root_page.lower().startswith(("http://", "https://")):
        try:
            root_path = urlsplit(root_page).path or "/"
            root_host = (urlsplit(root_page).hostname or "").lower()
        except ValueError:
            root_path, root_host = "/", ""
        if not _is_static_asset(root_host, root_path):
            _append_page(urls, root_page)
    emails: list[str] = []
    subdomains: list[str] = []
    social: list[str] = []
    js_endpoints: list[str] = []
    buckets: list[str] = []
    for fetch_url, result in pages:
        if result.error or not result.body:
            continue
        text = result.body.decode("utf-8", errors="replace")
        _extract_from_text(text, result.url or fetch_url, base_host, urls, emails,
                           subdomains, social, js_endpoints, buckets)

    payload = {
        "target": target,
        "base_host": base_host,
        "urls": urls,
        "emails": emails,
        "subdomains": subdomains,
        "social_profiles": social,
        "js_endpoints": js_endpoints,
        "buckets": buckets,
        "evidence": {
            "base_host": base_host,
            "final_url": root.url or root_url,
            "redirect_chain": list(root.hops),
            "pages": [
                {
                    "url": fetch_url,
                    "status": result.status_code,
                    "bytes": len(result.body),
                    "truncated": result.truncated,
                    "error": result.error,
                }
                for fetch_url, result in pages
            ],
            "counts": {
                "urls": len(urls),
                "emails": len(emails),
                "subdomains": len(subdomains),
                "social_profiles": len(social),
                "js_endpoints": len(js_endpoints),
                "buckets": len(buckets),
            },
        },
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Crawl the root page, ``robots.txt`` and ``sitemap.xml`` of a public target."""
    _ = scope  # host scope is enforced by the SSRF guard and the runtime policy gate
    target = str((params or {}).get("target") or "").strip()
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="photon_crawler requires a non-empty 'target'",
        )
    root_url, base_host = _normalise_target(target)
    if not root_url or not base_host:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid target: {target!r}",
            error_message=f"photon_crawler received an invalid target: {target!r}",
        )
    safe, reason = await asyncio.to_thread(assert_safe_host, base_host)
    if not safe:
        return BuiltinOutput(exit_code=-1, stderr=reason,
                             error_code=ErrorCode.SCOPE_BLOCKED,
                             error_message=reason)
    try:
        result = await asyncio.wait_for(
            _crawl(target, root_url, base_host, timeout_sec), timeout=timeout_sec
        )
    except (asyncio.TimeoutError, TimeoutError):
        message = f"photon_crawler timed out after {timeout_sec}s for {base_host}"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
    return result
