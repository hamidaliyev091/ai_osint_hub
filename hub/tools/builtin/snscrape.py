"""Python-native snscrape replacement (Phase 13).

The upstream ``snscrape`` CLI exits code 2 for Twitter/X because unauthenticated
guest tokens were removed, burning pivot budgets.  This native collector instead
queries real public JSON/web endpoints across high-signal developer, chess, cyber
and social platforms and emits JSONL records matching
``hub.tools.parsers.snscrape``:

    {"url": "<profile url>", "source": "gitlab", "user": {"username": "u",
     "displayname": "U", "profile_url": "<profile url>"}}

No API keys, no auth, fixed public hosts only. Individual platform failures are
warnings; the collector never raises and returns a clean EMPTY result when no
public profile is found.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Awaitable, Callable, Optional

from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import (
    MAX_JSON_BYTES,
    decode_json,
    fetch,
    make_client,
)

__all__ = ["collect"]

GITLAB_API = "https://gitlab.com/api/v4/users"
REDDIT_API = "https://www.reddit.com/user/{u}/about.json"
KEYBASE_API = "https://keybase.io/_/api/1.0/user/lookup.json"
HACKERNEWS_API = "https://hacker-news.firebaseio.com/v0/user/{u}.json"
LICHESS_API = "https://lichess.org/api/user/{u}"
CHESSCOM_API = "https://api.chess.com/pub/player/{u}"
DEVTO_API = "https://dev.to/api/users/by_username"
MASTODON_API = "https://mastodon.social/api/v1/accounts/lookup"
MEDIUM_PROFILE = "https://medium.com/@{u}"
MAX_RECORDS = 20
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}$")


def _record(platform: str, username: str, url: str,
            displayname: str = "", *, evidence: str = "") -> dict[str, Any]:
    return {
        "url": url,
        "source": platform,
        "user": {
            "username": username,
            "displayname": displayname or username,
            "profile_url": url,
        },
        "evidence": evidence or f"{platform}:{username}",
    }


async def _json(client, url: str) -> tuple[int, Any]:
    result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    if not result.ok or not 200 <= int(result.status_code) < 300:
        return int(result.status_code or 0), None
    try:
        return int(result.status_code), decode_json(result.body)
    except ValueError:
        return int(result.status_code), None


async def _gitlab(client, username: str) -> Optional[dict]:
    status, data = await _json(client, f"{GITLAB_API}?username={username}")
    if status == 200 and isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and str(item.get("username", "")).lower() == username.lower():
                url = str(item.get("web_url") or f"https://gitlab.com/{username}")
                return _record("gitlab", username, url, str(item.get("name") or ""))
    return None


async def _reddit(client, username: str) -> Optional[dict]:
    status, data = await _json(client, REDDIT_API.format(u=username))
    if status == 200 and isinstance(data, dict):
        payload = data.get("data")
        if isinstance(payload, dict) and payload.get("name"):
            url = str(payload.get("url") or f"https://www.reddit.com/user/{username}")
            return _record("reddit", username, url, str(payload.get("name") or ""))
    return None


async def _keybase(client, username: str) -> Optional[dict]:
    status, data = await _json(client, f"{KEYBASE_API}?username={username}")
    if status == 200 and isinstance(data, dict):
        them = data.get("them")
        if isinstance(them, list) and them and isinstance(them[0], dict):
            profile = them[0].get("profile") or {}
            display = str(profile.get("full_name") or username) if isinstance(profile, dict) else username
            return _record("keybase", username, f"https://keybase.io/{username}", display)
    return None


async def _hackernews(client, username: str) -> Optional[dict]:
    status, data = await _json(client, HACKERNEWS_API.format(u=username))
    if status == 200 and isinstance(data, dict) and data.get("id"):
        return _record("hackernews", username,
                       f"https://news.ycombinator.com/user?id={username}",
                       str(data.get("id") or ""))
    return None


async def _lichess(client, username: str) -> Optional[dict]:
    status, data = await _json(client, LICHESS_API.format(u=username))
    if status == 200 and isinstance(data, dict) and data.get("username"):
        return _record("lichess", username,
                       str(data.get("url") or f"https://lichess.org/@/{username}"),
                       str(data.get("username") or ""))
    return None


async def _chesscom(client, username: str) -> Optional[dict]:
    status, data = await _json(client, CHESSCOM_API.format(u=username.lower()))
    if status == 200 and isinstance(data, dict) and data.get("username"):
        return _record("chess.com", username,
                       str(data.get("url") or f"https://www.chess.com/member/{username}"),
                       str(data.get("name") or data.get("username") or ""))
    return None


async def _devto(client, username: str) -> Optional[dict]:
    status, data = await _json(client, f"{DEVTO_API}?url={username}")
    if status == 200 and isinstance(data, dict) and data.get("username"):
        return _record("dev.to", username,
                       str(data.get("url") or f"https://dev.to/{username}"),
                       str(data.get("name") or ""))
    return None


async def _mastodon(client, username: str) -> Optional[dict]:
    status, data = await _json(client, f"{MASTODON_API}?acct={username}")
    if status == 200 and isinstance(data, dict) and data.get("username"):
        return _record("mastodon", username,
                       str(data.get("url") or f"https://mastodon.social/@{username}"),
                       str(data.get("display_name") or ""))
    return None


async def _medium(client, username: str) -> Optional[dict]:
    result = await fetch(client, MEDIUM_PROFILE.format(u=username),
                         max_bytes=MAX_JSON_BYTES)
    if result.ok and int(result.status_code or 0) == 200:
        body = (result.body or b"").decode("utf-8", errors="ignore").lower()
        if username.lower() in body and "page not found" not in body:
            return _record("medium", username,
                           MEDIUM_PROFILE.format(u=username))
    return None


_PROBES: tuple[Callable[..., Awaitable[Optional[dict]]], ...] = (
    _gitlab, _reddit, _keybase, _hackernews, _lichess, _chesscom,
    _devto, _mastodon, _medium,
)


async def _execute(params: dict, timeout_sec: int) -> BuiltinOutput:
    username = str((params or {}).get("username") or "").strip().lstrip("@")
    if not username:
        return BuiltinOutput(exit_code=2, stderr="missing username",
                             error_message="snscrape requires a username")
    if not _USERNAME_RE.match(username):
        return BuiltinOutput(exit_code=2, stderr="invalid username",
                             error_message="snscrape username has invalid characters")

    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    client = make_client(timeout_sec=timeout_sec, follow_redirects=True)
    async with client:
        outcomes = await asyncio.gather(
            *[probe(client, username) for probe in _PROBES],
            return_exceptions=True,
        )
    for outcome in outcomes:
        if isinstance(outcome, BaseException):
            warnings.append(f"probe error: {type(outcome).__name__}")
        elif isinstance(outcome, dict):
            records.append(outcome)
    # Deterministic platform order, dedupe by URL.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda row: (row["source"], row["url"])):
        url = str(record.get("url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        unique.append(record)
        if len(unique) >= MAX_RECORDS:
            break
    stdout = "\n".join(json.dumps(row, sort_keys=True) for row in unique)
    return BuiltinOutput(stdout=stdout, stderr="; ".join(warnings)[:500],
                         exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Probe public platform APIs for a username and emit JSONL profile records."""
    _ = scope  # fixed public hosts only; no target-site access
    try:
        return await asyncio.wait_for(_execute(params, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"snscrape timed out after {timeout_sec}s"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
