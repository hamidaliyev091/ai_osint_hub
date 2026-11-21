"""Zero-auth Gravatar profile collector (email -> public JSON profile).

Gravatar identifies profiles by the MD5 of the normalised (trimmed, lowercase)
e-mail address. The preferred JSON profile endpoint
``https://gravatar.com/<md5>.json`` is queried first; when it 404s the avatar
endpoint ``?d=404`` distinguishes "profile exists" from "no profile". A missing
profile is a *valid empty result* (exit code 0, ``exists: false``), never an
error.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re

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

PROFILE_URL = "https://gravatar.com/{hash}.json"
AVATAR_URL = "https://www.gravatar.com/avatar/{hash}?d=404"
MAX_ACCOUNTS = 50
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_verified(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return _as_text(value).lower() == "true"


def _first_photo(entry: dict) -> str:
    photos = entry.get("photos")
    if isinstance(photos, list):
        for photo in photos:
            if isinstance(photo, dict):
                value = _as_text(photo.get("value"))
                if value:
                    return value
            elif isinstance(photo, str) and photo.strip():
                return photo.strip()
    return ""


def _normalise_profile(entry: dict) -> dict:
    """Flatten the Gravatar ``entry[0]`` object into the collector schema."""
    name = entry.get("name")
    formatted = _as_text(name.get("formatted")) if isinstance(name, dict) else ""
    accounts: list[dict] = []
    raw_accounts = entry.get("accounts")
    if isinstance(raw_accounts, list):
        for account in raw_accounts[:MAX_ACCOUNTS]:
            if not isinstance(account, dict):
                continue
            accounts.append({
                "shortname": _as_text(account.get("shortname")
                                      or account.get("domain")),
                "username": _as_text(account.get("username")
                                     or account.get("display")),
                "url": _as_text(account.get("url")),
                "verified": _as_verified(account.get("verified")),
            })
    return {
        "displayName": _as_text(entry.get("displayName")) or formatted,
        "preferredUsername": _as_text(entry.get("preferredUsername")),
        "aboutMe": _as_text(entry.get("aboutMe")),
        "profileUrl": _as_text(entry.get("profileUrl")),
        "thumbnailUrl": _as_text(entry.get("thumbnailUrl")) or _first_photo(entry),
        "accounts": accounts,
    }


def _empty_profile() -> dict:
    return {
        "displayName": "",
        "preferredUsername": "",
        "aboutMe": "",
        "profileUrl": "",
        "thumbnailUrl": "",
        "accounts": [],
    }


async def _lookup(client, md5: str) -> tuple[dict, bool, BuiltinOutput | None]:
    """Return ``(profile, exists, error_output)``; a 404 is resolved via the avatar probe."""
    profile_result = await fetch(client, PROFILE_URL.format(hash=md5),
                                 max_bytes=MAX_JSON_BYTES)
    if profile_result.error:
        return _empty_profile(), False, failure_output(
            "gravatar_lookup profile request", profile_result)
    status = profile_result.status_code
    if status in {403, 429}:
        message = f"Gravatar rate-limited the profile request (HTTP {status})"
        return _empty_profile(), False, BuiltinOutput(
            exit_code=1, stderr=message,
            error_code=ErrorCode.RATE_LIMITED, error_message=message)
    if 200 <= status < 300:
        try:
            data = decode_json(profile_result.body)
        except ValueError as exc:
            message = f"Gravatar profile response could not be parsed: {exc}"
            return _empty_profile(), False, BuiltinOutput(
                exit_code=1, stderr=message,
                error_code=ErrorCode.PARSE_ERROR, error_message=message)
        entries = data.get("entry") if isinstance(data, dict) else None
        if isinstance(entries, list) and entries and isinstance(entries[0], dict):
            return _normalise_profile(entries[0]), True, None
        # 200 without an entry is treated as "no profile".
        return _empty_profile(), False, None
    if status != 404:
        message = f"Gravatar profile endpoint returned HTTP {status}"
        return _empty_profile(), False, BuiltinOutput(
            exit_code=1, stderr=message,
            error_code=ErrorCode.SPAWN_ERROR, error_message=message)

    avatar_result = await fetch(client, AVATAR_URL.format(hash=md5), max_bytes=4096)
    if not avatar_result.error and 200 <= avatar_result.status_code < 300:
        return _empty_profile(), True, None  # profile exists, JSON not exposed
    return _empty_profile(), False, None


async def _execute(email: str, timeout_sec: int) -> BuiltinOutput:
    normalised = email.strip().lower()
    md5 = hashlib.md5(normalised.encode("utf-8")).hexdigest()
    sha256 = hashlib.sha256(normalised.encode("utf-8")).hexdigest()
    client = make_client(timeout_sec=timeout_sec, follow_redirects=True,
                         headers={"Accept": "application/json"})
    async with client:
        profile, exists, error = await _lookup(client, md5)
    if error is not None:
        return error
    payload = {
        "email": email.strip(),
        "md5": md5,
        "sha256": sha256,
        "exists": exists,
        "profile": profile,
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up the public Gravatar profile for an e-mail address."""
    _ = scope  # gravatar.com is a fixed passive source; no target-site access
    email = str((params or {}).get("email") or "").strip()
    if not email:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: email",
            error_message="gravatar_lookup requires a non-empty 'email'",
        )
    if not _EMAIL_RE.match(email):
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid email: {email!r}",
            error_message=f"gravatar_lookup received an invalid email: {email!r}",
        )
    try:
        return await asyncio.wait_for(_execute(email, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"gravatar_lookup timed out after {timeout_sec}s"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
