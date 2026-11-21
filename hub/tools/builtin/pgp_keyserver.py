"""Zero-auth OpenPGP keyserver index collector (HKP machine-readable format).

Queries the HKP ``op=index&options=mr`` endpoint of ``keys.openpgp.org`` first
and falls back to ``keyserver.ubuntu.com``. Only the *index* is fetched — no key
material is imported, no signature is verified and nothing is decrypted. UIDs
and bound e-mail addresses are extracted from the raw machine-readable lines
(``info:``/``pub:``/``uid:``).

An empty keyserver answer ("no key found") is a valid empty result; a 4xx after
the fallback is still a successful empty lookup, while transport errors / 5xx
are surfaced as classified collection failures.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import quote

from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import MAX_JSON_BYTES, fetch, make_client

__all__ = ["collect"]

PRIMARY_URL = "https://keys.openpgp.org/pks/lookup"
PRIMARY_LABEL = "keys.openpgp.org"
FALLBACK_URL = "https://keyserver.ubuntu.com/pks/lookup"
FALLBACK_LABEL = "keyserver.ubuntu.com"
MAX_PUB = 100
MAX_UIDS = 100

_ANGLE_EMAIL_RE = re.compile(r"<([^<>\s]+@[^<>\s]+)>")
_BARE_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def _as_int(value: object) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _split_uid(value: str) -> tuple[str, str]:
    """Split an OpenPGP UID into ``(name, email)``; either side may be empty."""
    text = str(value or "").strip()
    match = _ANGLE_EMAIL_RE.search(text)
    if match:
        email = match.group(1).strip().lower()
        name = re.sub(r"\s+", " ", text[:match.start()]).strip().strip("\"'")
        return name, email
    if _BARE_EMAIL_RE.match(text):
        return "", text.lower()
    return text, ""


def _parse_mr(text: str) -> dict:
    """Parse an HKP machine-readable index response into info/pub/uids."""
    info: dict[str, int] = {"version": 0, "count": 0}
    pubs: list[dict] = []
    uids: list[dict] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("info:") and len(pubs) == 0 and len(uids) == 0:
            parts = line.split(":")
            if len(parts) >= 3:
                info = {"version": _as_int(parts[1]) or 0, "count": _as_int(parts[2]) or 0}
        elif line.startswith("pub:"):
            if len(pubs) >= MAX_PUB:
                continue
            parts = line.split(":")
            if len(parts) < 5:
                continue
            pubs.append({
                "key_id": parts[1].strip().upper(),
                "algo": _as_int(parts[2]),
                "bits": _as_int(parts[3]),
                "created": _as_int(parts[4]),
                "expires": _as_int(parts[5]) if len(parts) > 5 else None,
                "flags": parts[6] if len(parts) > 6 else "",
                "raw": line[:400],
            })
        elif line.startswith("uid:"):
            if len(uids) >= MAX_UIDS:
                continue
            rest = line[4:]
            try:
                uid_value, created, expires, flags = rest.rsplit(":", 3)
            except ValueError:
                uid_value, created, expires, flags = rest, "", "", ""
            name, email = _split_uid(uid_value)
            uids.append({
                "uid": uid_value.strip()[:300],
                "name": name,
                "email": email,
                "created": _as_int(created) if created else None,
                "expires": _as_int(expires) if expires else None,
                "flags": flags,
                "raw": line[:500],
            })
    return {"info": info, "pub": pubs[:MAX_PUB], "uids": uids[:MAX_UIDS]}


def _mr_url(base: str, search: str) -> str:
    return f"{base}?op=index&options=mr&search={quote(search, safe='')}"


async def _fetch_index(client, base: str, search: str) -> tuple:
    result = await fetch(client, _mr_url(base, search), max_bytes=MAX_JSON_BYTES)
    parsed = None
    if result.ok and 200 <= result.status_code < 300:
        parsed = _parse_mr(result.body.decode("utf-8", errors="replace"))
    return result, parsed


def _has_data(parsed: dict | None) -> bool:
    return bool(parsed and (parsed.get("pub") or parsed.get("uids")))


def _failure_output(label: str, result) -> BuiltinOutput | None:
    """Classify an index request failure; None means "treat as empty answer"."""
    code = result.error_code
    if code is None and result.status_code in {403, 429}:
        code = ErrorCode.RATE_LIMITED
    if code is None and result.status_code >= 500:
        code = ErrorCode.SPAWN_ERROR
    if code is None:
        return None
    detail = result.error or f"HTTP {result.status_code}"
    message = f"{label} keyserver lookup failed: {detail}"
    return BuiltinOutput(exit_code=-1 if code == ErrorCode.TIMEOUT else 1,
                         stderr=message, error_code=code, error_message=message)


async def _execute(email: str, username: str, timeout_sec: int) -> BuiltinOutput:
    search = email or username
    client = make_client(timeout_sec=timeout_sec, follow_redirects=True,
                         headers={"Accept": "text/plain, */*"})
    async with client:
        primary, primary_parsed = await _fetch_index(client, PRIMARY_URL, search)
        chosen_source = PRIMARY_LABEL
        chosen = primary_parsed
        fallback = None
        if not _has_data(chosen):
            fallback, fallback_parsed = await _fetch_index(client, FALLBACK_URL, search)
            if _has_data(fallback_parsed):
                chosen_source = FALLBACK_LABEL
                chosen = fallback_parsed
            elif fallback_parsed is not None:
                chosen = fallback_parsed

    pubs = list((chosen or {}).get("pub") or [])
    uids = list((chosen or {}).get("uids") or [])
    evidence = {
        "search": search,
        "primary": PRIMARY_LABEL,
        "primary_status": primary.status_code,
        "primary_error": primary.error,
        "fallback_used": fallback is not None,
        "fallback_status": fallback.status_code if fallback is not None else None,
        "fallback_error": fallback.error if fallback is not None else "",
        "source": chosen_source if (pubs or uids) else "",
        "pub_count": len(pubs),
        "uid_count": len(uids),
        "info": (chosen or {}).get("info") or {},
    }
    if not pubs and not uids:
        failure = _failure_output(PRIMARY_LABEL, fallback or primary)
        if failure is not None:
            return failure
    payload = {
        "query": {"email": email, "username": username, "search": search},
        "source": evidence["source"],
        "pub": pubs,
        "uids": uids,
        "evidence": evidence,
    }
    notes: list[str] = []
    if fallback is not None:
        notes.append(f"primary keyserver unavailable; used {chosen_source}")
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True),
                         stderr="; ".join(notes)[:1000], exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up OpenPGP UIDs / bound e-mail addresses on public keyservers."""
    _ = scope  # public keyservers are fixed passive sources; no target-site access
    email = str((params or {}).get("email") or "").strip()
    username = str((params or {}).get("username") or "").strip().lstrip("@")
    if not email and not username:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: email or username",
            error_message="pgp_keyserver requires 'email' and/or 'username'",
        )
    if email and not _EMAIL_RE.match(email):
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid email: {email!r}",
            error_message=f"pgp_keyserver received an invalid email: {email!r}",
        )
    try:
        return await asyncio.wait_for(
            _execute(email, username, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"pgp_keyserver timed out after {timeout_sec}s"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
