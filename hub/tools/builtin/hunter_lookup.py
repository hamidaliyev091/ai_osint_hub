"""Hunter.io API v2 passive collector (domain email search + email verifier).

Requires the ``HUNTER_API_KEY`` secret, sent as the ``api_key`` query parameter;
the raw key is scrubbed from every error string this module emits. Domain
targets call ``/v2/domain-search`` (indexed e-mails, names, roles, LinkedIn) and
e-mail targets call ``/v2/email-verifier`` (deliverability). A 404/no-data
response is a valid empty result; every list and text field is bounded before
serialisation.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import quote, urlencode

from hub.credentials import CONFIGURED
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

HUNTER_API = "https://api.hunter.io/v2"
MAX_EMAILS = 25
MAX_TEXT = 300
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_MISSING_KEY_MESSAGE = (
    "Hunter API key not configured; use the Web UI API Keys drawer "
    "or 'python -m hub.cli auth set'"
)
_EMAIL_FIELDS = ("value", "type", "confidence", "first_name", "last_name",
                 "position", "linkedin", "phone_number")
_VERIFICATION_FIELDS = ("status", "result", "score", "regexp", "disposable",
                        "webmail")


def _api_key() -> str:
    """Resolve the key at call time (tests patch ``hub.credentials.get_secret``)."""
    from hub.credentials import get_secret

    return get_secret("hunter", "api_key")


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_bool(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


def _scrub(text: str, secret: str) -> str:
    """Remove the API key from any message that could have embedded it."""
    if secret:
        return text.replace(secret, "[REDACTED]")
    return text


def _scrubbed(output: BuiltinOutput, secret: str) -> BuiltinOutput:
    return BuiltinOutput(
        stdout=_scrub(output.stdout, secret),
        stderr=_scrub(output.stderr, secret),
        exit_code=output.exit_code,
        error_code=output.error_code,
        error_message=_scrub(output.error_message, secret),
    )


def _classify_target(target: str) -> tuple[str, str]:
    """Return ``("email"|"domain", normalised)`` or ``("", "")`` when invalid."""
    text = _as_text(target)
    if not text:
        return "", ""
    if "://" in text:
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(text)
            text = parts.path if parts.path.strip("/") else (parts.hostname or "")
        except ValueError:
            text = ""
    text = text.strip().strip("/")
    if "@" in text:
        address = text.lower()
        return ("email", address) if _EMAIL_RE.match(address) else ("", "")
    domain = text.strip("[]").strip().lower().rstrip(".")
    if _DOMAIN_RE.match(domain):
        return "domain", domain
    return "", ""


def _target_of(params: dict) -> str:
    data = params or {}
    for key in ("email", "target", "domain"):
        value = _as_text(data.get(key))
        if value:
            return value
    return ""


def _email_record(item: object) -> dict | None:
    if not isinstance(item, dict):
        return None
    address = _as_text(item.get("value") or item.get("email")).lower()
    if not address or not _EMAIL_RE.match(address):
        return None
    record: dict = {"value": address}
    for field in _EMAIL_FIELDS[1:]:
        value = item.get(field)
        if field == "confidence":
            record[field] = _as_int(value)
        else:
            record[field] = _as_text(value)[:MAX_TEXT]
    return record


def _emails(payload: object) -> list[dict]:
    data = payload.get("data") if isinstance(payload, dict) else None
    raw_emails = data.get("emails") if isinstance(data, dict) else data
    emails: list[dict] = []
    if not isinstance(raw_emails, list):
        return emails
    for item in raw_emails[:MAX_EMAILS]:
        record = _email_record(item)
        if record is not None:
            emails.append(record)
    return emails


def _verification(payload: object) -> dict:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        return {}
    verification: dict = {}
    for field in _VERIFICATION_FIELDS:
        if field not in data:
            continue
        value = data.get(field)
        if field == "score":
            verification[field] = _as_int(value)
        elif field in {"regexp", "disposable", "webmail"}:
            verification[field] = _as_bool(value)
        else:
            verification[field] = _as_text(value)[:MAX_TEXT]
    return verification


def _empty_payload(target: str, kind: str) -> dict:
    return {
        "target": target,
        "target_type": kind,
        "auth_status": CONFIGURED,
        "domain": "",
        "organization": "",
        "emails": [],
        "verification": {},
    }


def _status_error(result, secret: str) -> BuiltinOutput | None:
    if result.error:
        return _scrubbed(failure_output("hunter_lookup", result), secret)
    status = int(result.status_code)
    if status in {401, 403}:
        message = f"Hunter rejected the API key (HTTP {status})"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.AUTHORIZATION_REQUIRED,
                             error_message=message)
    if status == 429:
        message = "Hunter API rate limit reached (HTTP 429)"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.RATE_LIMITED, error_message=message)
    if not 200 <= status < 300:
        message = f"Hunter API returned HTTP {status}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.SPAWN_ERROR, error_message=message)
    return None


def _data_payload(data: object) -> dict:
    return data if isinstance(data, dict) else {}


async def _execute(kind: str, value: str, api_key: str,
                   timeout_sec: int) -> BuiltinOutput:
    encoded_key = quote(api_key, safe="")
    if kind == "email":
        url = (f"{HUNTER_API}/email-verifier?"
               f"{urlencode({'email': value, 'api_key': encoded_key})}")
        endpoint = "Hunter email-verifier API"
    else:
        url = (f"{HUNTER_API}/domain-search?"
               f"{urlencode({'domain': value, 'api_key': encoded_key, 'limit': 10})}")
        endpoint = "Hunter domain-search API"
    client = make_client(timeout_sec=timeout_sec, follow_redirects=True,
                         headers={"Accept": "application/json"})
    async with client:
        result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    error = _status_error(result, api_key)
    if error is not None:
        return error
    if result.status_code == 404:
        return BuiltinOutput(stdout=json.dumps(_empty_payload(value, kind),
                                               sort_keys=True), exit_code=0)
    try:
        data = decode_json(result.body)
    except ValueError as exc:
        message = f"{endpoint} response could not be parsed: {exc}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.PARSE_ERROR, error_message=message)
    payload = _empty_payload(value, kind)
    body = _data_payload(data.get("data") if isinstance(data, dict) else data)
    if kind == "email":
        domain = value.split("@", 1)[1] if "@" in value else ""
        payload["domain"] = domain
        payload["verification"] = _verification(data)
    else:
        payload["domain"] = _as_text(body.get("domain") or value).lower()
        payload["organization"] = _as_text(body.get("organization"))[:MAX_TEXT]
        payload["emails"] = _emails(data)
    notes = ""
    if isinstance(data, dict):
        raw_errors = data.get("errors")
        if isinstance(raw_errors, list) and raw_errors:
            first = raw_errors[0]
            detail = (_as_text(first.get("details") or first.get("id"))
                      if isinstance(first, dict) else _as_text(first))
            if detail:
                notes = _scrub(f"Hunter API note: {detail}", api_key)[:1000]
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True),
                         stderr=notes, exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up Hunter.io indexed e-mails for a domain or verify an e-mail address."""
    _ = scope  # only api.hunter.io is contacted; target is never fetched
    api_key = _api_key()
    if not api_key:
        return BuiltinOutput(exit_code=1, stderr=_MISSING_KEY_MESSAGE,
                             error_code=ErrorCode.AUTHORIZATION_REQUIRED,
                             error_message=_MISSING_KEY_MESSAGE)
    target = _target_of(params)
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: email or domain",
            error_message="hunter_lookup requires a non-empty 'email' or 'domain'",
        )
    kind, value = _classify_target(target)
    if not kind:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid target: {target!r}",
            error_message=f"hunter_lookup requires an email or domain target, got {target!r}",
        )
    try:
        return await asyncio.wait_for(
            _execute(kind, value, api_key, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"hunter_lookup timed out after {timeout_sec}s for {value}"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
