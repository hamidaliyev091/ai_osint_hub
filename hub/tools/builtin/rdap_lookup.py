"""Zero-auth RDAP (WHOIS successor) collector — domains and IP addresses.

The target itself is validated (domain syntax or IP literal) and never
contacted: the request goes to the public ``rdap.org`` bootstrap service, which
may redirect to the authoritative RDAP server for the TLD/RIR (redirects are
followed by httpx here, and only rdap.org URLs are constructed by this module).

The standard RDAP JSON is flattened into registrar/registrant organizations,
contact e-mail addresses, nameservers and the registration/expiration/changed
events. A 404 ("no RDAP service for this resource") is a valid empty result.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
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

RDAP_BASE = "https://rdap.org"
MAX_ENTITIES = 100
MAX_NAMESERVERS = 100
MAX_EVENTS = 20
MAX_EMAILS_PER_ENTITY = 10
MAX_ENTITY_DEPTH = 4

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_ACTION_MAP = {
    "registration": "registration",
    "expiration": "expiration",
    "last changed": "changed",
    "changed": "changed",
    "transfer": "transfer",
    "last update of rdap database": "database_updated",
}


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _classify_target(target: str) -> tuple[str, str]:
    """Return ``("domain"|"ip", normalised)`` or ``("", "")`` when invalid."""
    text = str(target or "").strip()
    if not text:
        return "", ""
    if "://" in text:
        text = extract_host(text)
    text = text.strip().strip("[]").strip().lower().rstrip(".")
    if not text:
        return "", ""
    try:
        return "ip", str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if _DOMAIN_RE.match(text):
        return "domain", text
    return "", ""


def _normalise_events(data: dict) -> list[dict]:
    events: list[dict] = []
    raw_events = data.get("events")
    if not isinstance(raw_events, list):
        return events
    for event in raw_events[:MAX_EVENTS]:
        if not isinstance(event, dict):
            continue
        action = _as_text(event.get("eventAction")).lower()
        date = _as_text(event.get("eventDate"))
        if not action:
            continue
        events.append({"action": _ACTION_MAP.get(action, action), "date": date})
    return events


def _normalise_nameservers(data: dict) -> list[str]:
    nameservers: list[str] = []
    raw_servers = data.get("nameservers")
    if not isinstance(raw_servers, list):
        return nameservers
    for server in raw_servers[:MAX_NAMESERVERS]:
        if not isinstance(server, dict):
            continue
        name = _as_text(server.get("ldhName") or server.get("unicodeName"))
        name = name.lower().rstrip(".")
        if name and name not in nameservers:
            nameservers.append(name)
    return nameservers


def _vcard_values(vcard: object) -> dict[str, list[str]]:
    """Extract ``org``/``fn``/``email`` values from an RDAP ``vcardArray``."""
    values: dict[str, list[str]] = {"org": [], "fn": [], "email": []}
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return values
    for entry in vcard[1]:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        name = _as_text(entry[0]).lower()
        raw_value = entry[3]
        items = raw_value if isinstance(raw_value, list) else [raw_value]
        for item in items:
            text = _as_text(item)
            if not text:
                continue
            if name == "org":
                values["org"].append(text)
            elif name in {"fn", "n"}:
                values["fn"].append(text)
            elif name in {"email", "contact-email"}:
                address = text.lower()
                if address not in values["email"]:
                    values["email"].append(address)
    return values


def _extract_entities(raw_entities: object, depth: int = 0) -> list[dict]:
    """Flatten RDAP entities (including nested ones) into role/org/email records."""
    entities: list[dict] = []
    if depth > MAX_ENTITY_DEPTH or not isinstance(raw_entities, list):
        return entities
    for entity in raw_entities[:MAX_ENTITIES]:
        if not isinstance(entity, dict):
            continue
        roles = [
            _as_text(role).lower()
            for role in entity.get("roles") or []
            if _as_text(role)
        ]
        vcard = _vcard_values(entity.get("vcardArray"))
        org = ""
        if vcard["org"]:
            org = vcard["org"][0]
        elif vcard["fn"]:
            org = vcard["fn"][0]
        emails = vcard["email"][:MAX_EMAILS_PER_ENTITY]
        handle = _as_text(entity.get("handle"))
        if org or emails:
            entities.append({"roles": roles, "org": org, "emails": emails, "handle": handle})
        entities.extend(_extract_entities(entity.get("entities"), depth + 1))
        if len(entities) >= MAX_ENTITIES:
            break
    return entities[:MAX_ENTITIES]


def _empty_payload(target: str, kind: str) -> dict:
    return {
        "target": target,
        "kind": kind,
        "handle": "",
        "ldth": "",
        "events": [],
        "nameservers": [],
        "entities": [],
        "found": False,
    }


async def _execute(target: str, timeout_sec: int) -> BuiltinOutput:
    kind, value = _classify_target(target)
    if not kind:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid target: {target!r}",
            error_message=f"rdap_lookup requires a domain or IP target, got {target!r}",
        )
    url = f"{RDAP_BASE}/{kind}/{quote(value, safe='')}"
    client = make_client(timeout_sec=timeout_sec, follow_redirects=True,
                         headers={"Accept": "application/rdap+json"})
    async with client:
        result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    if result.error:
        return failure_output("rdap_lookup", result)
    if result.status_code in {403, 429}:
        message = f"rdap.org rate-limited the lookup (HTTP {result.status_code})"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.RATE_LIMITED, error_message=message)
    if result.status_code == 404:
        return BuiltinOutput(stdout=json.dumps(_empty_payload(value, kind), sort_keys=True),
                             exit_code=0)
    if not 200 <= result.status_code < 300:
        message = f"rdap.org returned HTTP {result.status_code} for {value}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.SPAWN_ERROR, error_message=message)
    try:
        data = decode_json(result.body)
    except ValueError as exc:
        message = f"RDAP response could not be parsed: {exc}"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.PARSE_ERROR, error_message=message)
    if not isinstance(data, dict):
        message = "RDAP response was not a JSON object"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.PARSE_ERROR, error_message=message)

    payload = {
        "target": value,
        "kind": kind,
        "handle": _as_text(data.get("handle")),
        "ldth": _as_text(data.get("ldhName")).lower().rstrip("."),
        "events": _normalise_events(data),
        "nameservers": _normalise_nameservers(data),
        "entities": _extract_entities(data.get("entities")),
        "found": True,
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up public RDAP registration data for a domain or IP address."""
    _ = scope  # rdap.org is the only host contacted; target format is validated
    target = str((params or {}).get("target") or "").strip()
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="rdap_lookup requires a non-empty 'target'",
        )
    try:
        return await asyncio.wait_for(_execute(target, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"rdap_lookup timed out after {timeout_sec}s for {target}"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
