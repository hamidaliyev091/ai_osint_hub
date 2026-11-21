"""Deterministic parser for the builtin RDAP (WHOIS successor) collector.

Input (collector stdout)::

    {"target": "example.com", "kind": "domain", "handle": "2336799_DOMAIN_COM-VRSN",
     "ldth": "example.com",
     "events": [{"action": "registration", "date": "1995-08-14T04:00:00Z"}],
     "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
     "entities": [{"roles": ["registrar"], "org": "RESERVED-Internet Assigned Numbers Authority",
                   "emails": ["abuse@example.net"], "handle": "376"}],
     "found": true}

Output: the queried DOMAIN/IP entity (registration dates as attributes),
ORGANIZATION entities for registrars/registrants, EMAIL entities with
``organization HAS_EMAIL email``, ``domain REGISTERED_BY organization`` and
nameserver SUBDOMAIN entities related with ``ASSOCIATED_WITH``.
"""

from __future__ import annotations

import json
import re

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ITEMS = 100

_REGISTRANT_ROLES = {"registrar", "registrant"}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_EVENT_KEYS = {"registration", "expiration", "changed", "transfer", "database_updated"}


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse RDAP collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"rdap_lookup parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _target_type(value: str, kind: str) -> EntityType:
    if kind == "ip":
        return EntityType.IP
    try:
        inferred = infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN
    return inferred if inferred in {EntityType.DOMAIN, EntityType.IP} else EntityType.DOMAIN


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from rdap_lookup: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected rdap_lookup payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    returned_target = _as_text(data.get("target") or target).lower().rstrip(".")
    kind = _as_text(data.get("kind")).lower()
    handle = _as_text(data.get("handle"))
    ldth = _as_text(data.get("ldth")).lower().rstrip(".")
    found = bool(data.get("found"))
    events = data.get("events") if isinstance(data.get("events"), list) else []
    nameservers = data.get("nameservers") if isinstance(data.get("nameservers"), list) else []
    raw_entities = data.get("entities") if isinstance(data.get("entities"), list) else []

    target_type = _target_type(returned_target, kind)
    target_value = ldth or returned_target
    event_attributes: dict[str, str] = {}
    event_notes: list[str] = []
    for event in events[:MAX_ITEMS]:
        if not isinstance(event, dict):
            continue
        action = _as_text(event.get("action")).lower()
        date = _as_text(event.get("date"))
        if not action or not date:
            continue
        if action in _EVENT_KEYS:
            event_attributes[action] = date
            event_notes.append(f"{action}={date}")

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   evidence: str, *, metadata: dict | None = None,
                   attributes: dict | None = None) -> bool:
        value = _as_text(value)
        if not value:
            return False
        key = (entity_type.value, value.lower())
        if key in seen:
            return False
        seen.add(key)
        entities.append(EntityCandidate(
            type=entity_type, value=value, confidence=confidence,
            metadata=dict(metadata or {}), attributes=dict(attributes or {}),
            evidence=evidence[:MAX_EVIDENCE],
        ))
        return True

    def add_relation(subject_type: EntityType, subject_value: str,
                     predicate: EdgeType, object_type: EntityType,
                     object_value: str, confidence: float, evidence: str) -> None:
        if not _as_text(subject_value) or not _as_text(object_value):
            return
        relations.append(RelationCandidate(
            subject_type=subject_type, subject_value=subject_value,
            predicate=predicate, object_type=object_type,
            object_value=object_value, confidence=confidence,
            evidence=evidence[:MAX_EVIDENCE],
        ))

    if target_value:
        if found:
            target_evidence = f"RDAP record for {target_value}"
            if handle:
                target_evidence += f" handle={handle}"
            if event_notes:
                target_evidence += "; " + "; ".join(event_notes)
        else:
            target_evidence = f"RDAP lookup returned no registration record for {target_value}"
        add_entity(target_type, target_value, 0.85 if found else 0.70, target_evidence,
                   metadata={"source": "rdap", "kind": kind or target_type.value},
                   attributes={"handle": handle, **event_attributes})

    for record in raw_entities[:MAX_ITEMS]:
        if not isinstance(record, dict):
            continue
        roles = [str(role).strip().lower() for role in record.get("roles") or []
                 if str(role).strip()]
        organisation = _as_text(record.get("org"))
        role_label = ",".join(roles) or "entity"
        if organisation:
            org_evidence = f"RDAP {role_label} organization: {organisation}"
            add_entity(EntityType.ORGANIZATION, organisation, 0.75, org_evidence,
                       metadata={"rdap_roles": roles,
                                 "rdap_handle": _as_text(record.get("handle"))},
                       attributes={"roles": roles})
            if target_value:
                predicate = (EdgeType.REGISTERED_BY
                             if roles and set(roles) & _REGISTRANT_ROLES
                             else EdgeType.ASSOCIATED_WITH)
                add_relation(target_type, target_value, predicate,
                             EntityType.ORGANIZATION, organisation, 0.75,
                             f"RDAP {role_label} organization for {target_value}: {organisation}")
        raw_emails = record.get("emails") if isinstance(record.get("emails"), list) else []
        for address in raw_emails[:MAX_ITEMS]:
            email = _as_text(address).lower()
            if not _EMAIL_RE.match(email):
                continue
            email_evidence = f"RDAP {role_label} contact e-mail: {email}"
            add_entity(EntityType.EMAIL, email, 0.70, email_evidence,
                       metadata={"rdap_roles": roles})
            if organisation:
                add_relation(EntityType.ORGANIZATION, organisation,
                             EdgeType.HAS_EMAIL, EntityType.EMAIL, email, 0.65,
                             f"RDAP {role_label} contact {email} belongs to {organisation}")

    for server in nameservers[:MAX_ITEMS]:
        nameserver = _as_text(server).lower().rstrip(".")
        if not nameserver:
            continue
        ns_evidence = f"RDAP nameserver for {target_value or returned_target}: {nameserver}"
        add_entity(EntityType.SUBDOMAIN, nameserver, 0.70, ns_evidence,
                   metadata={"kind": "nameserver"})
        if target_value:
            add_relation(target_type, target_value, EdgeType.ASSOCIATED_WITH,
                         EntityType.SUBDOMAIN, nameserver, 0.70, ns_evidence)

    if not found:
        warnings.append(f"no RDAP registration record found for {returned_target or target}")
    if not target_value and not entities:
        warnings.append("no RDAP entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
