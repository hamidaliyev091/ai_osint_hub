"""Deterministic parser for the builtin Hunter.io API v2 collector.

Input (collector stdout)::

    {"target": "example.com", "target_type": "domain",
     "auth_status": "CONFIGURED", "domain": "example.com",
     "organization": "Example Inc",
     "emails": [{"value": "john@example.com", "type": "personal",
                 "confidence": 95, "first_name": "John", "last_name": "Doe",
                 "position": "CEO", "linkedin": "https://www.linkedin.com/in/johndoe",
                 "phone_number": "+1 555 0100"}],
     "verification": {}}

Output: EMAIL entities (deliverability/confidence attributes), PERSON entities
(full name), ORGANIZATION entities and SOCIAL_PROFILE entities for LinkedIn
profiles; ``person HAS_EMAIL email``, ``email ASSOCIATED_WITH domain`` and
``person ASSOCIATED_WITH organization/social_profile`` relations.
"""

from __future__ import annotations

import json
import re

from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ITEMS = 25
MAX_TEXT = 200
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_VERIFICATION_KEYS = ("status", "result", "score", "regexp", "disposable", "webmail")


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse Hunter.io collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"hunter_lookup parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _target_entity_type(value: str, declared: str) -> EntityType:
    lowered = declared.strip().lower()
    if lowered == "email":
        return EntityType.EMAIL
    if lowered in {"domain", "subdomain"}:
        return EntityType.DOMAIN
    try:
        inferred = infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN
    return inferred if inferred in {EntityType.EMAIL, EntityType.DOMAIN} else EntityType.DOMAIN


def _email_confidence(confidence: int, *, verified: bool = False) -> float:
    if verified:
        return 0.90
    if confidence >= 90:
        return 0.88
    return 0.80


def _full_name(first_name: str, last_name: str) -> str:
    return " ".join(part for part in (first_name.strip(), last_name.strip()) if part)


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from hunter_lookup: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected hunter_lookup payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    target_value = _as_text(data.get("target") or target).lower()
    declared_type = _as_text(data.get("target_type"))
    target_type = _target_entity_type(target_value, declared_type)
    domain = _as_text(data.get("domain")).lower().rstrip(".")
    if not domain and "@" in target_value:
        domain = target_value.split("@", 1)[1]
    organization = _as_text(data.get("organization"))[:MAX_TEXT]
    emails = data.get("emails") if isinstance(data.get("emails"), list) else []
    verification = data.get("verification") if isinstance(data.get("verification"), dict) else {}

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str]] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   evidence: str, *, metadata: dict | None = None,
                   attributes: dict | None = None) -> bool:
        value = _as_text(value)
        if not value:
            return False
        key = (entity_type.value, value.lower())
        if key in seen_entities:
            return False
        seen_entities.add(key)
        entities.append(EntityCandidate(
            type=entity_type, value=value, confidence=confidence,
            metadata=dict(metadata or {}), attributes=dict(attributes or {}),
            evidence=evidence[:MAX_EVIDENCE],
        ))
        return True

    def add_relation(subject_type: EntityType, subject_value: str,
                     predicate: EdgeType, object_type: EntityType,
                     object_value: str, confidence: float, evidence: str) -> None:
        subject_value = _as_text(subject_value)
        object_value = _as_text(object_value)
        if not subject_value or not object_value:
            return
        key = (subject_value.lower(), predicate.value, object_value.lower())
        if key in seen_relations:
            return
        seen_relations.add(key)
        relations.append(RelationCandidate(
            subject_type=subject_type, subject_value=subject_value,
            predicate=predicate, object_type=object_type,
            object_value=object_value, confidence=confidence,
            evidence=evidence[:MAX_EVIDENCE],
        ))

    if target_type is EntityType.EMAIL and _EMAIL_RE.match(target_value):
        verified = _as_text(verification.get("status")).lower() in {"valid", "deliverable"}
        verification_attributes = {key: verification[key] for key in
                                   _VERIFICATION_KEYS if key in verification}
        evidence = (f"Hunter.io e-mail verification for {target_value}"
                    + (f"; status={_as_text(verification.get('status'))}"
                       if verification.get("status") else "")
                    + (f"; score={verification.get('score')}"
                       if verification.get("score") not in (None, "") else ""))
        add_entity(EntityType.EMAIL, target_value,
                   _email_confidence(_as_int(verification.get("score")), verified=verified),
                   evidence, metadata={"source": "hunter:email-verifier"},
                   attributes={"verification": verification_attributes,
                               "confidence": _as_int(verification.get("score"))})
        if domain:
            add_relation(EntityType.EMAIL, target_value, EdgeType.ASSOCIATED_WITH,
                         EntityType.DOMAIN, domain, 0.80,
                         f"Hunter.io e-mail {target_value} belongs to {domain}")

    for item in emails[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        address = _as_text(item.get("value")).lower()
        if not address or not _EMAIL_RE.match(address):
            continue
        first_name = _as_text(item.get("first_name"))[:MAX_TEXT]
        last_name = _as_text(item.get("last_name"))[:MAX_TEXT]
        position = _as_text(item.get("position"))[:MAX_TEXT]
        linkedin = _as_text(item.get("linkedin"))
        phone_number = _as_text(item.get("phone_number"))[:MAX_TEXT]
        email_type = _as_text(item.get("type"))[:MAX_TEXT]
        confidence = _as_int(item.get("confidence"))
        person_name = _full_name(first_name, last_name)
        evidence = (f"Hunter.io indexed e-mail {address}"
                    + (f"; name={person_name}" if person_name else "")
                    + (f"; position={position}" if position else "")
                    + (f"; confidence={confidence}" if confidence else "")
                    + (f"; type={email_type}" if email_type else ""))
        add_entity(EntityType.EMAIL, address, _email_confidence(confidence), evidence,
                   metadata={"source": "hunter:domain-search", "type": email_type},
                   attributes={"type": email_type, "confidence": confidence,
                               "first_name": first_name, "last_name": last_name,
                               "position": position, "linkedin": linkedin,
                               "phone_number": phone_number})
        if domain:
            add_relation(EntityType.EMAIL, address, EdgeType.ASSOCIATED_WITH,
                         EntityType.DOMAIN, domain, 0.80,
                         f"Hunter.io indexed e-mail {address} for {domain}")
        if person_name:
            person_evidence = ("Hunter.io employee " + person_name
                               + (f"; position={position}" if position else "")
                               + (f"; e-mail={address}" if address else ""))
            add_entity(EntityType.PERSON, person_name, 0.80, person_evidence,
                       metadata={"source": "hunter:domain-search"},
                       attributes={"position": position, "linkedin": linkedin,
                                   "phone_number": phone_number})
            add_relation(EntityType.PERSON, person_name, EdgeType.HAS_EMAIL,
                         EntityType.EMAIL, address, 0.80, person_evidence)
            if organization:
                add_relation(EntityType.PERSON, person_name,
                             EdgeType.ASSOCIATED_WITH, EntityType.ORGANIZATION,
                             organization, 0.72, person_evidence)
            if linkedin:
                social_value = linkedin if _URL_RE.match(linkedin) else f"https://{linkedin.lstrip('/')}"
                social_evidence = f"Hunter.io LinkedIn profile for {person_name}: {social_value}"
                add_entity(EntityType.SOCIAL_PROFILE, social_value, 0.75,
                           social_evidence, metadata={"source": "hunter:linkedin"})
                add_relation(EntityType.PERSON, person_name, EdgeType.ASSOCIATED_WITH,
                             EntityType.SOCIAL_PROFILE, social_value, 0.75,
                             social_evidence)

    if organization:
        evidence = f"Hunter.io organization for {domain or target_value or 'target'}: {organization}"
        add_entity(EntityType.ORGANIZATION, organization, 0.75, evidence,
                   metadata={"source": "hunter"})
        if target_type is EntityType.DOMAIN and domain:
            add_relation(EntityType.DOMAIN, domain, EdgeType.ASSOCIATED_WITH,
                         EntityType.ORGANIZATION, organization, 0.70, evidence)

    if not entities:
        warnings.append("no Hunter.io entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
