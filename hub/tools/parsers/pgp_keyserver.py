"""Deterministic parser for the builtin OpenPGP keyserver collector.

Input (collector stdout)::

    {"query": {"email": "john@example.com", "username": "", "search": "john@example.com"},
     "source": "keys.openpgp.org",
     "pub": [{"key_id": "93D2...", "algo": 1, "bits": 4096, "created": ...}],
     "uids": [{"uid": "John Doe <john@example.com>", "name": "John Doe",
               "email": "john@example.com", "raw": "uid:John Doe <john@example.com>:..."}]}

Output: PERSON entities from UID real names, EMAIL entities from UID addresses
and ``person HAS_EMAIL email`` relations. Machine-readable raw HKP lines are
used as evidence. Keys without machine-readable UIDs yield an empty parse with
warnings (the key fingerprints alone are not identity evidence).
"""

from __future__ import annotations

import json
import re

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 500
MAX_ITEMS = 100

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse keyserver collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"pgp_keyserver parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from pgp_keyserver: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected pgp_keyserver payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    query = data.get("query") if isinstance(data.get("query"), dict) else {}
    queried_email = _as_text(query.get("email") or target).lower()
    uids = data.get("uids") if isinstance(data.get("uids"), list) else []
    pubs = data.get("pub") if isinstance(data.get("pub"), list) else []
    key_ids = [
        _as_text(pub.get("key_id")).upper()
        for pub in pubs[:MAX_ITEMS]
        if isinstance(pub, dict) and _as_text(pub.get("key_id"))
    ]

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen: set[tuple[str, str]] = set()
    person_names: list[str] = []

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
        relations.append(RelationCandidate(
            subject_type=subject_type, subject_value=subject_value,
            predicate=predicate, object_type=object_type,
            object_value=object_value, confidence=confidence,
            evidence=evidence[:MAX_EVIDENCE],
        ))

    for uid in uids[:MAX_ITEMS]:
        if not isinstance(uid, dict):
            continue
        uid_text = _as_text(uid.get("uid"))
        name = _as_text(uid.get("name"))
        email = _as_text(uid.get("email")).lower()
        raw = _as_text(uid.get("raw")) or f"uid:{uid_text}"
        if email and not _EMAIL_RE.match(email):
            email = ""
        if not name and not email:
            warnings.append(f"dropped unparseable UID line: {raw[:120]}")
            continue
        if name:
            evidence = f"OpenPGP UID: {raw}" if raw.startswith("uid:") else raw
            if add_entity(EntityType.PERSON, name, 0.70, evidence,
                          metadata={"pgp_uid": uid_text, "source": "pgp_keyserver"},
                          attributes={"pgp_uid": uid_text}):
                person_names.append(name)
        if email:
            evidence = f"OpenPGP UID e-mail: {raw}" if raw.startswith("uid:") else raw
            add_entity(EntityType.EMAIL, email, 0.80, evidence,
                       metadata={"source": "pgp_keyserver"})
            if name:
                add_relation(EntityType.PERSON, name, EdgeType.HAS_EMAIL,
                             EntityType.EMAIL, email, 0.70,
                             f"OpenPGP UID binds {name} to {email}: {raw}")

    if key_ids and person_names:
        attributes = {"pgp_key_ids": key_ids[:10]}
        for entity in entities:
            if entity.type is EntityType.PERSON:
                entity.attributes.update(attributes)
                if pubs and isinstance(pubs[0], dict):
                    entity.metadata["pgp_key_evidence"] = _as_text(pubs[0].get("raw"))[:200]

    if queried_email and not any(
            entity.type is EntityType.EMAIL and entity.value.lower() == queried_email
            for entity in entities):
        warnings.append(f"keyserver response did not bind the queried e-mail {queried_email}")
    if not entities:
        if pubs:
            warnings.append(
                f"keyserver returned {len(pubs)} public key(s) but no machine-readable UIDs")
        else:
            warnings.append("no OpenPGP UID/email entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
