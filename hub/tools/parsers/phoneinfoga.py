"""Parse phoneinfoga stdout into the v2 ParseOutput contract.

phoneinfoga reports carrier / location intelligence for a phone number::

    [+] Carrier: AT&T Mobility
    [+] Location: California, United States

The target phone yields ``phone REGISTERED_BY organization`` (carrier) and
``phone LOCATED_IN location`` relations.  Both inline ``Label: value`` and
section + list-item output styles are supported.  Pure and deterministic.
"""

from __future__ import annotations

import re

from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

_CARRIER_LABEL_RE = re.compile(r"carrier(?:s)?\s*:\s*(.*)$", re.IGNORECASE)
_LOCATION_LABEL_RE = re.compile(r"\blocation\s*:\s*(.*)$", re.IGNORECASE)
_COUNTRY_LABEL_RE = re.compile(r"\bcountry\s*:\s*(.*)$", re.IGNORECASE)
_LIST_ITEM_RE = re.compile(r"^[-*+]\s+(.+)$")
_VALID_RE = re.compile(r"\bvalid\s*:\s*(true|yes)\b", re.IGNORECASE)
_VALID_FALSE_RE = re.compile(r"\bvalid\s*:\s*(false|no)\b", re.IGNORECASE)
_STRUCTURED_PHONE_RE = re.compile(
    r"\b(?:country|local|e164|international|carrier|location)\s*:\s*([^\r\n]+)",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(r"\+?\d[\d\s().-]{6,}\d")
_NOISE_VALUES = {"", "unknown", "not found", "n/a", "none", "null", "error", "-"}


def _subject(target: str) -> tuple[EntityType, str]:
    """Resolve the relation subject type/value for the CLI target."""
    text = (target or "").strip()
    if not text:
        return EntityType.PHONE, ""
    try:
        found = infer_value_type(text)
    except ValueError:
        return EntityType.PHONE, text
    return (found if found is EntityType.PHONE else EntityType.PHONE), text


def _clean(value: str) -> str:
    text = str(value or "").strip().strip("\"'").strip()
    if text.lower() in _NOISE_VALUES:
        return ""
    return text[:200]


def _find_phone(text: str) -> str:
    for match in _PHONE_RE.finditer(text):
        digits = re.sub(r"[^\d+]", "", match.group(0))
        if len(re.sub(r"\D", "", digits)) >= 7:
            return digits
    return ""


def _evidence_line(text: str, needle: str) -> str:
    for line in text.splitlines():
        if needle in line:
            return line.strip()
    return ""


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse phoneinfoga stdout. Never raises; empty/garbage input warns."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["phoneinfoga: empty stdout"])

    subject_type, subject_value = _subject(target)
    if not subject_value:
        subject_value = _find_phone(text)
        subject_type = EntityType.PHONE
    elif not subject_value.startswith("+"):
        subject_value = _find_phone(text) or subject_value

    carriers: list[tuple[str, str]] = []
    locations: list[tuple[str, str, str]] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        label = _CARRIER_LABEL_RE.search(stripped)
        if label:
            value = _clean(label.group(1))
            if value:
                carriers.append((value, stripped))
                current = ""
            else:
                current = "carrier"
            continue
        label = _LOCATION_LABEL_RE.search(stripped)
        if label:
            value = _clean(label.group(1))
            if value:
                locations.append((value, stripped, "location"))
                current = ""
            else:
                current = "location"
            continue
        label = _COUNTRY_LABEL_RE.search(stripped)
        if label:
            value = _clean(label.group(1))
            if value:
                locations.append((value, stripped, "country"))
                current = ""
            else:
                current = "location"
            continue
        item = _LIST_ITEM_RE.match(stripped)
        if item and current:
            value = _clean(item.group(1))
            if value:
                if current == "carrier":
                    carriers.append((value, stripped))
                else:
                    locations.append((value, stripped, "location"))
            continue
        current = ""

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str]] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   metadata: dict, evidence: str,
                   attributes: dict | None = None) -> bool:
        key = (entity_type.value, value.lower())
        if key in seen_entities:
            return False
        seen_entities.add(key)
        entities.append(EntityCandidate(
            type=entity_type,
            value=value,
            confidence=confidence,
            metadata=metadata,
            evidence=evidence,
            attributes=attributes or {},
        ))
        return True

    def add_relation(predicate: EdgeType, object_type: EntityType,
                     object_value: str, evidence: str,
                     confidence: float) -> None:
        key = (predicate.value, subject_value.lower(), object_value.lower())
        if key in seen_relations:
            return
        seen_relations.add(key)
        relations.append(RelationCandidate(
            subject_type=subject_type,
            subject_value=subject_value,
            predicate=predicate,
            object_type=object_type,
            object_value=object_value,
            confidence=confidence,
            evidence=evidence,
        ))

    if subject_value:
        phone_evidence = _evidence_line(text, subject_value.lstrip("+")) or ""
        attributes: dict[str, object] = {}
        if _VALID_FALSE_RE.search(text):
            attributes["valid"] = False
        elif _VALID_RE.search(text):
            attributes["valid"] = True
        else:
            structured_hit = any(_clean(m.group(1)) for m in _STRUCTURED_PHONE_RE.finditer(text))
            if structured_hit:
                attributes["valid"] = True
        add_entity(EntityType.PHONE, subject_value, 0.90,
                   {"target": target or subject_value}, phone_evidence, attributes)

    # Prefer explicit "Location:" over "Country:" when both are present.
    explicit_locations = [entry for entry in locations if entry[2] == "location"]
    selected_locations = explicit_locations or locations
    for carrier, evidence in carriers:
        if add_entity(EntityType.ORGANIZATION, carrier, 0.85,
                      {"phone": subject_value, "kind": "carrier"}, evidence,
                      {"carrier": True}):
            if subject_value:
                add_relation(EdgeType.REGISTERED_BY, EntityType.ORGANIZATION,
                             carrier, evidence, 0.85)
    for location, evidence, _kind in selected_locations:
        if add_entity(EntityType.LOCATION, location, 0.70,
                      {"phone": subject_value}, evidence):
            if subject_value:
                add_relation(EdgeType.LOCATED_IN, EntityType.LOCATION,
                             location, evidence, 0.70)

    if not entities:
        return ParseOutput(warnings=["phoneinfoga: no carrier/location data recognised"])
    return ParseOutput(entities=entities, relations=relations)
