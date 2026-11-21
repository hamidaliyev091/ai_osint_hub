"""Deterministic parser for the builtin Wayback CDX collector.

Input (collector stdout)::

    {"target": "example.com", "query": {"url_param": "example.com/*"},
     "rows": [{"url": "http://example.com/", "timestamp": "19980818030244",
               "status": "200", "mimetype": "text/html"}],
     "subdomains": ["blog.example.com"]}

Output: URL entities for archived pages (timestamp/status/mimetype as
attributes) and SUBDOMAIN entities with ``SUBDOMAIN_OF domain`` relations.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ITEMS = 100


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse Wayback CDX collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"wayback_cdx parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _host_of(value: str) -> str:
    try:
        parts = urlsplit(str(value or ""))
    except ValueError:
        return ""
    if not parts.hostname and "://" not in str(value or ""):
        return _as_text(value).lower().strip("/")
    return (parts.hostname or "").strip().lower().rstrip(".")


def _domain_type(value: str) -> EntityType:
    try:
        inferred = infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN
    return inferred if inferred in {EntityType.DOMAIN, EntityType.SUBDOMAIN} else EntityType.DOMAIN


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from wayback_cdx: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected wayback_cdx payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    target_value = _as_text(data.get("target") or target)
    base_host = _host_of(target_value)
    if not base_host and target_value and "://" not in target_value:
        base_host = target_value.lower().strip("/")
    rows = data.get("rows") if isinstance(data.get("rows"), list) else []
    subdomains = data.get("subdomains") if isinstance(data.get("subdomains"), list) else []

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

    for row in rows[:MAX_ITEMS]:
        if not isinstance(row, dict):
            continue
        url = _as_text(row.get("url"))
        if not url:
            continue
        timestamp = _as_text(row.get("timestamp"))
        status = _as_text(row.get("status"))
        mimetype = _as_text(row.get("mimetype"))
        evidence = (
            f"Wayback capture {timestamp or '?'} (status {status or '?'}"
            f", {mimetype or 'unknown type'}): {url}"
        )
        add_entity(EntityType.URL, url, 0.75, evidence,
                   metadata={"source": "wayback_cdx"},
                   attributes={"timestamp": timestamp, "status": status,
                               "mimetype": mimetype})

    domain_type = _domain_type(base_host) if base_host else EntityType.DOMAIN
    for subdomain in subdomains[:MAX_ITEMS]:
        value = _as_text(subdomain).lower().rstrip(".")
        if not value:
            continue
        evidence = f"Wayback archived URL exposes subdomain {value}"
        if base_host:
            evidence += f" of {base_host}"
        add_entity(EntityType.SUBDOMAIN, value, 0.70, evidence,
                   metadata={"source": "wayback_cdx"})
        if base_host:
            relations.append(RelationCandidate(
                subject_type=EntityType.SUBDOMAIN, subject_value=value,
                predicate=EdgeType.SUBDOMAIN_OF, object_type=domain_type,
                object_value=base_host, confidence=0.70,
                evidence=evidence[:MAX_EVIDENCE],
            ))

    if not entities:
        warnings.append("no Wayback archive entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
