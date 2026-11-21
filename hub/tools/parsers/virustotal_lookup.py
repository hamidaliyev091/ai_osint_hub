"""Deterministic parser for the builtin VirusTotal API v3 collector.

Input (collector stdout)::

    {"target": "example.com", "target_type": "domain", "auth_status": "CONFIGURED",
     "domain": {"value": "example.com", "registrar": "RESERVED-...",
                "as_owner": "CLOUDFLARENET", "asn": 13335, "country": "US",
                "reputation": 0, "last_analysis_stats": {"malicious": 0, ...},
                "whois_date": 1149024000, "categories": {"sophos": "..."},
                "verdict": "harmless"},
     "ip": {},
     "subdomains": ["www.example.com"],
     "resolutions": [{"host_name": "example.com", "ip_address": "93.184.216.34",
                      "date": 1600000000}],
     "reputation": 0, "verdict": "harmless"}

Output: the queried DOMAIN/IP entity (reputation/verdict/ASN attributes),
SUBDOMAIN entities with ``SUBDOMAIN_OF domain``, IP entities from resolutions
with ``domain RESOLVES_TO ip``, ORGANIZATION entities for the registrar /
AS owner and a SERVICE entity recording the VirusTotal analysis verdict.
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
MAX_ITEMS = 40
MAX_TEXT = 200
_DOMAIN_RE = re.compile(r"^[\w.-]+\.[A-Za-z]{2,}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse VirusTotal collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"virustotal_lookup parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _clean_attributes(attributes: dict | None) -> dict:
    """Drop None/empty-string attributes; never emit HAS_ATTRIBUTE:* -> ""."""
    cleaned: dict = {}
    for key, value in (attributes or {}).items():
        if value is None:
            continue
        if isinstance(value, str):
            text = value.strip()
            if not text:
                continue
            cleaned[key] = text
        else:
            cleaned[key] = value
    return cleaned


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _target_entity_type(value: str, declared: str) -> EntityType:
    lowered = declared.strip().lower()
    if lowered == "ip":
        return EntityType.IP
    if lowered in {"domain", "subdomain"}:
        return EntityType.DOMAIN
    try:
        inferred = infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN
    return inferred if inferred in {EntityType.DOMAIN, EntityType.IP} else EntityType.DOMAIN


def _host_type(value: str) -> EntityType:
    """Resolutions/names are hostnames: IP or DOMAIN, never a crash."""
    value = value.strip()
    if _IPV4_RE.match(value):
        return EntityType.IP
    try:
        inferred = infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN
    return inferred if inferred in {EntityType.DOMAIN, EntityType.IP} else EntityType.DOMAIN


def _is_hostname(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value)) and not value.startswith("-")


def _record(data: dict, kind: str) -> dict:
    raw = data.get(kind)
    return raw if isinstance(raw, dict) else {}


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from virustotal_lookup: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected virustotal_lookup payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    target_value = _as_text(data.get("target") or target).lower().rstrip(".")
    declared_type = _as_text(data.get("target_type"))
    target_type = _target_entity_type(target_value, declared_type)
    record = _record(data, "domain" if target_type is EntityType.DOMAIN else "ip")
    reputation = _as_int(data.get("reputation", record.get("reputation")))
    verdict = _as_text(data.get("verdict") or record.get("verdict"))
    subdomains = data.get("subdomains") if isinstance(data.get("subdomains"), list) else []
    resolutions = data.get("resolutions") if isinstance(data.get("resolutions"), list) else []

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
            metadata=dict(metadata or {}),
            attributes=_clean_attributes(attributes),
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

    record_present = bool(record)
    if target_value:
        evidence = f"VirusTotal v3 {target_type.value} record for {target_value}"
        if verdict:
            evidence += f"; verdict={verdict}"
        if record.get("country"):
            evidence += f"; country={record.get('country')}"
        attributes = {
            "reputation": reputation,
            "verdict": verdict,
            "country": _as_text(record.get("country"))[:MAX_TEXT],
            "asn": record.get("asn") if record.get("asn") not in (None, "") else "",
            "as_owner": _as_text(record.get("as_owner"))[:MAX_TEXT],
            "registrar": _as_text(record.get("registrar"))[:MAX_TEXT],
        }
        add_entity(target_type, target_value,
                   0.85 if record_present else 0.70, evidence,
                   metadata={"source": "virustotal", "auth_status":
                             _as_text(data.get("auth_status"))},
                   attributes=attributes)

    if record_present:
        add_entity(EntityType.SERVICE, "virustotal", 0.75,
                   f"VirusTotal analysis for {target_value or 'target'}: "
                   f"verdict={verdict or 'unknown'} reputation={reputation}",
                   metadata={"kind": "analysis_source",
                             "categories": record.get("categories") or {},
                             "last_analysis_stats": record.get("last_analysis_stats") or {}},
                   attributes={"verdict": verdict, "reputation": reputation})
        if target_value:
            add_relation(target_type, target_value, EdgeType.ASSOCIATED_WITH,
                         EntityType.SERVICE, "virustotal", 0.70,
                         f"VirusTotal analysis exists for {target_value}")

        registrar = _as_text(record.get("registrar"))
        if registrar:
            registrar_evidence = f"VirusTotal registrar for {target_value}: {registrar}"
            add_entity(EntityType.ORGANIZATION, registrar, 0.75, registrar_evidence,
                       metadata={"source": "virustotal:registrar"})
            if target_value:
                add_relation(target_type, target_value, EdgeType.REGISTERED_BY,
                             EntityType.ORGANIZATION, registrar, 0.75,
                             registrar_evidence)
        as_owner = _as_text(record.get("as_owner"))
        if as_owner:
            owner_evidence = f"VirusTotal AS owner for {target_value}: {as_owner}"
            add_entity(EntityType.ORGANIZATION, as_owner, 0.75, owner_evidence,
                       metadata={"source": "virustotal:as_owner"})
            if target_value:
                add_relation(target_type, target_value, EdgeType.ASSOCIATED_WITH,
                             EntityType.ORGANIZATION, as_owner, 0.75, owner_evidence)

    for item in subdomains[:MAX_ITEMS]:
        subdomain = _as_text(item).lower().rstrip(".")
        if not subdomain or not _is_hostname(subdomain):
            continue
        evidence = f"VirusTotal subdomain of {target_value or 'domain'}: {subdomain}"
        add_entity(EntityType.SUBDOMAIN, subdomain, 0.80, evidence,
                   metadata={"source": "virustotal"})
        if target_value and target_type is EntityType.DOMAIN:
            add_relation(EntityType.SUBDOMAIN, subdomain, EdgeType.SUBDOMAIN_OF,
                         EntityType.DOMAIN, target_value, 0.80, evidence)

    for item in resolutions[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        host_name = _as_text(item.get("host_name")).lower().rstrip(".")
        ip_address = _as_text(item.get("ip_address"))
        date = item.get("date")
        if not host_name and not ip_address:
            continue
        evidence = (f"VirusTotal passive-DNS resolution: {host_name or '?'} -> "
                    f"{ip_address or '?'}" + (f" ({date})" if date else ""))
        if host_name and _is_hostname(host_name):
            add_entity(_host_type(host_name), host_name, 0.78, evidence,
                       metadata={"source": "virustotal:resolutions",
                                 "date": date})
        if ip_address:
            add_entity(EntityType.IP, ip_address, 0.82, evidence,
                       metadata={"source": "virustotal:resolutions", "date": date})
            if host_name:
                add_relation(_host_type(host_name), host_name, EdgeType.RESOLVES_TO,
                             EntityType.IP, ip_address, 0.82, evidence)

    if not record_present and not subdomains and not resolutions:
        warnings.append(f"no VirusTotal record found for {target_value or target or 'target'}")
    if not entities:
        warnings.append("no VirusTotal entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
