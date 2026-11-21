"""Parse amass stdout into the v2 ParseOutput contract.

amass v4 defaults to the OAM graph text format on stdout::

    example.com (FQDN) --> ns_record --> hera.ns.cloudflare.com (FQDN)
    hera.ns.cloudflare.com (FQDN) --> a_record --> 173.245.58.162 (IPAddress)
    13335 (ASN) --> managed_by --> CLOUDFLARE (RIROrganization)

JSONL records (older amass ``-json`` output) are also supported::

    {"name":"www.example.com","domain":"example.com",
     "addresses":[{"ip":"93.184.216.34","asn":15133}]}

Subdomains are related to their parent domain with ``SUBDOMAIN_OF``, FQDNs to
resolved addresses with ``RESOLVES_TO``, peer FQDNs with ``ASSOCIATED_WITH`` and
ASNs to their RIR organization. Plain hostname lines are a final fallback.
Pure and deterministic; never raises.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Optional

from hub.erkg.resolution import split_hostname
from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]

_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)

# amass v4 default stdout is the OAM graph format:
#   example.com (FQDN) --> ns_record --> hera.ns.cloudflare.com (FQDN)
#   hera.ns.cloudflare.com (FQDN) --> a_record --> 173.245.58.162 (IPAddress)
#   13335 (ASN) --> managed_by --> CLOUDFLARE (RIROrganization)
_OAM_RE = re.compile(
    r"^(?P<subject>.+?)\s+\((?P<subject_kind>[A-Za-z]+)\)\s+-->\s+"
    r"(?P<predicate>[A-Za-z0-9_]+)\s+-->\s+(?P<object>.+?)\s+\((?P<object_kind>[A-Za-z]+)\)$",
)


def _normalise_asn(value: str) -> str:
    digits = re.sub(r"[^0-9]", "", value or "")
    return f"AS{digits}" if digits else ""


def _parse_oam_line(line: str, fallback_parent: str, add_host, add_entity,
                    add_relation) -> bool:
    """Parse one amass v4 OAM graph line. Returns True if the line was consumed."""
    match = _OAM_RE.match(line)
    if match is None:
        return False
    subject = match.group("subject").strip()
    subject_kind = match.group("subject_kind").strip().lower()
    predicate = match.group("predicate").strip().lower()
    obj = match.group("object").strip()
    object_kind = match.group("object_kind").strip().lower()
    consumed = False

    if subject_kind == "fqdn" and _HOST_RE.match(subject):
        hostname, is_subdomain, parent = add_host(subject, fallback_parent, line)
        if not hostname:
            return False
        subject_type = EntityType.SUBDOMAIN if is_subdomain else EntityType.DOMAIN
        consumed = True
        if object_kind == "fqdn" and _HOST_RE.match(obj):
            add_host(obj, fallback_parent, line)
            add_relation(subject_type, hostname, EdgeType.ASSOCIATED_WITH,
                         EntityType.DOMAIN, obj, line, 0.85,
                         {"record": predicate})
            return True
        if object_kind == "ipaddress":
            ip_value = _normalise_ip(obj)
            if ip_value:
                add_entity(EntityType.IP, ip_value, line, 0.85,
                           {"record": predicate, "hostname": hostname})
                add_relation(subject_type, hostname, EdgeType.RESOLVES_TO,
                             EntityType.IP, ip_value, line, 0.85,
                             {"record": predicate})
            return True
        return True

    if subject_kind == "asn":
        asn = _normalise_asn(subject)
        if not asn:
            return False
        add_entity(EntityType.ASN, asn, line, 0.80, {"declared": subject})
        consumed = True
        if object_kind in ("rirorganization", "organization"):
            add_entity(EntityType.ORGANIZATION, obj, line, 0.75,
                       {"asn": asn, "role": "rir_organization"})
            add_relation(EntityType.ASN, asn, EdgeType.ASSOCIATED_WITH,
                         EntityType.ORGANIZATION, obj, line, 0.75,
                         {"relationship": predicate})
        return True

    # Netblock / other structural nodes carry no canonical ERKG entity: consume
    # the line silently to avoid it being parsed as a bare hostname.
    if subject_kind in ("netblock", "ipaddress"):
        return True
    return consumed


def _base_domain(target: str) -> str:
    text = (target or "").strip().lower()
    if not text:
        return ""
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/")[0].split(":")[0].strip().strip(".")
    if text.startswith("www."):
        text = text[4:]
    return text if _HOST_RE.match(text) else ""


def _parent_domain(name: str) -> str:
    parts = name.split(".")
    if len(parts) >= 3:
        return ".".join(parts[1:])
    return ""


def _normalise_ip(value: Any) -> str:
    text = str(value or "").strip().strip("[](),;")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse amass JSONL/text stdout. Never raises; empty/garbage input warns."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["amass: empty stdout"])

    fallback_parent = _base_domain(target)
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str]] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, evidence: str,
                   confidence: float, metadata: Optional[dict] = None) -> bool:
        key = (entity_type.value, value.lower())
        if key in seen_entities:
            return False
        seen_entities.add(key)
        entities.append(EntityCandidate(
            type=entity_type,
            value=value,
            confidence=confidence,
            metadata=metadata or {},
            evidence=evidence,
        ))
        return True

    def add_relation(s_type: EntityType, s_value: str, predicate: EdgeType,
                     o_type: EntityType, o_value: str, evidence: str,
                     confidence: float, metadata: Optional[dict] = None) -> None:
        key = (predicate.value, s_value.lower(), o_value.lower())
        if key in seen_relations:
            return
        seen_relations.add(key)
        relations.append(RelationCandidate(
            subject_type=s_type,
            subject_value=s_value,
            predicate=predicate,
            object_type=o_type,
            object_value=o_value,
            confidence=confidence,
            evidence=evidence,
            metadata=metadata or {},
        ))

    def add_host(name: str, parent: str, evidence: str,
                 metadata: Optional[dict] = None) -> tuple[str, bool, str]:
        raw = name.strip().lower().rstrip(".")
        if not _HOST_RE.match(raw):
            return "", False, ""
        # Preserve the raw FQDN as the entity value (ERKG canonicalization strips
        # `www.` later); use ERKG hostname classification for Domain vs Subdomain.
        parts = split_hostname(raw)
        if parts is None:
            hostname, registrable, split_is_sub = raw, "", False
        else:
            _normalized, registrable, split_is_sub = parts
            hostname = raw
        supplied_parent = (parent or "").strip().lower().rstrip(".")
        if supplied_parent and (hostname == supplied_parent
                                or hostname.endswith("." + supplied_parent)):
            parent = supplied_parent
        else:
            parent = registrable
        if not parent:
            parent = fallback_parent
        is_subdomain = (bool(parent) and hostname != parent
                        and hostname.endswith("." + parent))
        entity_type = EntityType.SUBDOMAIN if is_subdomain else EntityType.DOMAIN
        host_metadata = dict(metadata or {})
        if parent:
            host_metadata["parent_domain"] = parent
        add_entity(entity_type, name, evidence, 0.85, host_metadata)
        if is_subdomain:
            add_relation(EntityType.SUBDOMAIN, name, EdgeType.SUBDOMAIN_OF,
                         EntityType.DOMAIN, parent, evidence, 0.85)
        return name, is_subdomain, parent

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # amass v4 default stdout: OAM graph triples.
        if "-->" in stripped:
            _parse_oam_line(stripped, fallback_parent, add_host, add_entity,
                            add_relation)
            continue
        record: Optional[dict] = None
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                record = parsed
        except (json.JSONDecodeError, ValueError):
            record = None

        if record is None:
            add_host(stripped, fallback_parent, stripped, {"discovery": "amass_text"})
            continue

        name = str(record.get("name") or "").strip()
        if not name:
            continue
        metadata = {"source": "amass_json"}
        sources = [str(item) for item in (record.get("sources") or []) if item]
        if sources:
            metadata["sources"] = sources
        hostname, is_subdomain, parent = add_host(
            name, str(record.get("domain") or "").strip(), stripped, metadata)
        if not hostname:
            continue
        addresses = record.get("addresses") or []
        if not isinstance(addresses, list):
            continue
        host_type = EntityType.SUBDOMAIN if is_subdomain else EntityType.DOMAIN
        for address in addresses:
            if not isinstance(address, dict):
                continue
            ip_value = _normalise_ip(address.get("ip"))
            if not ip_value:
                continue
            ip_metadata = {"hostname": hostname, "source": "amass_json"}
            if address.get("asn") is not None:
                ip_metadata["asn"] = address.get("asn")
            if address.get("cidr"):
                ip_metadata["cidr"] = address.get("cidr")
            add_entity(EntityType.IP, ip_value, stripped, 0.80, ip_metadata)
            add_relation(host_type, hostname, EdgeType.RESOLVES_TO,
                         EntityType.IP, ip_value, stripped, 0.80,
                         {"asn": address.get("asn")})

    if not entities:
        return ParseOutput(warnings=["amass: no subdomains or addresses recognised"])
    return ParseOutput(entities=entities, relations=relations)
