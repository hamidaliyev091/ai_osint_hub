"""Deterministic parser for the builtin Shodan API collector.

Input (collector stdout)::

    {"target": "1.2.3.4", "target_type": "ip", "auth_status": "CONFIGURED",
     "ip": "1.2.3.4", "domain": "", "ports": [443],
     "hostnames": ["www.example.com"], "subdomains": [], "records": [],
     "org": "Example Org", "isp": "Example ISP", "asn": "AS12345",
     "data": [{"port": 443, "transport": "tcp", "module": "https",
               "product": "nginx", "version": "1.18", "banner": "HTTP/1.1 ..."}]}

Output: the scanned IP entity (ASN/org attributes), PORT entities
(``443/tcp``) and SERVICE entities (``nginx:443/tcp``) linked with
``ASSOCIATED_WITH`` (the model has no HAS_PORT predicate), SUBDOMAIN entities
with ``SUBDOMAIN_OF domain`` and ORGANIZATION entities for org/ISP.
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
    """Parse Shodan collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"shodan_lookup parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_int(value: object, default: int = -1) -> int:
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
    if _IPV4_RE.match(value):
        return EntityType.IP
    try:
        inferred = infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN
    return inferred if inferred in {EntityType.DOMAIN, EntityType.IP} else EntityType.DOMAIN


def _is_hostname(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from shodan_lookup: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected shodan_lookup payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    target_value = _as_text(data.get("target") or target).lower().rstrip(".")
    declared_type = _as_text(data.get("target_type"))
    target_type = _target_entity_type(target_value, declared_type)
    ip_value = _as_text(data.get("ip")).lower()
    domain = _as_text(data.get("domain")).lower().rstrip(".")
    base_domain = domain or (target_value if target_type is EntityType.DOMAIN else "")
    ports = data.get("ports") if isinstance(data.get("ports"), list) else []
    hostnames = data.get("hostnames") if isinstance(data.get("hostnames"), list) else []
    subdomains = data.get("subdomains") if isinstance(data.get("subdomains"), list) else []
    services = data.get("data") if isinstance(data.get("data"), list) else []
    org = _as_text(data.get("org"))
    isp = _as_text(data.get("isp"))
    asn = _as_text(data.get("asn"))

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

    scan_ip = ip_value or (target_value if target_type is EntityType.IP else "")
    if scan_ip:
        evidence = (f"Shodan host record for {scan_ip}"
                    + (f"; org={org}" if org else "")
                    + (f"; isp={isp}" if isp else "")
                    + (f"; asn={asn}" if asn else ""))
        add_entity(EntityType.IP, scan_ip, 0.85, evidence,
                   metadata={"source": "shodan"},
                   attributes={"asn": asn, "org": org, "isp": isp})

    for item in services[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        port = _as_int(item.get("port"))
        if port < 0:
            continue
        transport = _as_text(item.get("transport") or "tcp").lower() or "tcp"
        module = _as_text(item.get("module"))[:MAX_TEXT]
        product = _as_text(item.get("product"))[:MAX_TEXT]
        version = _as_text(item.get("version"))[:MAX_TEXT]
        banner = _as_text(item.get("banner"))[:MAX_TEXT]
        service_name = product or module or "unknown"
        port_value = f"{port}/{transport}"
        service_value = f"{service_name.lower()}:{port_value}"
        evidence = (f"Shodan service banner {service_value}"
                    + (f" version={version}" if version else "")
                    + (f": {banner}" if banner else ""))
        port_attributes = {"port": port, "protocol": transport,
                           "service_name": service_name,
                           "module": module, "product": product,
                           "version": version, "banner": banner}
        add_entity(EntityType.PORT, port_value, 0.85, evidence,
                   metadata={"source": "shodan", **port_attributes},
                   attributes=port_attributes)
        add_entity(EntityType.SERVICE, service_value, 0.82, evidence,
                   metadata={"source": "shodan", **port_attributes},
                   attributes=port_attributes)
        if scan_ip:
            add_relation(EntityType.IP, scan_ip, EdgeType.ASSOCIATED_WITH,
                         EntityType.PORT, port_value, 0.85, evidence)
            add_relation(EntityType.IP, scan_ip, EdgeType.ASSOCIATED_WITH,
                         EntityType.SERVICE, service_value, 0.82, evidence)

    for port in ports[:MAX_ITEMS]:
        number = _as_int(port)
        if number < 0:
            continue
        port_value = f"{number}/tcp"
        evidence = f"Shodan reported open port {port_value} for {scan_ip or target_value or 'host'}"
        add_entity(EntityType.PORT, port_value, 0.80, evidence,
                   metadata={"source": "shodan", "port": number,
                             "protocol": "tcp", "state": "open"})
        if scan_ip:
            add_relation(EntityType.IP, scan_ip, EdgeType.ASSOCIATED_WITH,
                         EntityType.PORT, port_value, 0.80, evidence)

    hostname_values = [_as_text(item).lower().rstrip(".")
                       for item in hostnames[:MAX_ITEMS]]
    subdomain_values = [_as_text(item).lower().rstrip(".")
                        for item in subdomains[:MAX_ITEMS]]
    for hostname in hostname_values + subdomain_values:
        if not hostname or not _is_hostname(hostname):
            continue
        evidence = f"Shodan hostname for {scan_ip or base_domain or 'host'}: {hostname}"
        add_entity(EntityType.SUBDOMAIN, hostname, 0.75, evidence,
                   metadata={"source": "shodan"})
        if base_domain and hostname != base_domain and hostname.endswith("." + base_domain):
            add_relation(EntityType.SUBDOMAIN, hostname, EdgeType.SUBDOMAIN_OF,
                         EntityType.DOMAIN, base_domain, 0.75, evidence)

    for organisation in (org, isp):
        if not organisation:
            continue
        evidence = f"Shodan organization/ISP for {scan_ip or target_value or 'host'}: {organisation}"
        add_entity(EntityType.ORGANIZATION, organisation, 0.75, evidence,
                   metadata={"source": "shodan"})
        if scan_ip:
            add_relation(EntityType.IP, scan_ip, EdgeType.ASSOCIATED_WITH,
                         EntityType.ORGANIZATION, organisation, 0.75, evidence)
        elif base_domain:
            add_relation(EntityType.DOMAIN, base_domain, EdgeType.ASSOCIATED_WITH,
                         EntityType.ORGANIZATION, organisation, 0.70, evidence)

    if not services:
        warnings.append("no Shodan service banners parsed")
    if not entities:
        warnings.append("no Shodan entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
