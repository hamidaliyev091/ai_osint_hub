"""Deterministic parser for the builtin Censys Platform API collector.

Input (collector stdout)::

    {"target": "1.2.3.4", "target_type": "ip", "auth_status": "CONFIGURED",
     "host": {"ip": "1.2.3.4", "location": "Mountain View, US", "asn": "AS15169",
              "organization": "GOOGLE", "names": ["dns.google"],
              "reverse_dns": "dns.google",
              "services": [{"port": 443, "transport_protocol": "tcp",
                            "service_name": "nginx",
                            "cert_names": ["*.example.com", "example.com"],
                            "cert_subject_cn": "example.com"}],
              "certificates": [{"fingerprint_sha256": "abc",
                                "names": ["example.com"], "subject_cn": "example.com"}]},
     "hosts": [...same shape...],
     "services": [...aggregated...], "certificates": [...aggregated...],
     "subdomains": ["www.example.com"], "asn": "AS15169",
     "organization": "GOOGLE", "errors": [], "warnings": []}

Output: the queried IP entity (ASN/organization/location attributes), PORT
entities (``443/tcp``) and SERVICE entities linked with ``ASSOCIATED_WITH``
(the model has no HAS_PORT predicate), SUBDOMAIN entities for certificate/DNS
names under the target domain (``SUBDOMAIN_OF domain``) and ORGANIZATION
entities from the ASN description / whois organization.
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
    """Parse Censys collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"censys_lookup parser error: {type(exc).__name__}: {exc}"],
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


def _is_hostname(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def _as_int_port(value: object) -> int:
    return _as_int(value)


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from censys_lookup: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected censys_lookup payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    target_value = _as_text(data.get("target") or target).lower().rstrip(".")
    declared_type = _as_text(data.get("target_type"))
    target_type = _target_entity_type(target_value, declared_type)
    hosts = data.get("hosts") if isinstance(data.get("hosts"), list) else []
    if not hosts and isinstance(data.get("host"), dict) and data.get("host"):
        hosts = [data["host"]]
    services = data.get("services") if isinstance(data.get("services"), list) else []
    certificates = (data.get("certificates")
                    if isinstance(data.get("certificates"), list) else [])
    subdomains = data.get("subdomains") if isinstance(data.get("subdomains"), list) else []
    asn = _as_text(data.get("asn"))
    organization = _as_text(data.get("organization"))
    for note in (data.get("errors") if isinstance(data.get("errors"), list) else []):
        if note:
            warnings.append(f"Censys collector note: {_as_text(note)}"[:MAX_EVIDENCE])
    for note in (data.get("warnings") if isinstance(data.get("warnings"), list) else []):
        if note:
            warnings.append(_as_text(note)[:MAX_EVIDENCE])

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

    host_ip = ""
    if target_type is EntityType.IP:
        host_ip = target_value
        for host in hosts[:MAX_ITEMS]:
            if isinstance(host, dict) and _as_text(host.get("ip")):
                host_ip = _as_text(host["ip"])
                break
        location = ""
        names: list[str] = []
        for host in hosts[:MAX_ITEMS]:
            if not isinstance(host, dict):
                continue
            location = location or _as_text(host.get("location"))
            names.extend(_as_text(name) for name in host.get("names") or []
                         if _as_text(name))
        evidence = (f"Censys Platform host asset for {host_ip}"
                    + (f"; asn={asn}" if asn else "")
                    + (f"; organization={organization}" if organization else "")
                    + (f"; location={location}" if location else ""))
        add_entity(EntityType.IP, host_ip, 0.85, evidence,
                   metadata={"source": "censys", "auth_status":
                             _as_text(data.get("auth_status"))},
                   attributes={"asn": asn, "organization": organization,
                               "location": location[:MAX_TEXT],
                               "names": [name for name in names
                                         if _is_hostname(name)][:MAX_ITEMS]})

    if not services:
        for host in hosts[:MAX_ITEMS]:
            if isinstance(host, dict) and isinstance(host.get("services"), list):
                services.extend(service for service in host["services"]
                                if isinstance(service, dict))

    host_subject = host_ip or (target_value if target_type is EntityType.DOMAIN else "")
    for item in services[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        port = _as_int_port(item.get("port"))
        if port < 0:
            continue
        transport = _as_text(item.get("transport_protocol")
                             or item.get("transport") or "tcp").lower() or "tcp"
        service_name = _as_text(item.get("service_name")
                                or item.get("protocol") or "unknown")
        cert_names = [name for name in (item.get("cert_names")
                                        if isinstance(item.get("cert_names"), list)
                                        else []) if _as_text(name)]
        cert_subject_cn = _as_text(item.get("cert_subject_cn"))
        port_value = f"{port}/{transport}"
        service_value = f"{service_name.lower()}:{port_value}"
        evidence = (f"Censys Platform service {service_value}"
                    + (f"; certificate CN={cert_subject_cn}" if cert_subject_cn else "")
                    + (f"; names={', '.join(cert_names[:5])}" if cert_names else ""))
        port_attributes = {"port": port, "protocol": transport,
                           "service_name": service_name,
                           "cert_names": cert_names[:MAX_ITEMS],
                           "cert_subject_cn": cert_subject_cn}
        add_entity(EntityType.PORT, port_value, 0.85, evidence,
                   metadata={"source": "censys", **port_attributes},
                   attributes=port_attributes)
        add_entity(EntityType.SERVICE, service_value, 0.82, evidence,
                   metadata={"source": "censys", **port_attributes},
                   attributes=port_attributes)
        if target_type is EntityType.IP and host_ip:
            add_relation(EntityType.IP, host_ip, EdgeType.ASSOCIATED_WITH,
                         EntityType.PORT, port_value, 0.85, evidence)
            add_relation(EntityType.IP, host_ip, EdgeType.ASSOCIATED_WITH,
                         EntityType.SERVICE, service_value, 0.82, evidence)

    if target_type is EntityType.DOMAIN and target_value:
        for item in subdomains[:MAX_ITEMS]:
            subdomain = _as_text(item).lower().rstrip(".")
            if subdomain.startswith("*."):
                subdomain = subdomain[2:]
            if not subdomain or not _is_hostname(subdomain):
                continue
            evidence = f"Censys Platform certificate/DNS name of {target_value}: {subdomain}"
            add_entity(EntityType.SUBDOMAIN, subdomain, 0.80, evidence,
                       metadata={"source": "censys"})
            if subdomain != target_value and subdomain.endswith("." + target_value):
                add_relation(EntityType.SUBDOMAIN, subdomain, EdgeType.SUBDOMAIN_OF,
                             EntityType.DOMAIN, target_value, 0.80, evidence)

    for certificate in certificates[:MAX_ITEMS]:
        if not isinstance(certificate, dict):
            continue
        for name in certificate.get("names") or []:
            subdomain = _as_text(name).lower().rstrip(".")
            if subdomain.startswith("*."):
                subdomain = subdomain[2:]
            if not subdomain or not _is_hostname(subdomain):
                continue
            if target_type is EntityType.IP:
                evidence = (f"Censys Platform TLS certificate name observed on "
                            f"{host_ip or 'host'}: {subdomain}")
                add_entity(EntityType.SUBDOMAIN, subdomain, 0.72, evidence,
                           metadata={"source": "censys:tls"})
            elif (subdomain != target_value
                  and subdomain.endswith("." + target_value)):
                evidence = (f"Censys Platform TLS certificate name of "
                            f"{target_value}: {subdomain}")
                add_entity(EntityType.SUBDOMAIN, subdomain, 0.78, evidence,
                           metadata={"source": "censys:tls"})
                add_relation(EntityType.SUBDOMAIN, subdomain,
                             EdgeType.SUBDOMAIN_OF, EntityType.DOMAIN,
                             target_value, 0.78, evidence)

    if organization:
        evidence = (f"Censys Platform organization/AS description"
                    + (f" ({asn})" if asn else "")
                    + f": {organization}")
        add_entity(EntityType.ORGANIZATION, organization, 0.78, evidence,
                   metadata={"source": "censys", "asn": asn})
        if target_type is EntityType.DOMAIN and target_value:
            add_relation(EntityType.DOMAIN, target_value, EdgeType.ASSOCIATED_WITH,
                         EntityType.ORGANIZATION, organization, 0.72, evidence)
        elif host_ip:
            add_relation(EntityType.IP, host_ip, EdgeType.ASSOCIATED_WITH,
                         EntityType.ORGANIZATION, organization, 0.72, evidence)

    if not entities:
        warnings.append("no Censys Platform entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
