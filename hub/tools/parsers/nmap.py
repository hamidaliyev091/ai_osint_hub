"""Parse nmap stdout into the v2 ParseOutput contract.

Supports nmap XML output (``-oX -``) and grepable output (``-oG -``).
Every open port yields a ``service`` entity (``ssh:22/tcp``) and a ``port``
entity (``22/tcp``); the scanned host ``ip`` is related to both with
``ASSOCIATED_WITH``.  ``port``/``protocol``/``service_name`` are carried as
structured attributes.  Pure and deterministic: no network, no file access.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Optional

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]

_GREPABLE_IP_RE = re.compile(r"^Host:\s+(\S+)")


def _evidence(raw: str, needle: str) -> str:
    """Return the raw output line containing ``needle`` (needle as fallback)."""
    for line in raw.splitlines():
        if needle in line:
            return line.strip()
    return needle


def _as_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _add_port_entities(host_ip: str, port_id: str, protocol: str, service_name: str,
                       evidence: str, entities: list[EntityCandidate],
                       relations: list[RelationCandidate], seen: set[tuple[str, str]],
                       extra_metadata: Optional[dict] = None) -> None:
    """Create the service/port entities plus host ASSOCIATED_WITH relations."""
    port_num = _as_int(port_id)
    service_value = f"{service_name}:{port_id}/{protocol}"
    port_value = f"{port_id}/{protocol}"
    port_metadata = {
        "port": port_num,
        "protocol": protocol,
        "service_name": service_name,
        "state": "open",
    }
    if host_ip:
        port_metadata["host"] = host_ip
    if extra_metadata:
        port_metadata.update({k: v for k, v in extra_metadata.items() if v})

    entity_type_service = EntityType.SERVICE
    service_key = (entity_type_service.value, service_value.lower())
    if service_key not in seen:
        seen.add(service_key)
        entities.append(EntityCandidate(
            type=entity_type_service,
            value=service_value,
            confidence=0.90,
            metadata=port_metadata,
            evidence=evidence,
            attributes={"port": port_num, "protocol": protocol, "service_name": service_name},
        ))
    port_key = (EntityType.PORT.value, port_value.lower())
    if port_key not in seen:
        seen.add(port_key)
        entities.append(EntityCandidate(
            type=EntityType.PORT,
            value=port_value,
            confidence=0.90,
            metadata=port_metadata,
            evidence=evidence,
            attributes={"port": port_num, "protocol": protocol, "service_name": service_name},
        ))
    if not host_ip:
        return
    relations.append(RelationCandidate(
        subject_type=EntityType.IP,
        subject_value=host_ip,
        predicate=EdgeType.ASSOCIATED_WITH,
        object_type=EntityType.SERVICE,
        object_value=service_value,
        confidence=0.90,
        evidence=evidence,
        metadata={"port": port_num, "protocol": protocol},
    ))
    relations.append(RelationCandidate(
        subject_type=EntityType.IP,
        subject_value=host_ip,
        predicate=EdgeType.ASSOCIATED_WITH,
        object_type=EntityType.PORT,
        object_value=port_value,
        confidence=0.90,
        evidence=evidence,
        metadata={"port": port_num, "protocol": protocol},
    ))


def _parse_xml(root: ET.Element, raw: str, target: str,
               entities: list[EntityCandidate], relations: list[RelationCandidate],
               seen: set[tuple[str, str]]) -> None:
    for host in root.iter("host"):
        host_ips: list[str] = []
        for address in host.findall("address"):
            addr = (address.get("addr") or "").strip()
            addr_type = (address.get("addrtype") or "").strip().lower()
            if addr and addr_type in ("ipv4", "ipv6"):
                host_ips.append(addr)
        hostnames = [
            (node.get("name") or "").strip()
            for node in host.findall("hostnames/hostname")
            if (node.get("name") or "").strip()
        ]
        for ip_value in host_ips:
            evidence = _evidence(raw, f'addr="{ip_value}"')
            metadata = {"discovery": "nmap_scan"}
            if hostnames:
                metadata["hostnames"] = hostnames
            key = (EntityType.IP.value, ip_value.lower())
            if key not in seen:
                seen.add(key)
                entities.append(EntityCandidate(
                    type=EntityType.IP,
                    value=ip_value,
                    confidence=0.95,
                    metadata=metadata,
                    evidence=evidence,
                ))
        host_ip = host_ips[0] if host_ips else (target or "").strip()
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or (state.get("state") or "").strip() != "open":
                continue
            port_id = (port.get("portid") or "").strip()
            protocol = (port.get("protocol") or "tcp").strip().lower()
            if not port_id.isdigit():
                continue
            service = port.find("service")
            service_name = "unknown"
            extra: dict = {}
            if service is not None:
                service_name = (service.get("name") or "unknown").strip().lower() or "unknown"
                extra = {
                    "product": (service.get("product") or "").strip(),
                    "version": (service.get("version") or "").strip(),
                    "extrainfo": (service.get("extrainfo") or "").strip(),
                }
            evidence = _evidence(raw, f'portid="{port_id}"')
            _add_port_entities(host_ip, port_id, protocol, service_name, evidence,
                               entities, relations, seen, extra)


def _parse_grepable(raw: str, target: str,
                    entities: list[EntityCandidate],
                    relations: list[RelationCandidate],
                    seen: set[tuple[str, str]]) -> None:
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped.startswith("Host:"):
            continue
        host_match = _GREPABLE_IP_RE.match(stripped)
        if not host_match:
            continue
        host_ip = host_match.group(1).strip()
        evidence = stripped
        key = (EntityType.IP.value, host_ip.lower())
        if key not in seen:
            seen.add(key)
            entities.append(EntityCandidate(
                type=EntityType.IP,
                value=host_ip,
                confidence=0.95,
                metadata={"discovery": "nmap_grepable"},
                evidence=evidence,
            ))
        ports_marker = stripped.find("Ports:")
        if ports_marker < 0:
            continue
        ports_str = stripped[ports_marker + len("Ports:"):].strip()
        for entry in ports_str.split(","):
            fields = entry.strip().split("/")
            if len(fields) < 3:
                continue
            port_id, state, protocol = fields[0].strip(), fields[1].strip(), fields[2].strip()
            if state != "open" or not port_id.isdigit():
                continue
            service_name = fields[4].strip().lower() if len(fields) > 4 else ""
            service_name = service_name or "unknown"
            version = fields[6].strip() if len(fields) > 6 else ""
            _add_port_entities(host_ip, port_id, protocol or "tcp", service_name, evidence,
                               entities, relations, seen, {"version": version})


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse nmap XML/grepable stdout. Never raises on garbage input."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["nmap: empty stdout"])

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen: set[tuple[str, str]] = set()
    xml_ok = False

    if "<nmaprun" in text or text.lstrip().startswith("<?xml"):
        try:
            root = ET.fromstring(text.strip())
        except (ET.ParseError, ValueError):
            root = None
        if root is not None:
            xml_ok = True
            _parse_xml(root, text, target, entities, relations, seen)

    if not xml_ok:
        _parse_grepable(text, target, entities, relations, seen)

    if not entities:
        return ParseOutput(warnings=["nmap: no hosts or open ports recognised"])
    return ParseOutput(entities=entities, relations=relations)
