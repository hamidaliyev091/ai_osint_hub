"""Deterministic parser for the builtin DNS resolver.

Input (collector stdout)::

    {"target": "example.com",
     "addresses": [{"ip": "93.184.216.34", "family": "AF_INET"}, ...]}

Output: IP entity candidates plus ``<target> RESOLVES_TO <ip>`` relations.
"""

from __future__ import annotations

import ipaddress
import json

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"dns_lookup parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from dns_lookup: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected dns_lookup payload: {type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    resolved_target = str(data.get("target") or target or "").strip()
    subject_type = EntityType.DOMAIN
    if resolved_target:
        try:
            subject_type = infer_value_type(resolved_target)
        except ValueError:
            subject_type = EntityType.DOMAIN

    addresses = data.get("addresses")
    if not isinstance(addresses, list):
        warnings.append("missing 'addresses' list in dns_lookup output")
        addresses = []

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    for item in addresses:
        if not isinstance(item, dict):
            warnings.append("dropped non-object address record")
            continue
        ip_value = str(item.get("ip") or "").strip()
        family = str(item.get("family") or "").strip()
        if not ip_value:
            warnings.append("dropped address record without 'ip'")
            continue
        try:
            ipaddress.ip_address(ip_value)
        except ValueError:
            warnings.append(f"dropped invalid IP address {ip_value!r}")
            continue
        evidence = f"DNS resolve {resolved_target or 'target'} -> {ip_value}" + (
            f" ({family})" if family else ""
        )
        entities.append(EntityCandidate(
            type=EntityType.IP,
            value=ip_value,
            confidence=0.85,
            metadata={"family": family, "resolved_from": resolved_target},
            evidence=evidence,
        ))
        if resolved_target:
            relations.append(RelationCandidate(
                subject_type=subject_type,
                subject_value=resolved_target,
                predicate=EdgeType.RESOLVES_TO,
                object_type=EntityType.IP,
                object_value=ip_value,
                confidence=0.85,
                evidence=evidence,
            ))
    if not entities:
        warnings.append("no DNS address records parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
