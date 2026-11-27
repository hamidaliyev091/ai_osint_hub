"""Deterministic parser for the builtin ASN/BGP lookup collector."""

from __future__ import annotations

import json

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse ASN/BGP collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"asn_bgp_lookup parser error: {type(exc).__name__}: {exc}"],
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
        return ParseOutput(
            warnings=[f"invalid JSON from asn_bgp_lookup: {exc}"],
            parser_version=PARSER_VERSION,
        )
    if not isinstance(data, dict):
        return ParseOutput(
            warnings=[f"unexpected asn_bgp_lookup payload: {type(data).__name__}"],
            parser_version=PARSER_VERSION,
        )

    tgt = str(data.get("target") or target or "").strip()
    kind = str(data.get("kind") or "").strip().lower()
    asns = [str(a).strip().upper() for a in (data.get("asns") or []) if str(a).strip()]
    prefixes = [str(p).strip() for p in (data.get("prefixes") or []) if str(p).strip()]
    org = str(data.get("org") or "").strip()
    country = str(data.get("country") or "").strip().upper()
    rir = str(data.get("rir") or "").strip()
    source = str(data.get("source") or "ripestat").strip()
    found = bool(data.get("found"))

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []

    if kind == "ip" and tgt and found:
        attrs = {}
        if prefixes:
            attrs["prefix"] = prefixes[0]
        if rir:
            attrs["rir"] = rir
        if country:
            attrs["country"] = country
        entities.append(
            EntityCandidate(
                type=EntityType.IP,
                value=tgt,
                confidence=0.85,
                metadata={"source": source, "prefixes": prefixes, "rir": rir, "country": country},
                attributes=attrs,
                evidence=f"{source}: IP {tgt} prefix={prefixes[0] if prefixes else 'n/a'} rir={rir or 'n/a'}"[:MAX_EVIDENCE],
            )
        )

    for asn in asns[:10]:
        if not asn.startswith("AS"):
            asn = f"AS{asn}"
        attrs = {}
        if prefixes:
            attrs["prefix"] = prefixes[0]
        if rir:
            attrs["rir"] = rir
        if country:
            attrs["country"] = country
        ev = f"{source}: {asn}" + (f" prefix={prefixes[0]}" if prefixes else "") + (f" org={org}" if org else "")
        entities.append(
            EntityCandidate(
                type=EntityType.ASN,
                value=asn,
                confidence=0.85,
                metadata={"source": source, "prefixes": prefixes, "rir": rir, "country": country},
                attributes=attrs,
                evidence=ev[:MAX_EVIDENCE],
            )
        )
        if kind == "ip" and tgt:
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.IP,
                    subject_value=tgt,
                    predicate=EdgeType.ASSOCIATED_WITH,
                    object_type=EntityType.ASN,
                    object_value=asn,
                    confidence=0.85,
                    evidence=ev[:MAX_EVIDENCE],
                )
            )

    if org:
        org_ev = f"{source}: AS holder/organization {org}" + (f" ({rir})" if rir else "")
        entities.append(
            EntityCandidate(
                type=EntityType.ORGANIZATION,
                value=org,
                confidence=0.80,
                metadata={"source": source, "rir": rir, "country": country},
                evidence=org_ev[:MAX_EVIDENCE],
            )
        )
        for asn in asns[:10]:
            if not asn.startswith("AS"):
                asn = f"AS{asn}"
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.ASN,
                    subject_value=asn,
                    predicate=EdgeType.REGISTERED_BY,
                    object_type=EntityType.ORGANIZATION,
                    object_value=org,
                    confidence=0.80,
                    evidence=org_ev[:MAX_EVIDENCE],
                )
            )
        if kind == "ip" and tgt and not asns:
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.IP,
                    subject_value=tgt,
                    predicate=EdgeType.ASSOCIATED_WITH,
                    object_type=EntityType.ORGANIZATION,
                    object_value=org,
                    confidence=0.75,
                    evidence=org_ev[:MAX_EVIDENCE],
                )
            )

    if country:
        loc_ev = f"{source}: RIR country={country}" + (f" ({rir})" if rir else "")
        entities.append(
            EntityCandidate(
                type=EntityType.LOCATION,
                value=country,
                confidence=0.75,
                metadata={"source": source, "rir": rir, "kind": "country"},
                evidence=loc_ev[:MAX_EVIDENCE],
            )
        )
        if asns:
            asn = asns[0] if asns[0].startswith("AS") else f"AS{asns[0]}"
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.ASN,
                    subject_value=asn,
                    predicate=EdgeType.LOCATED_IN,
                    object_type=EntityType.LOCATION,
                    object_value=country,
                    confidence=0.75,
                    evidence=loc_ev[:MAX_EVIDENCE],
                )
            )
        elif kind == "ip" and tgt:
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.IP,
                    subject_value=tgt,
                    predicate=EdgeType.LOCATED_IN,
                    object_type=EntityType.LOCATION,
                    object_value=country,
                    confidence=0.75,
                    evidence=loc_ev[:MAX_EVIDENCE],
                )
            )

    if not found or not entities:
        warnings.append(f"no ASN/BGP record found for {tgt or target}")

    return ParseOutput(
        entities=entities,
        relations=relations,
        warnings=warnings,
        parser_version=PARSER_VERSION,
    )
