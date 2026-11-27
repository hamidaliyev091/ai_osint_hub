"""Deterministic parser for the builtin crt.sh Certificate Transparency collector."""

from __future__ import annotations

import json

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ITEMS = 200


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse crt.sh collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"crtsh_lookup parser error: {type(exc).__name__}: {exc}"],
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
            warnings=[f"invalid JSON from crtsh_lookup: {exc}"],
            parser_version=PARSER_VERSION,
        )
    if not isinstance(data, dict):
        return ParseOutput(
            warnings=[f"unexpected crtsh_lookup payload: {type(data).__name__}"],
            parser_version=PARSER_VERSION,
        )

    domain = str(data.get("domain") or target or "").strip().lower().rstrip(".")
    subdomains = data.get("subdomains") if isinstance(data.get("subdomains"), list) else []
    issuer_orgs = data.get("issuer_orgs") if isinstance(data.get("issuer_orgs"), list) else []
    entries = data.get("entries") if isinstance(data.get("entries"), list) else []

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_hosts: set[str] = set()
    seen_orgs: set[str] = set()

    for raw_host in subdomains[:MAX_ITEMS]:
        host = str(raw_host or "").strip().lower().rstrip(".")
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        is_sub = bool(domain and host != domain and host.endswith("." + domain))
        etype = EntityType.SUBDOMAIN if is_sub or host != domain else EntityType.DOMAIN
        evidence = f"crt.sh CT log SAN/CN={host} (query=%.{domain})" if domain else f"crt.sh CT log SAN/CN={host}"
        entities.append(
            EntityCandidate(
                type=etype,
                value=host,
                confidence=0.80,
                metadata={"source": "crtsh", "query_domain": domain},
                evidence=evidence[:MAX_EVIDENCE],
            )
        )
        if domain and is_sub:
            relations.append(
                RelationCandidate(
                    subject_type=etype,
                    subject_value=host,
                    predicate=EdgeType.SUBDOMAIN_OF,
                    object_type=EntityType.DOMAIN,
                    object_value=domain,
                    confidence=0.80,
                    evidence=evidence[:MAX_EVIDENCE],
                )
            )
        elif domain and host != domain:
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.DOMAIN,
                    subject_value=domain,
                    predicate=EdgeType.ASSOCIATED_WITH,
                    object_type=etype,
                    object_value=host,
                    confidence=0.70,
                    evidence=evidence[:MAX_EVIDENCE],
                )
            )

    for raw_org in issuer_orgs[:MAX_ITEMS]:
        org = str(raw_org or "").strip()
        if not org or org.lower() in seen_orgs:
            continue
        seen_orgs.add(org.lower())
        evidence = f"crt.sh certificate issuer O={org}" + (f" for {domain}" if domain else "")
        entities.append(
            EntityCandidate(
                type=EntityType.ORGANIZATION,
                value=org,
                confidence=0.75,
                metadata={"source": "crtsh", "role": "ca_issuer"},
                evidence=evidence[:MAX_EVIDENCE],
            )
        )
        if domain:
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.DOMAIN,
                    subject_value=domain,
                    predicate=EdgeType.ASSOCIATED_WITH,
                    object_type=EntityType.ORGANIZATION,
                    object_value=org,
                    confidence=0.70,
                    evidence=evidence[:MAX_EVIDENCE],
                )
            )

    if not entities and not entries:
        warnings.append(f"no crt.sh certificates found for {domain or target}")

    return ParseOutput(
        entities=entities,
        relations=relations,
        warnings=warnings,
        parser_version=PARSER_VERSION,
    )
