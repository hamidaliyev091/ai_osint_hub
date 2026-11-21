"""Deterministic parser for the builtin TLS certificate collector.

Input (collector stdout)::

    {"host": "example.com", "version": "TLSv1.3",
     "subject": {"commonName": "example.com"},
     "issuer": {"organizationName": "DigiCert Inc", "commonName": "R3"},
     "subjectAltName": [["DNS", "example.com"], ["DNS", "www.example.com"]],
     "notBefore": "Jan  1 00:00:00 2026 GMT",
     "notAfter": "Apr  1 00:00:00 2026 GMT"}

Output: a SUBDOMAIN entity per DNS SAN, an ORGANIZATION entity for the issuer
``O``, and ``<host> ASSOCIATED_WITH <organization>``.
"""

from __future__ import annotations

import json

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400

_ORG_KEYS = ("organizationName", "O", "organization")


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"tls_cert parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_mapping(value: object) -> dict[str, str]:
    """getpeercert() RDN fields can arrive as a dict or list of pairs."""
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    mapping: dict[str, str] = {}
    if isinstance(value, list):
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                mapping[str(item[0])] = str(item[1])
    return mapping


def _organization(issuer: dict[str, str], subject: dict[str, str]) -> str:
    for source in (issuer, subject):
        for key in _ORG_KEYS:
            value = source.get(key)
            if value and str(value).strip():
                return str(value).strip()
    return ""


def _clean_san(value: str) -> tuple[str, bool]:
    """Return (canonical host, was_wildcard) for a DNS SAN."""
    text = value.strip().lower().rstrip(".")
    wildcard = text.startswith("*.")
    if wildcard:
        text = text[2:]
    return text, wildcard


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from tls_cert: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected tls_cert payload: {type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    host = str(data.get("host") or target or "").strip().lower().rstrip(".")
    subject = _as_mapping(data.get("subject"))
    issuer = _as_mapping(data.get("issuer"))
    version = str(data.get("version") or "").strip()
    not_before = str(data.get("notBefore") or "").strip()
    not_after = str(data.get("notAfter") or "").strip()
    valid_window = (f"notBefore={not_before}; notAfter={not_after}"
                    if not_before or not_after else "")
    organization = _organization(issuer, subject)

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_sans: set[str] = set()
    raw_sans = data.get("subjectAltName")
    if isinstance(raw_sans, list):
        for pair in raw_sans:
            if not isinstance(pair, (list, tuple)) or len(pair) < 2:
                warnings.append("dropped malformed subjectAltName entry")
                continue
            kind, raw_value = str(pair[0]).strip(), str(pair[1]).strip()
            if kind.upper() != "DNS" or not raw_value:
                continue
            san_host, wildcard = _clean_san(raw_value)
            if not san_host or san_host in seen_sans:
                continue
            seen_sans.add(san_host)
            evidence = (f"TLS certificate SAN DNS={raw_value}"
                        + (" (wildcard)" if wildcard else "")
                        + (f"; issuer O={organization}" if organization else "")
                        + (f"; {valid_window}" if valid_window else ""))
            entities.append(EntityCandidate(
                type=EntityType.SUBDOMAIN,
                value=san_host,
                confidence=0.80,
                metadata={"wildcard": wildcard, "raw_san": raw_value, "issuer": organization},
                evidence=evidence[:MAX_EVIDENCE],
            ))
    else:
        warnings.append("missing 'subjectAltName' list in tls_cert output")

    if organization:
        org_evidence = (f"TLS certificate issuer O={organization}"
                        + (f"; issuer CN={issuer.get('commonName')}" if issuer.get("commonName") else "")
                        + (f"; {valid_window}" if valid_window else ""))
        entities.append(EntityCandidate(
            type=EntityType.ORGANIZATION,
            value=organization,
            confidence=0.80,
            metadata={"issuer": issuer, "version": version,
                      "not_before": not_before, "not_after": not_after},
            evidence=org_evidence[:MAX_EVIDENCE],
        ))
        if host:
            try:
                subject_type = infer_value_type(host)
            except ValueError:
                subject_type = EntityType.DOMAIN
            relations.append(RelationCandidate(
                subject_type=subject_type,
                subject_value=host,
                predicate=EdgeType.ASSOCIATED_WITH,
                object_type=EntityType.ORGANIZATION,
                object_value=organization,
                confidence=0.70,
                evidence=org_evidence[:MAX_EVIDENCE],
            ))
    else:
        warnings.append("no issuer organization found in tls_cert output")

    if not entities:
        warnings.append("no TLS certificate entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
