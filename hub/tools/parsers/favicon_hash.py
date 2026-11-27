"""Deterministic parser for the builtin favicon MurmurHash3 collector."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse favicon_hash collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"favicon_hash parser error: {type(exc).__name__}: {exc}"],
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
            warnings=[f"invalid JSON from favicon_hash: {exc}"],
            parser_version=PARSER_VERSION,
        )
    if not isinstance(data, dict):
        return ParseOutput(
            warnings=[f"unexpected favicon_hash payload: {type(data).__name__}"],
            parser_version=PARSER_VERSION,
        )

    found = bool(data.get("found"))
    url = str(data.get("url") or "").strip()
    base_host = str(data.get("base_host") or "").strip().lower().rstrip(".")
    mmh3_val = data.get("mmh3")
    sha256_val = str(data.get("sha256") or "").strip().lower()
    content_type = str(data.get("content_type") or "").strip()
    size_bytes = int(data.get("bytes") or 0)

    if not found or mmh3_val is None:
        return ParseOutput(
            warnings=[f"no favicon found for {base_host or target}"],
            parser_version=PARSER_VERSION,
        )

    if not base_host and url:
        try:
            base_host = (urlsplit(url).hostname or "").strip().lower().rstrip(".")
        except ValueError:
            base_host = ""

    mmh3_str = str(mmh3_val)
    hash_label = f"mmh3:{mmh3_str}"
    service_label = f"favicon-mmh3:{mmh3_str}"
    evidence = (
        f"Favicon {url}: mmh3={mmh3_str} sha256={sha256_val[:16]}... "
        f"bytes={size_bytes} type={content_type or 'unknown'}"
    )[:MAX_EVIDENCE]

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []

    entities.append(
        EntityCandidate(
            type=EntityType.HASH,
            value=hash_label,
            confidence=0.90,
            metadata={"hash_kind": "mmh3", "mmh3": mmh3_val, "sha256": sha256_val, "url": url},
            attributes={"mmh3": mmh3_str, **({"sha256": sha256_val} if sha256_val else {})},
            evidence=evidence,
        )
    )
    entities.append(
        EntityCandidate(
            type=EntityType.SERVICE,
            value=service_label,
            confidence=0.80,
            metadata={"kind": "favicon", "mmh3": mmh3_val, "sha256": sha256_val, "content_type": content_type},
            attributes={"mmh3": mmh3_str},
            evidence=evidence,
        )
    )
    if url:
        entities.append(
            EntityCandidate(
                type=EntityType.URL,
                value=url,
                confidence=0.90,
                metadata={"mmh3": mmh3_val, "sha256": sha256_val, "content_type": content_type, "bytes": size_bytes},
                attributes={"mmh3": mmh3_str, **({"sha256": sha256_val} if sha256_val else {})},
                evidence=evidence,
            )
        )
        relations.append(
            RelationCandidate(
                subject_type=EntityType.URL,
                subject_value=url,
                predicate=EdgeType.ASSOCIATED_WITH,
                object_type=EntityType.HASH,
                object_value=hash_label,
                confidence=0.90,
                evidence=evidence,
            )
        )
        if base_host:
            try:
                host_type = infer_value_type(base_host)
            except ValueError:
                host_type = EntityType.DOMAIN
            relations.append(
                RelationCandidate(
                    subject_type=EntityType.URL,
                    subject_value=url,
                    predicate=EdgeType.MENTIONED_IN,
                    object_type=host_type,
                    object_value=base_host,
                    confidence=0.85,
                    evidence=evidence,
                )
            )
            relations.append(
                RelationCandidate(
                    subject_type=host_type,
                    subject_value=base_host,
                    predicate=EdgeType.ASSOCIATED_WITH,
                    object_type=EntityType.SERVICE,
                    object_value=service_label,
                    confidence=0.80,
                    evidence=evidence,
                )
            )

    relations.append(
        RelationCandidate(
            subject_type=EntityType.SERVICE,
            subject_value=service_label,
            predicate=EdgeType.ASSOCIATED_WITH,
            object_type=EntityType.HASH,
            object_value=hash_label,
            confidence=0.90,
            evidence=evidence,
        )
    )

    return ParseOutput(
        entities=entities,
        relations=relations,
        warnings=warnings,
        parser_version=PARSER_VERSION,
    )
