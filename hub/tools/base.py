"""Deterministic parser contract — Stage 1 of the two-stage output pipeline.

Every tool parser converts raw stdout into a :class:`ParseOutput` containing
structured entity candidates, relationship candidates and the raw evidence
snippets that back them. Parsers MUST be pure functions: no network, no AI.

Stage 2 (LLM correlation / disambiguation) happens later in
``hub.investigation.reflection`` and only ever sees the normalized delta plus
the local graph neighborhood — never raw tool output.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hub.models import EdgeType, EntityType

PARSER_CONTRACT_VERSION = "2.0.0"
MAX_EVIDENCE_SNIPPET = 500


class EntityCandidate(BaseModel):
    """One entity extracted by a deterministic parser."""

    model_config = ConfigDict(extra="forbid")

    type: EntityType
    value: str
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: str = ""
    aliases: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    direct: bool = True

    @field_validator("type", mode="before")
    @classmethod
    def _coerce_type(cls, value: Any) -> EntityType:
        return EntityType.coerce(value)

    @field_validator("value", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> str:
        return str(value).strip()

    @field_validator("evidence", mode="before")
    @classmethod
    def _trim_evidence(cls, value: Any) -> str:
        return str(value or "").strip()[:MAX_EVIDENCE_SNIPPET]


class RelationCandidate(BaseModel):
    """One relationship extracted by a deterministic parser."""

    model_config = ConfigDict(extra="forbid")

    subject_type: EntityType
    subject_value: str
    predicate: EdgeType
    object_type: EntityType
    object_value: str
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: str = ""
    direct: bool = True

    @field_validator("subject_type", "object_type", mode="before")
    @classmethod
    def _coerce_type(cls, value: Any) -> EntityType:
        return EntityType.coerce(value)

    @field_validator("predicate", mode="before")
    @classmethod
    def _coerce_predicate(cls, value: Any) -> EdgeType:
        return EdgeType.coerce(value)

    @field_validator("subject_value", "object_value", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> str:
        return str(value).strip()

    @field_validator("evidence", mode="before")
    @classmethod
    def _trim_evidence(cls, value: Any) -> str:
        return str(value or "").strip()[:MAX_EVIDENCE_SNIPPET]


class ParseOutput(BaseModel):
    """Structured Stage-1 parse result.

    ``entities`` and ``relations`` may be empty (valid EMPTY_RESULT outcome).
    ``warnings`` are surfaced in the iteration record, never raised.
    """

    model_config = ConfigDict(extra="forbid")

    entities: list[EntityCandidate] = Field(default_factory=list)
    relations: list[RelationCandidate] = Field(default_factory=list)
    parser_version: str = PARSER_CONTRACT_VERSION
    warnings: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.entities and not self.relations

    def entity_count(self) -> int:
        return len(self.entities)

    def summary(self) -> dict[str, Any]:
        return {
            "entities": len(self.entities),
            "relations": len(self.relations),
            "types": sorted({e.type.value for e in self.entities}),
            "parser_version": self.parser_version,
            "warnings": self.warnings[:5],
        }


def legacy_entity_to_candidate(raw: dict[str, Any]) -> EntityCandidate:
    """Convert a legacy ``list[dict]`` parser entity to the v2 contract."""
    metadata = dict(raw.get("metadata") or {})
    evidence = ""
    for key in ("evidence", "raw_evidence", "snippet"):
        if raw.get(key):
            evidence = str(raw[key])
            break
    if not evidence and metadata:
        evidence = str({k: v for k, v in metadata.items() if isinstance(v, (str, int, float))})
    attributes = dict(raw.get("attributes") or {})
    # Preserve legacy `metadata.registered` etc. as evidence-backed attributes.
    for key, value in metadata.items():
        if key in {"registered", "credentials_exposed", "username_found",
                   "username_hint", "port", "protocol", "service_name"}:
            attributes.setdefault(key, value)
    return EntityCandidate(
        type=EntityType.coerce(raw.get("type")),
        value=str(raw.get("value", "")),
        confidence=float(raw.get("confidence", 0.6)),
        metadata=metadata,
        evidence=evidence,
        aliases=[str(a) for a in raw.get("aliases", []) or []],
        attributes=attributes,
        direct=bool(raw.get("direct", True)),
    )


def coerce_parse_output(raw: Any, *, parser_version: str = PARSER_CONTRACT_VERSION) -> ParseOutput:
    """Accept ParseOutput, a legacy list[dict], a single dict, or None.

    This keeps third-party/legacy parsers working while new parsers use the
    strict contract. Invalid items are dropped with a warning — never raised.
    """
    if isinstance(raw, ParseOutput):
        return raw
    if raw is None:
        return ParseOutput(parser_version=parser_version)
    warnings: list[str] = []
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []

    if isinstance(raw, dict):
        if "entities" in raw or "relations" in raw:
            entity_items = raw.get("entities") or []
            relation_items = raw.get("relations") or []
            if not isinstance(entity_items, list) or not isinstance(relation_items, list):
                raise ValueError(
                    "invalid ParseOutput structure: 'entities' and 'relations' must be lists")
            parser_version = str(raw.get("parser_version", parser_version))
            warnings.extend(str(w) for w in raw.get("warnings", []) or [])
        else:
            entity_items, relation_items = [raw], []
    elif isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)):
        entity_items, relation_items = list(raw), []
    else:
        return ParseOutput(parser_version=parser_version,
                           warnings=[f"unsupported parser output type {type(raw).__name__}"])

    for item in entity_items:
        try:
            if isinstance(item, EntityCandidate):
                entities.append(item)
            elif isinstance(item, dict):
                entities.append(legacy_entity_to_candidate(item))
            else:
                warnings.append(f"dropped entity candidate of type {type(item).__name__}")
        except Exception as exc:  # noqa: BLE001 - invalid parser data must never crash a run
            warnings.append(f"dropped invalid entity candidate: {exc}")

    for item in relation_items:
        try:
            if isinstance(item, RelationCandidate):
                relations.append(item)
            elif isinstance(item, dict):
                relations.append(RelationCandidate(**item))
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"dropped invalid relation candidate: {exc}")

    return ParseOutput(entities=entities, relations=relations,
                       parser_version=parser_version, warnings=warnings[:20])


_IPV4_RE = None


def infer_value_type(value: str) -> EntityType:
    """Infer an entity type from a bare string (used by parsers for relation subjects)."""
    import ipaddress
    import re

    text = (value or "").strip().strip('"\'')
    if not text:
        raise ValueError("empty value")
    if "@" in text and re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", text):
        return EntityType.EMAIL
    try:
        ip = ipaddress.ip_address(text)
        return EntityType.IP
    except ValueError:
        pass
    if re.match(r"^https?://", text, re.IGNORECASE):
        return EntityType.URL
    if re.match(r"^AS\d+$", text, re.IGNORECASE):
        return EntityType.ASN
    if re.match(r"^\+?[\d][\d\s().-]{5,}$", text) and sum(c.isdigit() for c in text) >= 7:
        return EntityType.PHONE
    if re.match(r"^[0-9a-fA-F]{32,}$", text):
        return EntityType.HASH
    if re.match(r"^[\w.-]+\.[A-Za-z]{2,}$", text):
        return EntityType.DOMAIN
    if text.startswith("@") or re.match(r"^[A-Za-z0-9._-]{2,32}$", text):
        return EntityType.USERNAME
    return EntityType.ORGANIZATION


def load_parser(parser_ref: str):
    """Import ``module:function`` parser reference; raise ImportError on failure."""
    module_path, _, func_name = parser_ref.partition(":")
    if not module_path or not func_name:
        raise ImportError(f"invalid parser reference: {parser_ref!r}")
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, func_name)


def entities_of_types(parse_output: ParseOutput,
                      types: Optional[set[EntityType]] = None) -> list[EntityCandidate]:
    if types is None:
        return parse_output.entities
    return [e for e in parse_output.entities if e.type in types]


__all__ = [
    "PARSER_CONTRACT_VERSION",
    "MAX_EVIDENCE_SNIPPET",
    "EntityCandidate",
    "RelationCandidate",
    "ParseOutput",
    "legacy_entity_to_candidate",
    "coerce_parse_output",
    "load_parser",
    "entities_of_types",
    "infer_value_type",
]
