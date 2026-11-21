"""Canonical domain models for the AI OSINT Hub ERKG (v2).

This module is the single source of truth for every entity type, epistemic status,
claim, evidence artifact, hypothesis and pivot score used anywhere in the system.
All persistence (SQLite) and transport (CLI/MCP) layers serialize these models.

Design rules:
  * Epistemic status is a closed enum — exactly six values, never free text.
  * Confidence is a deterministic float in [0.0, 1.0] (see hub.erkg.confidence).
  * Every claim references >= 1 immutable EvidenceArtifact id.
  * Timestamps are ISO-8601 UTC strings for SQLite/JSON round-trip stability.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Callable, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "2.0.0"


# ════════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════════

class EntityType(str, Enum):
    """Canonical entity types (13 from the spec + 6 operational extensions)."""

    # ── Spec 1 canonical types ──
    PERSON = "person"
    USERNAME = "username"
    EMAIL = "email"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    ORGANIZATION = "organization"
    PHONE = "phone"
    REPOSITORY = "repository"
    SOCIAL_PROFILE = "social_profile"
    BREACH_RECORD = "breach_record"
    CRYPTO_ADDRESS = "crypto_address"
    # ── Operational extensions produced by tool parsers ──
    SERVICE = "service"
    CREDENTIAL = "credential"
    HASH = "hash"
    PORT = "port"
    LOCATION = "location"
    URL = "url"

    @classmethod
    def coerce(cls, value: "str | EntityType | None") -> "EntityType":
        """Coerce legacy parser strings to canonical enum values."""
        if isinstance(value, cls):
            return value
        if value is None:
            raise ValueError("entity type is required")
        key = str(value).strip().lower()
        legacy = {
            "breach": cls.BREACH_RECORD,
            "breaches": cls.BREACH_RECORD,
            "profile": cls.SOCIAL_PROFILE,
            "social": cls.SOCIAL_PROFILE,
            "github": cls.REPOSITORY,
            "repo": cls.REPOSITORY,
            "organisation": cls.ORGANIZATION,
            "org": cls.ORGANIZATION,
            "phone_number": cls.PHONE,
            "crypto": cls.CRYPTO_ADDRESS,
            "sub_domain": cls.SUBDOMAIN,
            "hostname": cls.DOMAIN,
        }
        if key in legacy:
            return legacy[key]
        return cls(key)


class EpistemicStatus(str, Enum):
    """Closed epistemic status enum. No other values are permitted."""

    CONFIRMED = "CONFIRMED"
    CORROBORATED = "CORROBORATED"
    SINGLE_SOURCE_LEAD = "SINGLE_SOURCE_LEAD"
    HYPOTHESIS = "HYPOTHESIS"
    CONTRADICTED = "CONTRADICTED"
    COLLECTION_FAILURE = "COLLECTION_FAILURE"


# Statuses that mean "core objective satisfied" for stopping conditions.
SATISFIED_STATUSES = {EpistemicStatus.CONFIRMED, EpistemicStatus.CORROBORATED}
# Statuses that a pivot can help verify / refute (boosts CorroborationValue).
UNVERIFIED_STATUSES = {EpistemicStatus.HYPOTHESIS, EpistemicStatus.SINGLE_SOURCE_LEAD}


class EdgeType(str, Enum):
    """Relationship predicates. Spec predicates first, operational extensions after."""

    # ── Spec 1 required relationship types ──
    OWNS = "OWNS"
    RESOLVES_TO = "RESOLVES_TO"
    REGISTERED_BY = "REGISTERED_BY"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    COMMITTED_TO = "COMMITTED_TO"
    MENTIONED_IN = "MENTIONED_IN"
    # ── Operational predicates used by parsers / resolution ──
    SUBDOMAIN_OF = "SUBDOMAIN_OF"
    REGISTERED_ON = "REGISTERED_ON"
    EXPOSED_IN = "EXPOSED_IN"
    HAS_USERNAME = "HAS_USERNAME"
    HAS_EMAIL = "HAS_EMAIL"
    HAS_PHONE = "HAS_PHONE"
    LOCATED_IN = "LOCATED_IN"
    IDENTIFIED_AS = "IDENTIFIED_AS"
    FOUND_IN = "FOUND_IN"
    HAS_ATTRIBUTE = "HAS_ATTRIBUTE"

    @classmethod
    def coerce(cls, value: "str | EdgeType") -> "EdgeType":
        if isinstance(value, cls):
            return value
        key = str(value).strip().upper().replace("-", "_").replace(" ", "_")
        try:
            return cls(key)
        except ValueError:
            return cls.ASSOCIATED_WITH


# Predicates that are functional: a subject may have at most one true value.
# Conflicting values from independent sources are CONTRADICTED.
FUNCTIONAL_PREDICATES = {
    EdgeType.HAS_EMAIL,
    EdgeType.HAS_PHONE,
    EdgeType.REGISTERED_BY,
    # LOCATED_IN is intentionally NOT functional: locations are hierarchical
    # (city + country + region) and complementary, never conflicting.
    EdgeType.HAS_ATTRIBUTE,  # only same attribute key; checked at store level
    EdgeType.IDENTIFIED_AS,
}
FUNCTIONAL_PREDICATE_PREFIX = "HAS_ATTRIBUTE:"
#: Multi-valued property attributes: a domain may legitimately be both a
#: mail_domain and a registrable_parent, so these never trigger contradictions.
NON_FUNCTIONAL_ATTRIBUTE_KEYS = frozenset({
    "role", "clue_field", "clue_source", "provenance", "seed_wave",
    "derived_from_email",
})


def is_functional_predicate(predicate: str) -> bool:
    """True when a predicate is single-valued (contradictions are meaningful)."""
    text = str(predicate or "")
    base = text.split(":", 1)[0]
    if base not in {p.value for p in FUNCTIONAL_PREDICATES}:
        return False
    if base == EdgeType.HAS_ATTRIBUTE.value and ":" in text:
        key = text.split(":", 1)[1].strip().lower()
        if key in NON_FUNCTIONAL_ATTRIBUTE_KEYS:
            return False
    return True


class ExecutionStatus(str, Enum):
    """Execution ledger status — exactly the four values required by the spec."""

    SUCCESS = "SUCCESS"
    EMPTY = "EMPTY"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class ErrorCode(str, Enum):
    """Fine-grained runtime failure classification (stored alongside ledger status)."""

    MISSING_BINARY = "MISSING_BINARY"
    RATE_LIMITED = "RATE_LIMITED"
    PARSE_ERROR = "PARSE_ERROR"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    INTRUSIVE_BLOCKED = "INTRUSIVE_BLOCKED"
    AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
    TIMEOUT = "TIMEOUT"
    NONZERO_EXIT = "NONZERO_EXIT"
    SPAWN_ERROR = "SPAWN_ERROR"
    EMPTY_RESULT = "EMPTY_RESULT"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"


class ExecutionMode(str, Enum):
    """How a capability interacts with the target.

    PASSIVE          — no direct interaction with target infrastructure.
    ACTIVE_RECON     — connects to target hosts (allowed only inside explicit scope).
    INTRUSIVE_BLOCKED— never executed; blocked in deterministic Python before spawn.
    """

    PASSIVE = "PASSIVE"
    ACTIVE_RECON = "ACTIVE_RECON"
    INTRUSIVE_BLOCKED = "INTRUSIVE_BLOCKED"


class HypothesisType(str, Enum):
    CORROBORATION = "CORROBORATION"   # verify/refute a SINGLE_SOURCE_LEAD
    RESOLUTION = "RESOLUTION"         # resolve a CONTRADICTED claim
    EXPANSION = "EXPANSION"           # discover missing entity types
    IDENTITY_LINK = "IDENTITY_LINK"   # test that two entities are the same identity
    VERIFICATION = "VERIFICATION"     # confirm a HYPOTHESIS entity


class HypothesisStatus(str, Enum):
    OPEN = "OPEN"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class RunStatus(str, Enum):
    """Investigation lifecycle status."""

    ACTIVE = "active"
    COMPLETED = "completed"
    TERMINATED = "terminated"
    FAILED = "failed"


class SourceKind(str, Enum):
    SEED = "seed"            # raw user supplied intelligence
    TOOL = "tool"            # deterministic parser output from a tool run
    PLANNER = "planner"      # generated hypothesis (no artifact output)


# ════════════════════════════════════════════════════════════════════════
# Utility helpers
# ════════════════════════════════════════════════════════════════════════

def utc_now() -> str:
    """ISO-8601 UTC timestamp with second precision, stable across platforms."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(data: Any) -> str:
    """Deterministic JSON for hashing (sorted keys, no whitespace)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def param_hash(tool_id: str, params: dict[str, Any]) -> str:
    """Deterministic invocation hash of (tool_id, normalized params)."""
    return sha256_text(f"{tool_id}|{canonical_json(params)}")[:32]


def short_id(prefix: str, *parts: Any) -> str:
    """Deterministic readable id, e.g. ``art_1f3c...``."""
    return f"{prefix}_{sha256_text(canonical_json(list(parts)))[:16]}"


# ════════════════════════════════════════════════════════════════════════
# Evidence
# ════════════════════════════════════════════════════════════════════════

class EvidenceArtifact(BaseModel):
    """Immutable record of one piece of collected evidence.

    Every entity attribute and relationship claim cites at least one artifact.
    Artifacts are never updated after creation (enforced by the store).
    """

    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    investigation_id: str = ""
    source_tool: str
    invocation_params_hash: str
    timestamp_utc: str
    raw_evidence_snippet: str = Field(default="", max_length=4000)
    raw_output_sha256: str
    parser_version: str
    epistemic_status: EpistemicStatus = EpistemicStatus.SINGLE_SOURCE_LEAD
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    raw_output_path: Optional[str] = None
    stdout_bytes: int = Field(default=0, ge=0)
    truncated: bool = False

    @model_validator(mode="after")
    def _require_hash(self) -> "EvidenceArtifact":
        if not self.raw_output_sha256:
            raise ValueError("raw_output_sha256 is required")
        return self

    def summary(self) -> dict[str, Any]:
        """Compact provenance reference used in reports and LLM context."""
        return {
            "artifact_id": self.artifact_id,
            "source_tool": self.source_tool,
            "timestamp_utc": self.timestamp_utc,
            "invocation_params_hash": self.invocation_params_hash,
            "raw_output_sha256": self.raw_output_sha256,
            "parser_version": self.parser_version,
            "epistemic_status": self.epistemic_status.value,
            "confidence": round(self.confidence, 3),
            "snippet": self.raw_evidence_snippet[:500],
        }


# ════════════════════════════════════════════════════════════════════════
# Entities / claims
# ════════════════════════════════════════════════════════════════════════

class Entity(BaseModel):
    """A canonical, entity-resolved graph node."""

    model_config = ConfigDict(extra="forbid")

    entity_id: str
    investigation_id: str = ""
    type: EntityType
    canonical_value: str
    display_value: str
    aliases: list[str] = Field(default_factory=list)
    raw_values: list[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    created_by_artifact: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.canonical_value}"

    def summary(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "type": self.type.value,
            "value": self.canonical_value,
            "aliases": self.aliases[:5],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class Claim(BaseModel):
    """An evidence-backed assertion about an entity or a relationship.

    A claim has exactly one object: either another entity (relationship edge)
    or a JSON literal (attribute value).
    """

    model_config = ConfigDict(extra="forbid")

    claim_id: str
    investigation_id: str = ""
    subject_id: str
    predicate: str
    object_id: Optional[str] = None
    object_literal: Optional[Any] = None
    status: EpistemicStatus
    confidence: float = Field(ge=0.0, le=1.0)
    artifact_ids: list[str] = Field(default_factory=list)
    independent_sources: list[str] = Field(default_factory=list)
    first_seen: str
    updated_at: str
    direct: bool = False

    @model_validator(mode="after")
    def _exactly_one_object(self) -> "Claim":
        if (self.object_id is None) == (self.object_literal is None):
            raise ValueError("claim must have exactly one of object_id / object_literal")
        if not self.artifact_ids and self.status != EpistemicStatus.HYPOTHESIS:
            raise ValueError("non-hypothesis claim requires at least one artifact")
        return self

    @property
    def is_edge(self) -> bool:
        return self.object_id is not None

    @property
    def predicate_key(self) -> str:
        """Predicate used for functional-predicate comparison (attributes factor key)."""
        if self.predicate.startswith(FUNCTIONAL_PREDICATE_PREFIX):
            return self.predicate
        return self.predicate

    def object_display(self, entity_index: Optional[dict[str, "Entity"]] = None) -> str:
        if self.object_id is not None:
            if entity_index and self.object_id in entity_index:
                ent = entity_index[self.object_id]
                return f"{ent.type.value}:{ent.canonical_value}"
            return self.object_id
        return json.dumps(self.object_literal, sort_keys=True, default=str)

    def is_functional_conflict(self, other: "Claim") -> bool:
        """True if both claims are functional assertions with different objects."""
        if self.predicate != other.predicate:
            return False
        if not is_functional_predicate(self.predicate):
            return False
        if self.object_id is not None or other.object_id is not None:
            return self.object_id != other.object_id
        return canonical_json(self.object_literal) != canonical_json(other.object_literal)


class ClaimSource(BaseModel):
    """One independent evidence source supporting a claim."""

    model_config = ConfigDict(extra="forbid")

    source_tool: str
    reliability: float = Field(default=0.6, ge=0.0, le=1.0)
    artifact_id: str
    direct: bool = True
    snippet: str = ""


class Contradiction(BaseModel):
    """Two functional claims that assert different values for the same subject."""

    model_config = ConfigDict(extra="forbid")

    contradiction_id: str
    investigation_id: str = ""
    subject_id: str
    predicate: str
    claim_a: str
    claim_b: str
    created_at: str
    resolved: bool = False


# ════════════════════════════════════════════════════════════════════════
# Execution ledger
# ════════════════════════════════════════════════════════════════════════

class ExecutionRecord(BaseModel):
    """Ledger entry guaranteeing zero duplicate runs for one pivot."""

    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    entity_id: str
    tool_id: str
    param_hash: str
    status: ExecutionStatus
    error_code: Optional[ErrorCode] = None
    artifact_id: Optional[str] = None
    run_at: str
    duration_ms: int = Field(default=0, ge=0)
    error_message: str = ""


# ════════════════════════════════════════════════════════════════════════
# Hypotheses / objectives
# ════════════════════════════════════════════════════════════════════════

class Hypothesis(BaseModel):
    """An explicit investigative question linking known nodes to next actions."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    investigation_id: str = ""
    hypothesis_type: HypothesisType
    question: str
    target_entity_id: Optional[str] = None
    target_claim_id: Optional[str] = None
    proposed_tool_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    status: HypothesisStatus = HypothesisStatus.OPEN
    created_by: str = "planner"
    created_at: str
    updated_at: str
    closing_artifact_id: Optional[str] = None
    closing_note: str = ""


class Objective(BaseModel):
    """A core investigative objective used for deterministic stopping."""

    model_config = ConfigDict(extra="forbid")

    objective_id: str
    description: str
    entity_id: str
    required_status: EpistemicStatus = EpistemicStatus.CORROBORATED
    achieved: bool = False
    status: EpistemicStatus = EpistemicStatus.SINGLE_SOURCE_LEAD


# ════════════════════════════════════════════════════════════════════════
# Investigation configuration / state
# ════════════════════════════════════════════════════════════════════════

class ScopeConfig(BaseModel):
    """Code-enforced collection scope (allowlist / denylist)."""

    model_config = ConfigDict(extra="forbid")

    allow_domains: list[str] = Field(default_factory=list)
    deny_domains: list[str] = Field(default_factory=list)
    allow_ips: list[str] = Field(default_factory=list)        # IPs resolved from allowed domains
    allow_entities: list[str] = Field(default_factory=list)   # "email:x@y.z" or just values
    deny_entities: list[str] = Field(default_factory=list)
    # Passive-first safety default: active recon must be explicitly enabled.
    allow_active_recon: bool = False
    allow_authorized_tools: bool = False   # hashcat etc. off unless explicitly enabled
    allow_intrusive: bool = False          # hydra etc. ALWAYS blocked unless true
    block_private_addresses: bool = True

    def is_empty(self) -> bool:
        return not (self.allow_domains or self.allow_entities or self.deny_domains
                    or self.deny_entities)


class BudgetConfig(BaseModel):
    """Hard, deterministic execution budgets."""

    model_config = ConfigDict(extra="forbid")

    max_iterations: int = Field(default=20, ge=1, le=500)
    max_tool_calls: int = Field(default=30, ge=1, le=1000)
    wall_clock_timeout_sec: int = Field(default=900, ge=5, le=86400)


class PivotWeights(BaseModel):
    """Weights for the pivot score formula (w1..w4)."""

    model_config = ConfigDict(extra="forbid")

    # Non-negative weights; they are normalized to sum 1 by normalized().
    w1_info_gain: float = Field(default=0.45, ge=0.0)
    w2_corroboration: float = Field(default=0.30, ge=0.0)
    w3_hop_penalty: float = Field(default=0.15, ge=0.0)
    w4_cost: float = Field(default=0.10, ge=0.0)

    def normalized(self) -> "PivotWeights":
        total = self.w1_info_gain + self.w2_corroboration + self.w3_hop_penalty + self.w4_cost
        if total <= 0:
            return PivotWeights()
        return PivotWeights(
            w1_info_gain=self.w1_info_gain / total,
            w2_corroboration=self.w2_corroboration / total,
            w3_hop_penalty=self.w3_hop_penalty / total,
            w4_cost=self.w4_cost / total,
        )


class InvestigationConfig(BaseModel):
    """Complete config for one investigation run."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    raw_input: str
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)
    weights: PivotWeights = Field(default_factory=PivotWeights)
    min_pivot_threshold: float = Field(default=0.12, ge=0.0, le=1.0)
    top_k_pivots: int = Field(default=5, ge=1, le=50)
    max_concurrent_tools: int = Field(default=8, ge=1, le=64)
    max_hypotheses_per_entity: int = Field(default=3, ge=1, le=20)
    max_entities: int = Field(default=500, ge=10, le=100000)
    allow_hypothesis_expansion: bool = True
    collect_raw_artifacts: bool = True
    reflection_enabled: bool = True


class InvestigationState(BaseModel):
    """Top-level investigation metadata persisted in SQLite."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    raw_input: str
    created_at: str
    updated_at: str
    status: RunStatus = RunStatus.ACTIVE
    config: InvestigationConfig
    seed_entity_ids: list[str] = Field(default_factory=list)
    iteration_count: int = 0
    tool_calls: int = 0
    stop_reason: Optional[str] = None
    objectives: list[Objective] = Field(default_factory=list)


class IterationRecord(BaseModel):
    """Structured audit trail for one Plan/Execute/Normalize/Correlate/Score cycle."""

    model_config = ConfigDict(extra="forbid")

    iteration: int
    timestamp_utc: str
    action: dict[str, Any]
    result: dict[str, Any]
    artifact_ids: list[str] = Field(default_factory=list)
    new_entity_ids: list[str] = Field(default_factory=list)
    new_claims: int = 0
    contradictions: int = 0
    hypotheses_opened: int = 0
    hypotheses_closed: int = 0
    candidates_considered: int = 0
    candidate_count: int = 0
    duration_ms: int = 0


# ════════════════════════════════════════════════════════════════════════
# Capability manifest (Spec 3)
# ════════════════════════════════════════════════════════════════════════

class ParameterSpec(BaseModel):
    """Declaration of one tool parameter (auto-exported to JSON schema / MCP)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    type: str = "string"          # string | integer | number | boolean | array
    required: bool = False
    description: str = ""
    format: str = ""              # email | hostname | domain | ip | url | phone | hash
    enum: list[str] = Field(default_factory=list)
    items_type: str = "string"
    cli_flag: Optional[str] = None   # None => positional argument
    positional: bool = False

    def json_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {"type": self.type}
        if self.description:
            schema["description"] = self.description
        if self.format:
            schema["format"] = self.format
        if self.enum:
            schema["enum"] = self.enum
        if self.type == "array":
            schema["items"] = {"type": self.items_type}
        return schema


class InvocationSpec(BaseModel):
    """How a capability is executed (binary subprocess or builtin python function)."""

    model_config = ConfigDict(extra="forbid")

    kind: str = "binary"           # "binary" | "builtin"
    binary: Optional[str] = None
    cli_map: dict[str, Optional[str]] = Field(default_factory=dict)
    extra_flags: list[str] = Field(default_factory=list)
    prefix_args: list[str] = Field(default_factory=list)   # e.g. subcommand before flags
    builtin_ref: Optional[str] = None   # "hub.tools.builtin.dns_lookup:collect"
    api_key_envs: list[str] = Field(default_factory=list)
    #: Extra child env (trusted manifest values). Supports placeholders
    #: ``{tool_home}``, ``{repo_root}`` and ``{managed_bin}``.
    env: dict[str, str] = Field(default_factory=dict)
    #: Tolerate a non-zero exit when the tool still produced usable stdout
    #: (e.g. maigret exits 1 after completing its scan with site warnings).
    tolerate_nonzero_with_stdout: bool = False

    @model_validator(mode="after")
    def _validate_kind(self) -> "InvocationSpec":
        if self.kind not in {"binary", "builtin"}:
            raise ValueError("invocation kind must be 'binary' or 'builtin'")
        if self.kind == "binary" and not self.binary:
            raise ValueError("binary invocation requires a binary name")
        if self.kind == "builtin" and not self.builtin_ref:
            raise ValueError("builtin invocation requires a builtin_ref")
        return self


class ToolCapability(BaseModel):
    """Strict capability manifest — one per OSINT integration (Spec 3).

    Auto-generates LLM tool-calling schemas, MCP tool definitions and CLI
    capability tables via :mod:`hub.tools.capabilities`.
    """

    model_config = ConfigDict(extra="forbid")

    tool_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,40}$")
    display_name: str
    description: str
    accepted_entity_types: list[EntityType] = Field(default_factory=list)
    produced_entity_types: list[EntityType] = Field(default_factory=list)
    execution_mode: ExecutionMode = ExecutionMode.PASSIVE
    parameters: dict[str, ParameterSpec] = Field(default_factory=dict)
    timeout_sec: int = Field(default=120, ge=1, le=3600)
    rate_limit_rps: float = Field(default=0.5, gt=0.0, le=100.0)
    max_concurrency: Optional[int] = Field(default=None, ge=1, le=64)
    reliability: float = Field(default=0.6, ge=0.0, le=1.0)
    prior_yield: float = Field(default=0.5, ge=0.0, le=1.0)
    invocation: InvocationSpec
    parser_ref: str
    parser_version: str = "2.0.0"
    authorization_required: bool = False
    invocation_verified: bool = True
    #: Optional credential provider (``github``, ``virustotal``, ``shodan``,
    #: ``censys``, ``hunter``). Health checks report CONFIGURED / MISSING_KEY etc.
    auth_provider: Optional[str] = None
    notes: str = ""

    @model_validator(mode="after")
    def _validate_manifest(self) -> "ToolCapability":
        if ":" not in self.parser_ref:
            raise ValueError(f"{self.tool_id}: parser_ref must be 'module:function'")
        if not self.accepted_entity_types:
            raise ValueError(f"{self.tool_id}: must accept at least one entity type")
        if not self.produced_entity_types:
            raise ValueError(f"{self.tool_id}: must produce at least one entity type")
        if self.execution_mode == ExecutionMode.INTRUSIVE_BLOCKED and not self.authorization_required:
            raise ValueError(f"{self.tool_id}: INTRUSIVE_BLOCKED requires authorization_required=True")
        return self

    def parser(self):
        """Resolve and return the deterministic parser function."""
        from hub.tools.base import load_parser

        return load_parser(self.parser_ref)

    def accepts(self, entity_type: EntityType | str) -> bool:
        try:
            return EntityType.coerce(entity_type) in self.accepted_entity_types
        except ValueError:
            return False


class HealthStatus(BaseModel):
    """Result of a live capability health check."""

    model_config = ConfigDict(extra="forbid")

    tool_id: str
    available: bool
    kind: str
    detail: str
    binary_path: Optional[str] = None
    checked_at: str
    resolver: str = ""   # managed-home | managed-venv | python-wrapper | path | wsl | builtin
    #: Credential state: NOT_REQUIRED | CONFIGURED | KEYLESS_LIMITED |
    #: MISSING_KEY | PARTIAL | OPTIONAL_UNCONFIGURED.
    auth_status: str = "NOT_REQUIRED"
    auth_detail: str = ""

    @property
    def auth_ready(self) -> bool:
        """Whether the pivot planner/runtime may execute this tool unauthenticated."""
        return self.auth_status not in {
            "MISSING_KEY", "PARTIAL", "OPTIONAL_UNCONFIGURED",
        }

    def as_row(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "available": self.available,
            "kind": self.kind,
            "resolver": self.resolver,
            "detail": self.detail,
            "binary_path": self.binary_path or "",
            "auth_status": self.auth_status,
            "auth_detail": self.auth_detail,
            "auth_ready": self.auth_ready,
        }


class PivotCandidate(BaseModel):
    """One scored (TargetEntity, ToolCapability) pair."""

    model_config = ConfigDict(extra="forbid")

    pivot_id: str
    entity_id: str
    tool_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    expected_info_gain: float = Field(ge=0.0, le=1.0)
    corroboration_value: float = Field(ge=0.0, le=1.0)
    hop_distance: int = Field(default=0, ge=0)
    hop_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    execution_cost: float = Field(ge=0.0, le=1.0)
    score: float
    hypothesis_id: Optional[str] = None
    rationale: str = ""

    def score_breakdown(self) -> dict[str, float]:
        return {
            "expected_info_gain": round(self.expected_info_gain, 4),
            "corroboration_value": round(self.corroboration_value, 4),
            "hop_distance": self.hop_distance,
            "hop_penalty": round(self.hop_penalty, 4),
            "execution_cost": round(self.execution_cost, 4),
            "total": round(self.score, 4),
        }


# ════════════════════════════════════════════════════════════════════════
# Tool result models
# ════════════════════════════════════════════════════════════════════════

class ToolRunResult(BaseModel):
    """Raw outcome of one execution attempt (before parsing)."""

    model_config = ConfigDict(extra="forbid")

    tool_id: str
    entity_id: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    status: ExecutionStatus
    error_code: Optional[ErrorCode] = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: int = 0
    error_message: str = ""
    started_at: str = ""
    params_hash: str = ""


class ReflectionPacket(BaseModel):
    """Quarantined context handed to the LLM reasoning stage (stage 2)."""

    model_config = ConfigDict(extra="forbid")

    system_prompt: str
    task: str
    normalized_delta: dict[str, Any]
    graph_neighborhood: dict[str, Any]
    open_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    quarantined_external_data: str = ""
    expected_response_schema: dict[str, Any] = Field(default_factory=dict)


def compute_objective_status(statuses: list[EpistemicStatus]) -> EpistemicStatus:
    """Aggregate per-entity claim statuses into an objective status."""
    if not statuses:
        return EpistemicStatus.COLLECTION_FAILURE
    if any(s == EpistemicStatus.CONFIRMED for s in statuses):
        return EpistemicStatus.CONFIRMED
    if any(s == EpistemicStatus.CORROBORATED for s in statuses):
        return EpistemicStatus.CORROBORATED
    if any(s == EpistemicStatus.CONTRADICTED for s in statuses):
        return EpistemicStatus.CONTRADICTED
    if any(s == EpistemicStatus.SINGLE_SOURCE_LEAD for s in statuses):
        return EpistemicStatus.SINGLE_SOURCE_LEAD
    if any(s == EpistemicStatus.HYPOTHESIS for s in statuses):
        return EpistemicStatus.HYPOTHESIS
    return EpistemicStatus.COLLECTION_FAILURE


__all__ = [
    "SCHEMA_VERSION",
    "EntityType",
    "EpistemicStatus",
    "EdgeType",
    "ExecutionStatus",
    "ErrorCode",
    "ExecutionMode",
    "HypothesisType",
    "HypothesisStatus",
    "RunStatus",
    "SourceKind",
    "SATISFIED_STATUSES",
    "UNVERIFIED_STATUSES",
    "FUNCTIONAL_PREDICATES",
    "FUNCTIONAL_PREDICATE_PREFIX",
    "NON_FUNCTIONAL_ATTRIBUTE_KEYS",
    "is_functional_predicate",
    "EvidenceArtifact",
    "Entity",
    "Claim",
    "ClaimSource",
    "Contradiction",
    "ExecutionRecord",
    "Hypothesis",
    "Objective",
    "ScopeConfig",
    "BudgetConfig",
    "PivotWeights",
    "InvestigationConfig",
    "InvestigationState",
    "IterationRecord",
    "ParameterSpec",
    "InvocationSpec",
    "ToolCapability",
    "HealthStatus",
    "PivotCandidate",
    "ToolRunResult",
    "ReflectionPacket",
    "utc_now",
    "canonical_json",
    "sha256_text",
    "param_hash",
    "short_id",
    "compute_objective_status",
]
