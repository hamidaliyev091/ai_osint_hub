"""ERKG persistence engine — SQLite with WAL, claims, provenance and ledger.

Design:
  * WAL journal + NORMAL sync + 5s busy timeout => concurrent readers/writers
    and async workers never crash with "database is locked".
  * One connection per store instance, guarded by an RLock; writes run in
    ``BEGIN IMMEDIATE`` transactions. An engine iteration commits atomically,
    so a crash resumes from the last committed iteration.
  * Artifacts are immutable: inserts only, duplicates are ignored.
  * Execution ledger is keyed by (investigation, entity, tool, param_hash) so
    the planner can guarantee zero duplicate tool runs.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from hub.erkg import confidence as epistemic
from hub.models import (
    Claim,
    ClaimSource,
    Contradiction,
    Entity,
    EntityType,
    EpistemicStatus,
    ErrorCode,
    EvidenceArtifact,
    ExecutionRecord,
    ExecutionStatus,
    Hypothesis,
    HypothesisStatus,
    InvestigationConfig,
    InvestigationState,
    IterationRecord,
    Objective,
    RunStatus,
    canonical_json,
    sha256_text,
    short_id,
    utc_now,
)

SCHEMA_VERSION = "2.0.0"
BUSY_TIMEOUT_MS = 5000
_UNSET = object()


def default_home() -> Path:
    """Default state root: ``$AI_OSINT_HUB_HOME`` or ``~/.ai_osint_hub``."""
    env = os.environ.get("AI_OSINT_HUB_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".ai_osint_hub").resolve()


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigations (
    target_id TEXT PRIMARY KEY,
    raw_input TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    config_json TEXT NOT NULL,
    seed_entity_ids_json TEXT NOT NULL DEFAULT '[]',
    iteration_count INTEGER NOT NULL DEFAULT 0,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    stop_reason TEXT,
    objectives_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    invocation_params_hash TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    raw_evidence_snippet TEXT NOT NULL DEFAULT '',
    raw_output_sha256 TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    epistemic_status TEXT NOT NULL,
    confidence REAL NOT NULL,
    raw_output_path TEXT,
    stdout_bytes INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_artifacts_inv ON artifacts(investigation_id);

CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    type TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    display_value TEXT NOT NULL,
    aliases_json TEXT NOT NULL DEFAULT '[]',
    raw_values_json TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_by_artifact TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (investigation_id, type, canonical_value)
);
CREATE INDEX IF NOT EXISTS idx_entities_inv_type ON entities(investigation_id, type);

CREATE TABLE IF NOT EXISTS entity_aliases (
    investigation_id TEXT NOT NULL,
    alias_key TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    PRIMARY KEY (investigation_id, alias_key)
);
CREATE INDEX IF NOT EXISTS idx_aliases_entity ON entity_aliases(entity_id);

CREATE TABLE IF NOT EXISTS claims (
    claim_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    predicate TEXT NOT NULL,
    object_id TEXT,
    object_literal TEXT,
    status TEXT NOT NULL CHECK (status IN (
        'CONFIRMED','CORROBORATED','SINGLE_SOURCE_LEAD','HYPOTHESIS','CONTRADICTED','COLLECTION_FAILURE'
    )),
    confidence REAL NOT NULL,
    independent_sources_json TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    direct INTEGER NOT NULL DEFAULT 0,
    CHECK ((object_id IS NULL) + (object_literal IS NULL) = 1)
);
CREATE INDEX IF NOT EXISTS idx_claims_subject ON claims(investigation_id, subject_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(investigation_id, status);
CREATE INDEX IF NOT EXISTS idx_claims_object ON claims(investigation_id, object_id);

CREATE TABLE IF NOT EXISTS claim_artifacts (
    claim_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    snippet TEXT NOT NULL DEFAULT '',
    direct INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (claim_id, artifact_id, source_tool)
);
CREATE INDEX IF NOT EXISTS idx_claim_artifacts_claim ON claim_artifacts(claim_id);

CREATE TABLE IF NOT EXISTS contradictions (
    contradiction_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    predicate TEXT NOT NULL,
    claim_a TEXT NOT NULL,
    claim_b TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0,
    UNIQUE (investigation_id, claim_a, claim_b)
);

CREATE TABLE IF NOT EXISTS execution_ledger (
    investigation_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    param_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SUCCESS','EMPTY','TIMEOUT','ERROR')),
    error_code TEXT,
    artifact_id TEXT,
    run_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (investigation_id, entity_id, tool_id, param_hash)
);
CREATE INDEX IF NOT EXISTS idx_ledger_inv ON execution_ledger(investigation_id);

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    hypothesis_type TEXT NOT NULL,
    question TEXT NOT NULL,
    target_entity_id TEXT,
    target_claim_id TEXT,
    proposed_tool_ids_json TEXT NOT NULL DEFAULT '[]',
    rationale TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_by TEXT NOT NULL DEFAULT 'planner',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closing_artifact_id TEXT,
    closing_note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_inv_status ON hypotheses(investigation_id, status);

CREATE TABLE IF NOT EXISTS iterations (
    investigation_id TEXT NOT NULL,
    iteration INTEGER NOT NULL,
    timestamp_utc TEXT NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (investigation_id, iteration)
);
"""


class ERKGStore:
    """SQLite-backed Entity-Resolved Knowledge Graph store."""

    def __init__(self, path: str | os.PathLike, *,
                 investigation_id: Optional[str] = None,
                 auto_schema: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.investigation_id = investigation_id
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                     isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._in_transaction = False
        if auto_schema:
            with self._lock:
                self._conn.executescript(_SCHEMA)
                self._conn.execute(
                    "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('schema_version', ?)",
                    (SCHEMA_VERSION,),
                )

    # ── lifecycle ───────────────────────────────────────────────────

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "ERKGStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ── transaction helpers ─────────────────────────────────────────

    @contextmanager
    def transaction(self) -> Iterator["ERKGStore"]:
        """BEGIN IMMEDIATE ... COMMIT, nested-aware."""
        with self._lock:
            if self._in_transaction:
                yield self
                return
            self._conn.execute("BEGIN IMMEDIATE")
            self._in_transaction = True
            try:
                yield self
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            finally:
                self._in_transaction = False

    def _execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def _write(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            if self._in_transaction:
                return self._conn.execute(sql, tuple(params))
            with self.transaction():
                return self._conn.execute(sql, tuple(params))

    def _query_all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def _query_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchone()

    def pragmas(self) -> dict[str, Any]:
        with self._lock:
            journal = self._conn.execute("PRAGMA journal_mode").fetchone()[0]
            sync = self._conn.execute("PRAGMA synchronous").fetchone()[0]
            busy = self._conn.execute("PRAGMA busy_timeout").fetchone()[0]
        return {"journal_mode": journal, "synchronous": sync, "busy_timeout": busy}

    # ════════════════════════════════════════════════════════════════
    # Investigations
    # ════════════════════════════════════════════════════════════════

    def create_investigation(self, state: InvestigationState) -> InvestigationState:
        self._write(
            """INSERT OR REPLACE INTO investigations
               (target_id, raw_input, created_at, updated_at, status, config_json,
                seed_entity_ids_json, iteration_count, tool_calls, stop_reason,
                objectives_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                state.target_id, state.raw_input, state.created_at, state.updated_at,
                state.status.value, canonical_json(state.config.model_dump(mode="json")),
                canonical_json(state.seed_entity_ids), state.iteration_count,
                state.tool_calls, state.stop_reason,
                canonical_json([o.model_dump(mode="json") for o in state.objectives]),
            ),
        )
        return state

    def get_investigation(self, target_id: str) -> Optional[InvestigationState]:
        row = self._query_one("SELECT * FROM investigations WHERE target_id=?", (target_id,))
        if row is None:
            return None
        return self._row_to_investigation(row)

    def list_investigations(self) -> list[InvestigationState]:
        rows = self._query_all("SELECT * FROM investigations ORDER BY created_at DESC")
        return [self._row_to_investigation(row) for row in rows]

    def investigation_exists(self, target_id: str) -> bool:
        return self._query_one("SELECT 1 FROM investigations WHERE target_id=?",
                               (target_id,)) is not None

    def update_investigation(self, target_id: str, **fields: Any) -> None:
        allowed = {
            "raw_input", "updated_at", "status", "config_json", "seed_entity_ids_json",
            "iteration_count", "tool_calls", "stop_reason", "objectives_json",
        }
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        for key in ("seed_entity_ids_json", "objectives_json"):
            if key in updates and not isinstance(updates[key], str):
                updates[key] = canonical_json(updates[key])
        if "status" in updates and isinstance(updates["status"], RunStatus):
            updates["status"] = updates["status"].value
        sets = ", ".join(f"{k}=?" for k in updates)
        self._write(f"UPDATE investigations SET {sets} WHERE target_id=?",
                    (*updates.values(), target_id))

    def bump_counters(self, target_id: str, *, iterations: int = 0,
                      tool_calls: int = 0, timestamp: Optional[str] = None) -> None:
        self._write(
            """UPDATE investigations
               SET iteration_count = iteration_count + ?,
                   tool_calls = tool_calls + ?,
                   updated_at = ?
               WHERE target_id=?""",
            (iterations, tool_calls, timestamp or utc_now(), target_id),
        )

    def finish_investigation(self, target_id: str, status: RunStatus,
                             stop_reason: str) -> None:
        self.update_investigation(target_id, status=status.value,
                                  stop_reason=stop_reason, updated_at=utc_now())

    def set_objectives(self, target_id: str, objectives: list[Objective]) -> None:
        self.update_investigation(
            target_id,
            objectives_json=[o.model_dump(mode="json") for o in objectives],
            updated_at=utc_now(),
        )

    def _row_to_investigation(self, row: sqlite3.Row) -> InvestigationState:
        config_data = json.loads(row["config_json"])
        return InvestigationState(
            target_id=row["target_id"],
            raw_input=row["raw_input"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=RunStatus(row["status"]),
            config=InvestigationConfig.model_validate(config_data),
            seed_entity_ids=json.loads(row["seed_entity_ids_json"] or "[]"),
            iteration_count=row["iteration_count"],
            tool_calls=row["tool_calls"],
            stop_reason=row["stop_reason"],
            objectives=[Objective.model_validate(o)
                        for o in json.loads(row["objectives_json"] or "[]")],
        )

    # ════════════════════════════════════════════════════════════════
    # Evidence artifacts (immutable)
    # ════════════════════════════════════════════════════════════════

    def add_artifact(self, artifact: EvidenceArtifact) -> str:
        """Insert an immutable artifact. Existing identical id is left untouched."""
        self._write(
            """INSERT OR IGNORE INTO artifacts
               (artifact_id, investigation_id, source_tool, invocation_params_hash,
                timestamp_utc, raw_evidence_snippet, raw_output_sha256, parser_version,
                epistemic_status, confidence, raw_output_path, stdout_bytes, truncated)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                artifact.artifact_id, artifact.investigation_id, artifact.source_tool,
                artifact.invocation_params_hash, artifact.timestamp_utc,
                artifact.raw_evidence_snippet[:4000], artifact.raw_output_sha256,
                artifact.parser_version, artifact.epistemic_status.value,
                artifact.confidence, artifact.raw_output_path, artifact.stdout_bytes,
                int(artifact.truncated),
            ),
        )
        return artifact.artifact_id

    def get_artifact(self, artifact_id: str) -> Optional[EvidenceArtifact]:
        row = self._query_one("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,))
        return self._row_to_artifact(row) if row else None

    def list_artifacts(self, investigation_id: str) -> list[EvidenceArtifact]:
        rows = self._query_all(
            "SELECT * FROM artifacts WHERE investigation_id=? ORDER BY timestamp_utc",
            (investigation_id,),
        )
        return [self._row_to_artifact(r) for r in rows]

    def _row_to_artifact(self, row: sqlite3.Row) -> EvidenceArtifact:
        return EvidenceArtifact(
            artifact_id=row["artifact_id"],
            investigation_id=row["investigation_id"],
            source_tool=row["source_tool"],
            invocation_params_hash=row["invocation_params_hash"],
            timestamp_utc=row["timestamp_utc"],
            raw_evidence_snippet=row["raw_evidence_snippet"],
            raw_output_sha256=row["raw_output_sha256"],
            parser_version=row["parser_version"],
            epistemic_status=EpistemicStatus(row["epistemic_status"]),
            confidence=row["confidence"],
            raw_output_path=row["raw_output_path"],
            stdout_bytes=row["stdout_bytes"],
            truncated=bool(row["truncated"]),
        )

    # ════════════════════════════════════════════════════════════════
    # Entities
    # ════════════════════════════════════════════════════════════════

    def insert_entity(self, investigation_id: str, entity: Entity,
                      *, alias_keys: Iterable[str] = ()) -> None:
        self._write(
            """INSERT OR IGNORE INTO entities
               (entity_id, investigation_id, type, canonical_value, display_value,
                aliases_json, raw_values_json, first_seen, last_seen,
                created_by_artifact, metadata_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                entity.entity_id, investigation_id, entity.type.value,
                entity.canonical_value, entity.display_value,
                canonical_json(entity.aliases), canonical_json(entity.raw_values),
                entity.first_seen, entity.last_seen, entity.created_by_artifact,
                canonical_json(entity.metadata),
            ),
        )
        self._insert_aliases(investigation_id, entity.entity_id, alias_keys)

    def _insert_aliases(self, investigation_id: str, entity_id: str,
                        alias_keys: Iterable[str]) -> None:
        for key in alias_keys:
            if not key:
                continue
            self._write(
                """INSERT OR IGNORE INTO entity_aliases (investigation_id, alias_key, entity_id)
                   VALUES (?,?,?)""",
                (investigation_id, key, entity_id),
            )

    def find_entity_by_alias(self, investigation_id: str, alias_key: str) -> Optional[str]:
        row = self._query_one(
            "SELECT entity_id FROM entity_aliases WHERE investigation_id=? AND alias_key=?",
            (investigation_id, alias_key),
        )
        return row["entity_id"] if row else None

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        row = self._query_one("SELECT * FROM entities WHERE entity_id=?", (entity_id,))
        return self._row_to_entity(row) if row else None

    def get_entity_by_value(self, investigation_id: str, entity_type: EntityType | str,
                            canonical_value: str) -> Optional[Entity]:
        etype = EntityType.coerce(entity_type)
        row = self._query_one(
            """SELECT * FROM entities
               WHERE investigation_id=? AND type=? AND canonical_value=?""",
            (investigation_id, etype.value, canonical_value),
        )
        return self._row_to_entity(row) if row else None

    def list_entities(self, investigation_id: str,
                      types: Optional[Iterable[EntityType | str]] = None) -> list[Entity]:
        if types:
            type_values = [EntityType.coerce(t).value for t in types]
            placeholders = ",".join("?" for _ in type_values)
            rows = self._query_all(
                f"SELECT * FROM entities WHERE investigation_id=? AND type IN ({placeholders})",
                (investigation_id, *type_values),
            )
        else:
            rows = self._query_all(
                "SELECT * FROM entities WHERE investigation_id=? ORDER BY first_seen",
                (investigation_id,),
            )
        return [self._row_to_entity(r) for r in rows]

    def count_entities(self, investigation_id: str) -> int:
        row = self._query_one(
            "SELECT COUNT(*) AS c FROM entities WHERE investigation_id=?",
            (investigation_id,),
        )
        return int(row["c"]) if row else 0

    def update_entity_metadata(self, entity_id: str, metadata: dict[str, Any],
                               timestamp: Optional[str] = None) -> None:
        entity = self.get_entity(entity_id)
        if entity is None:
            return
        merged = {**entity.metadata, **metadata}
        self._write(
            "UPDATE entities SET metadata_json=?, last_seen=? WHERE entity_id=?",
            (canonical_json(merged), timestamp or utc_now(), entity_id),
        )

    def merge_entity_metadata(self, entity_id: str, metadata: dict) -> None:
        """Merge metadata keys into an existing entity (provenance promotion)."""
        entity = self.get_entity(entity_id)
        if entity is None:
            return
        merged = dict(entity.metadata or {})
        merged.update({str(key): value for key, value in (metadata or {}).items()})
        self._write("UPDATE entities SET metadata_json=? WHERE entity_id=?",
                    (canonical_json(merged), entity_id))

    def touch_entity(self, entity_id: str, *, raw_value: str,
                     aliases: Iterable[str], alias_keys: Iterable[str],
                     timestamp: str,
                     metadata: Optional[dict] = None) -> None:
        entity = self.get_entity(entity_id)
        if entity is None:
            return
        raw_values = list(entity.raw_values)
        if raw_value and raw_value not in raw_values:
            raw_values.append(raw_value)
        alias_list = list(entity.aliases)
        for alias in list(aliases) + [raw_value]:
            if alias and alias not in alias_list:
                alias_list.append(alias)
        merged_metadata = dict(entity.metadata or {})
        for key, value in (metadata or {}).items():
            # Never erase an existing provenance; fill/merge additional facts.
            if key not in merged_metadata or value not in (None, ""):
                merged_metadata[key] = value
        self._write(
            "UPDATE entities SET raw_values_json=?, aliases_json=?, metadata_json=?, "
            "last_seen=? WHERE entity_id=?",
            (canonical_json(raw_values), canonical_json(alias_list),
             canonical_json(merged_metadata), timestamp, entity_id),
        )
        self._insert_aliases(entity.investigation_id, entity_id, alias_keys)

    def _row_to_entity(self, row: sqlite3.Row) -> Entity:
        return Entity(
            entity_id=row["entity_id"],
            investigation_id=row["investigation_id"],
            type=EntityType(row["type"]),
            canonical_value=row["canonical_value"],
            display_value=row["display_value"],
            aliases=json.loads(row["aliases_json"] or "[]"),
            raw_values=json.loads(row["raw_values_json"] or "[]"),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            created_by_artifact=row["created_by_artifact"],
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    # ════════════════════════════════════════════════════════════════
    # Claims + provenance
    # ════════════════════════════════════════════════════════════════

    def upsert_claim(self, investigation_id: str, subject_id: str, predicate: str,
                     *, object_id: Optional[str] = None,
                     object_literal: Any = _UNSET,
                     artifact_id: Optional[str] = None,
                     source_tool: str = "seed",
                     timestamp: Optional[str] = None,
                     direct: bool = True,
                     snippet: str = "",
                     confidence_hint: Optional[float] = None) -> Claim:
        """Insert or strengthen a claim; detect functional-predicate contradictions."""
        if (object_id is None) == (object_literal is _UNSET):
            raise ValueError("claim needs exactly one of object_id / object_literal")
        if object_id is not None and object_id == subject_id:
            raise ValueError("self-referential edge claims are not allowed")
        if artifact_id is None and source_tool != "planner":
            raise ValueError("evidence-backed claim requires an immutable artifact_id")
        timestamp = timestamp or utc_now()
        predicate = str(predicate)
        literal_json = None if object_id is not None else canonical_json(object_literal)
        existing = self._find_claim_by_object(investigation_id, subject_id, predicate,
                                              object_id, literal_json)
        if existing is not None:
            claim_id = existing["claim_id"]
            if artifact_id:
                self._write(
                    """INSERT OR IGNORE INTO claim_artifacts
                       (claim_id, artifact_id, source_tool, snippet, direct)
                       VALUES (?,?,?,?,?)""",
                    (claim_id, artifact_id, source_tool, snippet[:2000], int(direct)),
                )
            self._recompute_claim(claim_id)
            return self.get_claim(claim_id)  # type: ignore[return-value]

        # New claim: check for a functional conflict with a different object.
        # Planner-only HYPOTHESIS claims have no artifact and must never be
        # marked CONTRADICTED (the evidence invariant requires artifacts).
        conflict = None
        if artifact_id is not None and self._is_functional(predicate):
            for row in self._claims_for_subject_predicate(investigation_id, subject_id, predicate):
                if row["object_id"] != object_id or (row["object_literal"] or "") != (literal_json or ""):
                    conflict = row
                    break

        claim_id = short_id("claim", investigation_id, subject_id, predicate,
                            object_id if object_id is not None else literal_json)
        sources: list[ClaimSource] = []
        if artifact_id is not None:
            sources = [ClaimSource(
                source_tool=source_tool,
                reliability=(confidence_hint if confidence_hint is not None
                             else epistemic.reliability_for_tool(source_tool)),
                artifact_id=artifact_id,
                direct=direct,
                snippet=snippet[:500],
            )]
        status, confidence = epistemic.assess(
            sources,
            hypothesis_confidence=confidence_hint or epistemic.HYPOTHESIS_CONFIDENCE,
        )
        self._write(
            """INSERT OR IGNORE INTO claims
               (claim_id, investigation_id, subject_id, predicate, object_id, object_literal,
                status, confidence, independent_sources_json, first_seen, updated_at, direct)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                claim_id, investigation_id, subject_id, predicate, object_id, literal_json,
                status.value, confidence,
                canonical_json([s.source_tool for s in sources if s.artifact_id]),
                timestamp, timestamp, int(direct),
            ),
        )
        if artifact_id:
            self._write(
                """INSERT OR IGNORE INTO claim_artifacts
                   (claim_id, artifact_id, source_tool, snippet, direct) VALUES (?,?,?,?,?)""",
                (claim_id, artifact_id, source_tool, snippet[:2000], int(direct)),
            )
        if conflict is not None:
            self._mark_contradiction(investigation_id, subject_id, predicate,
                                     claim_id, conflict["claim_id"], timestamp)
        return self.get_claim(claim_id)  # type: ignore[return-value]

    def add_hypothesis_claim(self, investigation_id: str, subject_id: str,
                             predicate: str, *, object_id: Optional[str] = None,
                             object_literal: Any = _UNSET,
                             timestamp: Optional[str] = None,
                             confidence: float = 0.30) -> Claim:
        """Create a planner-generated HYPOTHESIS claim (no artifact required)."""
        return self.upsert_claim(
            investigation_id, subject_id, predicate, object_id=object_id,
            object_literal=object_literal, artifact_id=None, source_tool="planner",
            timestamp=timestamp, direct=False, confidence_hint=confidence,
        )

    def _is_functional(self, predicate: str) -> bool:
        from hub.models import is_functional_predicate

        return is_functional_predicate(predicate)

    def _claims_for_subject_predicate(self, investigation_id: str, subject_id: str,
                                      predicate: str) -> list[sqlite3.Row]:
        return self._query_all(
            """SELECT * FROM claims
               WHERE investigation_id=? AND subject_id=? AND predicate=?""",
            (investigation_id, subject_id, predicate),
        )

    def _find_claim_by_object(self, investigation_id: str, subject_id: str,
                              predicate: str, object_id: Optional[str],
                              literal_json: Optional[str]) -> Optional[sqlite3.Row]:
        if object_id is not None:
            return self._query_one(
                """SELECT * FROM claims WHERE investigation_id=? AND subject_id=?
                   AND predicate=? AND object_id=?""",
                (investigation_id, subject_id, predicate, object_id),
            )
        return self._query_one(
            """SELECT * FROM claims WHERE investigation_id=? AND subject_id=?
               AND predicate=? AND object_literal=?""",
            (investigation_id, subject_id, predicate, literal_json),
        )

    def _mark_contradiction(self, investigation_id: str, subject_id: str,
                            predicate: str, claim_a: str, claim_b: str,
                            timestamp: str) -> None:
        # Only evidence-backed claims can be marked CONTRADICTED; an artifact-less
        # hypothesis is left as a hypothesis (spec: non-hypothesis claims need evidence).
        for claim_id in (claim_a, claim_b):
            row = self._query_one(
                "SELECT 1 FROM claim_artifacts WHERE claim_id=? LIMIT 1", (claim_id,))
            if row is None:
                return
        a, b = sorted([claim_a, claim_b])
        contradiction_id = short_id("con", investigation_id, subject_id, predicate, a, b)
        self._write(
            """INSERT OR IGNORE INTO contradictions
               (contradiction_id, investigation_id, subject_id, predicate, claim_a,
                claim_b, created_at, resolved)
               VALUES (?,?,?,?,?,?,?,0)""",
            (contradiction_id, investigation_id, subject_id, predicate, a, b, timestamp),
        )
        for claim_id in (a, b):
            self._write(
                "UPDATE claims SET status=?, confidence=?, updated_at=? WHERE claim_id=?",
                (EpistemicStatus.CONTRADICTED.value,
                 epistemic.CONTRADICTED_CONFIDENCE, timestamp, claim_id),
            )

    def _recompute_claim(self, claim_id: str) -> None:
        claim_row = self._query_one("SELECT * FROM claims WHERE claim_id=?", (claim_id,))
        if claim_row is None:
            return
        sources = self.get_claim_sources(claim_id)
        contradicted = self._query_one(
            "SELECT 1 FROM contradictions WHERE claim_a=? OR claim_b=? LIMIT 1",
            (claim_id, claim_id),
        ) is not None
        hypothesis = claim_row["status"] == EpistemicStatus.HYPOTHESIS.value and not sources
        status, confidence = epistemic.assess(
            sources, contradicted=contradicted,
            hypothesis_confidence=claim_row["confidence"] if hypothesis else 0.30,
        )
        self._write(
            """UPDATE claims SET status=?, confidence=?, independent_sources_json=?,
               updated_at=? WHERE claim_id=?""",
            (
                status.value, confidence,
                canonical_json(sorted({s.source_tool for s in sources})),
                utc_now(), claim_id,
            ),
        )

    def get_claim(self, claim_id: str) -> Optional[Claim]:
        row = self._query_one("SELECT * FROM claims WHERE claim_id=?", (claim_id,))
        if row is None:
            return None
        return self._row_to_claim(row)

    def list_claims(self, investigation_id: str, *,
                    statuses: Optional[Iterable[EpistemicStatus]] = None,
                    subject_id: Optional[str] = None,
                    predicate: Optional[str] = None,
                    object_id: Optional[str] = None) -> list[Claim]:
        sql = "SELECT * FROM claims WHERE investigation_id=?"
        params: list[Any] = [investigation_id]
        if statuses:
            status_values = [s.value if isinstance(s, EpistemicStatus) else str(s)
                             for s in statuses]
            sql += f" AND status IN ({','.join('?' for _ in status_values)})"
            params.extend(status_values)
        if subject_id:
            sql += " AND subject_id=?"
            params.append(subject_id)
        if predicate:
            sql += " AND predicate=?"
            params.append(predicate)
        if object_id:
            sql += " AND object_id=?"
            params.append(object_id)
        sql += " ORDER BY updated_at DESC"
        return [self._row_to_claim(r) for r in self._query_all(sql, params)]

    def get_claims_for_entities(self, investigation_id: str,
                                entity_ids: Iterable[str]) -> list[Claim]:
        ids = list(entity_ids)
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        rows = self._query_all(
            f"""SELECT * FROM claims WHERE investigation_id=?
                AND (subject_id IN ({placeholders}) OR object_id IN ({placeholders}))""",
            (investigation_id, *ids, *ids),
        )
        return [self._row_to_claim(r) for r in rows]

    def count_claims(self, investigation_id: str,
                     statuses: Optional[Iterable[EpistemicStatus]] = None) -> int:
        if statuses:
            values = [s.value for s in statuses]
            placeholders = ",".join("?" for _ in values)
            row = self._query_one(
                f"SELECT COUNT(*) c FROM claims WHERE investigation_id=? AND status IN ({placeholders})",
                (investigation_id, *values),
            )
        else:
            row = self._query_one(
                "SELECT COUNT(*) c FROM claims WHERE investigation_id=?",
                (investigation_id,),
            )
        return int(row["c"]) if row else 0

    def claim_status_counts(self, investigation_id: str) -> dict[str, int]:
        rows = self._query_all(
            "SELECT status, COUNT(*) c FROM claims WHERE investigation_id=? GROUP BY status",
            (investigation_id,),
        )
        return {row["status"]: int(row["c"]) for row in rows}

    def get_claim_sources(self, claim_id: str) -> list[ClaimSource]:
        rows = self._query_all(
            "SELECT * FROM claim_artifacts WHERE claim_id=?", (claim_id,)
        )
        sources: list[ClaimSource] = []
        for row in rows:
            sources.append(ClaimSource(
                source_tool=row["source_tool"],
                reliability=epistemic.reliability_for_tool(row["source_tool"]),
                artifact_id=row["artifact_id"],
                direct=bool(row["direct"]),
                snippet=row["snippet"],
            ))
        return sources

    def get_claim_artifacts(self, claim_id: str) -> list[EvidenceArtifact]:
        rows = self._query_all(
            """SELECT a.* FROM artifacts a
               JOIN claim_artifacts ca ON ca.artifact_id = a.artifact_id
               WHERE ca.claim_id=? ORDER BY a.timestamp_utc""",
            (claim_id,),
        )
        return [self._row_to_artifact(r) for r in rows]

    def get_edges(self, investigation_id: str,
                  statuses: Optional[Iterable[EpistemicStatus]] = None) -> list[Claim]:
        sql = ("SELECT * FROM claims WHERE investigation_id=? AND object_id IS NOT NULL")
        params: list[Any] = [investigation_id]
        if statuses:
            values = [s.value for s in statuses]
            sql += f" AND status IN ({','.join('?' for _ in values)})"
            params.extend(values)
        return [self._row_to_claim(r) for r in self._query_all(sql, params)]

    def _row_to_claim(self, row: sqlite3.Row) -> Claim:
        literal = None
        if row["object_literal"] is not None:
            try:
                literal = json.loads(row["object_literal"])
            except (json.JSONDecodeError, TypeError):
                literal = row["object_literal"]
        return Claim(
            claim_id=row["claim_id"],
            investigation_id=row["investigation_id"],
            subject_id=row["subject_id"],
            predicate=row["predicate"],
            object_id=row["object_id"],
            object_literal=literal,
            status=EpistemicStatus(row["status"]),
            confidence=row["confidence"],
            artifact_ids=[s.artifact_id for s in self.get_claim_sources(row["claim_id"])
                          if s.artifact_id],
            independent_sources=json.loads(row["independent_sources_json"] or "[]"),
            first_seen=row["first_seen"],
            updated_at=row["updated_at"],
            direct=bool(row["direct"]),
        )

    # ── contradictions ──────────────────────────────────────────────

    def list_contradictions(self, investigation_id: str,
                            *, resolved: Optional[bool] = None) -> list[Contradiction]:
        sql = "SELECT * FROM contradictions WHERE investigation_id=?"
        params: list[Any] = [investigation_id]
        if resolved is not None:
            sql += " AND resolved=?"
            params.append(int(resolved))
        rows = self._query_all(sql, params)
        return [Contradiction(
            contradiction_id=r["contradiction_id"],
            investigation_id=r["investigation_id"],
            subject_id=r["subject_id"],
            predicate=r["predicate"],
            claim_a=r["claim_a"],
            claim_b=r["claim_b"],
            created_at=r["created_at"],
            resolved=bool(r["resolved"]),
        ) for r in rows]

    # ════════════════════════════════════════════════════════════════
    # Execution ledger
    # ════════════════════════════════════════════════════════════════

    def record_execution(self, record: ExecutionRecord) -> None:
        self._write(
            """INSERT OR REPLACE INTO execution_ledger
               (investigation_id, entity_id, tool_id, param_hash, status, error_code,
                artifact_id, run_at, duration_ms, error_message)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                record.investigation_id, record.entity_id, record.tool_id,
                record.param_hash, record.status.value,
                record.error_code.value if record.error_code else None,
                record.artifact_id, record.run_at, record.duration_ms,
                record.error_message[:2000],
            ),
        )

    def try_claim_execution(self, record: ExecutionRecord) -> bool:
        """Atomically claim one pivot invocation for execution (cross-process).

        The first writer inserts an in-flight ERROR/SPAWN_ERROR row; concurrent
        workers (other processes/threads) fail to insert and therefore never
        duplicate the tool run. The final ``record_execution`` overwrites the
        claim with the real outcome.
        """
        cursor = self._write(
            """INSERT INTO execution_ledger
               (investigation_id, entity_id, tool_id, param_hash, status, error_code,
                artifact_id, run_at, duration_ms, error_message)
               SELECT ?,?,?,?,?,?,?,?,?,?
               WHERE NOT EXISTS (
                   SELECT 1 FROM execution_ledger
                   WHERE investigation_id=? AND entity_id=? AND tool_id=? AND param_hash=?
               )""",
            (
                record.investigation_id, record.entity_id, record.tool_id,
                record.param_hash, record.status.value,
                record.error_code.value if record.error_code else None,
                record.artifact_id, record.run_at, record.duration_ms,
                record.error_message[:2000],
                record.investigation_id, record.entity_id, record.tool_id,
                record.param_hash,
            ),
        )
        return cursor.rowcount > 0

    def has_execution(self, investigation_id: str, entity_id: str, tool_id: str,
                      param_hash: str) -> bool:
        return self._query_one(
            """SELECT 1 FROM execution_ledger
               WHERE investigation_id=? AND entity_id=? AND tool_id=? AND param_hash=?""",
            (investigation_id, entity_id, tool_id, param_hash),
        ) is not None

    def get_execution(self, investigation_id: str, entity_id: str, tool_id: str,
                      param_hash: str) -> Optional[ExecutionRecord]:
        row = self._query_one(
            """SELECT * FROM execution_ledger
               WHERE investigation_id=? AND entity_id=? AND tool_id=? AND param_hash=?""",
            (investigation_id, entity_id, tool_id, param_hash),
        )
        return self._row_to_execution(row) if row else None

    def list_ledger(self, investigation_id: str,
                    statuses: Optional[Iterable[ExecutionStatus]] = None,
                    tool_id: Optional[str] = None) -> list[ExecutionRecord]:
        sql = "SELECT * FROM execution_ledger WHERE investigation_id=?"
        params: list[Any] = [investigation_id]
        if statuses:
            values = [s.value for s in statuses]
            sql += f" AND status IN ({','.join('?' for _ in values)})"
            params.extend(values)
        if tool_id:
            sql += " AND tool_id=?"
            params.append(tool_id)
        sql += " ORDER BY run_at"
        return [self._row_to_execution(r) for r in self._query_all(sql, params)]

    def execution_entity_ids(self, investigation_id: str, tool_id: str) -> set[str]:
        rows = self._query_all(
            "SELECT DISTINCT entity_id FROM execution_ledger WHERE investigation_id=? AND tool_id=?",
            (investigation_id, tool_id),
        )
        return {row["entity_id"] for row in rows}

    def count_tool_calls(self, investigation_id: str) -> int:
        row = self._query_one(
            "SELECT COUNT(*) c FROM execution_ledger WHERE investigation_id=?",
            (investigation_id,),
        )
        return int(row["c"]) if row else 0

    def ledger_status_counts(self, investigation_id: str) -> dict[str, int]:
        rows = self._query_all(
            """SELECT status, COUNT(*) c FROM execution_ledger
               WHERE investigation_id=? GROUP BY status""",
            (investigation_id,),
        )
        return {row["status"]: int(row["c"]) for row in rows}

    def _row_to_execution(self, row: sqlite3.Row) -> ExecutionRecord:
        return ExecutionRecord(
            investigation_id=row["investigation_id"],
            entity_id=row["entity_id"],
            tool_id=row["tool_id"],
            param_hash=row["param_hash"],
            status=ExecutionStatus(row["status"]),
            error_code=ErrorCode(row["error_code"]) if row["error_code"] else None,
            artifact_id=row["artifact_id"],
            run_at=row["run_at"],
            duration_ms=row["duration_ms"],
            error_message=row["error_message"],
        )

    # ════════════════════════════════════════════════════════════════
    # Hypotheses
    # ════════════════════════════════════════════════════════════════

    def add_hypothesis(self, hypothesis: Hypothesis) -> str:
        self._write(
            """INSERT OR REPLACE INTO hypotheses
               (hypothesis_id, investigation_id, hypothesis_type, question,
                target_entity_id, target_claim_id, proposed_tool_ids_json, rationale,
                status, created_by, created_at, updated_at, closing_artifact_id,
                closing_note)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                hypothesis.hypothesis_id, hypothesis.investigation_id,
                hypothesis.hypothesis_type.value, hypothesis.question,
                hypothesis.target_entity_id, hypothesis.target_claim_id,
                canonical_json(hypothesis.proposed_tool_ids), hypothesis.rationale,
                hypothesis.status.value, hypothesis.created_by,
                hypothesis.created_at, hypothesis.updated_at,
                hypothesis.closing_artifact_id, hypothesis.closing_note,
            ),
        )
        return hypothesis.hypothesis_id

    def update_hypothesis(self, hypothesis_id: str, *,
                          status: Optional[HypothesisStatus] = None,
                          closing_artifact_id: Optional[str] = None,
                          closing_note: Optional[str] = None) -> None:
        fields: dict[str, Any] = {"updated_at": utc_now()}
        if status is not None:
            fields["status"] = status.value
        if closing_artifact_id is not None:
            fields["closing_artifact_id"] = closing_artifact_id
        if closing_note is not None:
            fields["closing_note"] = closing_note
        sets = ", ".join(f"{k}=?" for k in fields)
        self._write(f"UPDATE hypotheses SET {sets} WHERE hypothesis_id=?",
                    (*fields.values(), hypothesis_id))

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        row = self._query_one("SELECT * FROM hypotheses WHERE hypothesis_id=?",
                              (hypothesis_id,))
        return self._row_to_hypothesis(row) if row else None

    def list_hypotheses(self, investigation_id: str,
                        statuses: Optional[Iterable[HypothesisStatus]] = None,
                        target_entity_id: Optional[str] = None) -> list[Hypothesis]:
        sql = "SELECT * FROM hypotheses WHERE investigation_id=?"
        params: list[Any] = [investigation_id]
        if statuses:
            values = [s.value for s in statuses]
            sql += f" AND status IN ({','.join('?' for _ in values)})"
            params.extend(values)
        if target_entity_id:
            sql += " AND target_entity_id=?"
            params.append(target_entity_id)
        sql += " ORDER BY created_at"
        return [self._row_to_hypothesis(r) for r in self._query_all(sql, params)]

    def hypothesis_exists(self, investigation_id: str, hypothesis_type: str,
                          target_entity_id: Optional[str],
                          target_claim_id: Optional[str]) -> bool:
        row = self._query_one(
            """SELECT 1 FROM hypotheses WHERE investigation_id=? AND hypothesis_type=?
               AND COALESCE(target_entity_id,'')=? AND COALESCE(target_claim_id,'')=?""",
            (investigation_id, hypothesis_type, target_entity_id or "",
             target_claim_id or ""),
        )
        return row is not None

    def _row_to_hypothesis(self, row: sqlite3.Row) -> Hypothesis:
        from hub.models import HypothesisType

        return Hypothesis(
            hypothesis_id=row["hypothesis_id"],
            investigation_id=row["investigation_id"],
            hypothesis_type=HypothesisType(row["hypothesis_type"]),
            question=row["question"],
            target_entity_id=row["target_entity_id"],
            target_claim_id=row["target_claim_id"],
            proposed_tool_ids=json.loads(row["proposed_tool_ids_json"] or "[]"),
            rationale=row["rationale"],
            status=HypothesisStatus(row["status"]),
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            closing_artifact_id=row["closing_artifact_id"],
            closing_note=row["closing_note"],
        )

    # ════════════════════════════════════════════════════════════════
    # Iterations
    # ════════════════════════════════════════════════════════════════

    def record_iteration(self, investigation_id: str, record: IterationRecord) -> None:
        self._write(
            """INSERT OR REPLACE INTO iterations
               (investigation_id, iteration, timestamp_utc, record_json)
               VALUES (?,?,?,?)""",
            (investigation_id, record.iteration, record.timestamp_utc,
             record.model_dump_json()),
        )

    def list_iterations(self, investigation_id: str) -> list[IterationRecord]:
        rows = self._query_all(
            "SELECT * FROM iterations WHERE investigation_id=? ORDER BY iteration",
            (investigation_id,),
        )
        return [IterationRecord.model_validate_json(r["record_json"]) for r in rows]

    # ════════════════════════════════════════════════════════════════
    # Stats
    # ════════════════════════════════════════════════════════════════

    def stats(self, investigation_id: str) -> dict[str, Any]:
        entities = self.list_entities(investigation_id)
        type_counts: dict[str, int] = {}
        for entity in entities:
            type_counts[entity.type.value] = type_counts.get(entity.type.value, 0) + 1
        return {
            "entities": len(entities),
            "entity_types": type_counts,
            "claims": self.count_claims(investigation_id),
            "claim_statuses": self.claim_status_counts(investigation_id),
            "artifacts": len(self.list_artifacts(investigation_id)),
            "contradictions": len(self.list_contradictions(investigation_id)),
            "ledger": self.ledger_status_counts(investigation_id),
            "hypotheses": len(self.list_hypotheses(investigation_id)),
            "iterations": len(self.list_iterations(investigation_id)),
        }

    # ── convenience ────────────────────────────────────────────────

    def claims_without_artifacts(self, investigation_id: str) -> list[Claim]:
        return [c for c in self.list_claims(investigation_id)
                if not c.artifact_ids and c.status != EpistemicStatus.HYPOTHESIS]

    def integrity_report(self, investigation_id: str) -> dict[str, Any]:
        """Structural integrity check used by tests and crash-recovery paths."""
        claims = self.list_claims(investigation_id)
        missing = [c.claim_id for c in claims
                   if not c.artifact_ids and c.status != EpistemicStatus.HYPOTHESIS]
        orphan_edges = []
        entity_ids = {e.entity_id for e in self.list_entities(investigation_id)}
        for claim in claims:
            if claim.subject_id not in entity_ids:
                orphan_edges.append(claim.claim_id)
            if claim.object_id is not None and claim.object_id not in entity_ids:
                orphan_edges.append(claim.claim_id)
        return {
            "claims_without_artifacts": missing,
            "orphan_claims": sorted(set(orphan_edges)),
            "ok": not missing and not orphan_edges,
        }


__all__ = ["ERKGStore", "SCHEMA_VERSION", "default_home"]
