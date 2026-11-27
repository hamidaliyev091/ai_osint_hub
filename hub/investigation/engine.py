"""Hypothesis-driven autonomous investigation engine (Spec 2 + Spec 3 + Spec 4).

The loop is:

    Plan (hypotheses) -> Score pivots -> Execute (sandboxed) -> Normalize (deterministic
    parser) -> Correlate (ERKG claims/contradictions) -> Score next pivots -> Reflect
    (quarantined LLM packet) -> stop or continue

Every step is transactional: artifact + claims + ledger + hypotheses + counters
commit together, so a killed run resumes from the last committed iteration with
zero duplicate tool executions.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from hub.erkg.graph import GraphView
from hub.erkg.ingestion import EvidenceIngestor, IngestResult
from hub.erkg.resolution import EntityResolver, derive_entity_drafts, normalize_domain
from hub.erkg.store import ERKGStore, default_home
from hub.intake import (
    EMAIL_DERIVED_DOMAIN,
    EMAIL_DERIVED_USERNAME,
    USER_PROVIDED_SEED,
    HypothesisDraft,
    MultiClueIntake,
    StructuredSeeds,
    _email_derived_username,
)
from hub.investigation import hypotheses as hypothesis_mod
from hub.investigation.pivot import PivotRanking, PivotScorer
from hub.investigation.reflection import build_reflection_packet
from hub.investigation.stopping import StopDecision, evaluate_stop
from hub.models import (
    BudgetConfig,
    EntityType,
    EpistemicStatus,
    ErrorCode,
    EvidenceArtifact,
    ExecutionRecord,
    ExecutionStatus,
    HypothesisStatus,
    InvestigationConfig,
    InvestigationState,
    IterationRecord,
    Objective,
    PivotCandidate,
    ReflectionPacket,
    RunStatus,
    ScopeConfig,
    SourceKind,
    ToolRunResult,
    compute_objective_status,
    param_hash,
    sha256_text,
    short_id,
    utc_now,
)
from hub.tools import capabilities as cap_registry
from hub.tools.base import EntityCandidate, ParseOutput, coerce_parse_output

STATE_ENV = "AI_OSINT_HUB_HOME"
RAW_OUTPUT_LIMIT = 2_000_000  # bytes persisted per raw tool output
EVIDENCE_SNIPPET_LIMIT = 4000


class EngineError(RuntimeError):
    """Raised for invalid engine operations (unknown investigation, bad pivot)."""


# ════════════════════════════════════════════════════════════════════════
# Result objects
# ════════════════════════════════════════════════════════════════════════

@dataclass
class IterationOutcome:
    target_id: str
    stopped: bool
    stop_reason: str = ""
    stop_detail: dict[str, Any] = field(default_factory=dict)
    iteration: int = 0
    record: Optional[IterationRecord] = None
    pivot: Optional[PivotCandidate] = None
    next_pivots: list[PivotCandidate] = field(default_factory=list)
    reflection: Optional[ReflectionPacket] = None
    ledger_status: Optional[ExecutionStatus] = None
    error: Optional[str] = None
    graph_summary: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    objectives: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "stop_detail": self.stop_detail,
            "iteration": self.iteration,
            "action": (self.pivot.model_dump(mode="json") if self.pivot else None),
            "execution": (self.record.result if self.record else None),
            "record": (self.record.model_dump(mode="json") if self.record else None),
            "next_pivots": [p.model_dump(mode="json") for p in self.next_pivots],
            "reflection": (self.reflection.model_dump(mode="json")
                           if self.reflection else None),
            "ledger_status": self.ledger_status.value if self.ledger_status else None,
            "error": self.error,
            "graph_summary": self.graph_summary,
            "stats": self.stats,
            "objectives": self.objectives,
        }


@dataclass
class InvestigationOutcome:
    target_id: str
    status: RunStatus
    stop_reason: str
    iterations: int
    tool_calls: int
    state_path: str
    stats: dict[str, Any] = field(default_factory=dict)
    objectives: list[dict[str, Any]] = field(default_factory=list)
    next_pivots: list[PivotCandidate] = field(default_factory=list)
    reflection: Optional[ReflectionPacket] = None
    stop_detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "status": self.status.value,
            "stop_reason": self.stop_reason,
            "iterations": self.iterations,
            "tool_calls": self.tool_calls,
            "state_path": self.state_path,
            "stats": self.stats,
            "objectives": self.objectives,
            "next_pivots": [p.model_dump(mode="json") for p in self.next_pivots],
            "reflection": (self.reflection.model_dump(mode="json")
                           if self.reflection else None),
            "stop_detail": self.stop_detail,
        }


# ════════════════════════════════════════════════════════════════════════
# Engine
# ════════════════════════════════════════════════════════════════════════

class InvestigationEngine:
    """Async autonomous investigation engine.

    Test seams:
      * ``runner``            — object with ``async run(capability, params, context)``.
      * ``parser_resolver``   — ``callable(capability) -> parse(raw, target)``.
      * ``health_probe``      — ``callable(capability) -> bool``.
      * ``now_provider``      — ``callable() -> datetime`` (UTC aware).
      * ``state_root``        — override investigation storage directory.
    """

    def __init__(self, *, runner: Any = None,
                 parser_resolver: Optional[Callable[[Any], Callable]] = None,
                 health_probe: Optional[Callable[[Any], bool]] = None,
                 now_provider: Optional[Callable[[], datetime]] = None,
                 state_root: Optional[str | os.PathLike] = None,
                 raw_output_limit: int = RAW_OUTPUT_LIMIT):
        self._runner = runner
        self._runtime = None
        self._parser_resolver = parser_resolver
        self._health_probe = health_probe
        self._now_provider = now_provider
        self._state_root = Path(state_root) if state_root else None
        self._raw_output_limit = raw_output_limit

    # ── storage paths ──────────────────────────────────────────────

    @staticmethod
    def home_root() -> Path:
        env = os.environ.get(STATE_ENV)
        return Path(env).expanduser().resolve() if env else default_home()

    def state_root(self) -> Path:
        return (self._state_root or (self.home_root() / "investigations")).resolve()

    def paths(self, target_id: str):
        return InvestigationPaths(self.state_root() / target_id)

    def list_investigation_ids(self) -> list[str]:
        root = self.state_root()
        if not root.exists():
            return []
        return sorted(p.name for p in root.iterdir()
                      if p.is_dir() and (p / "erkg.sqlite3").exists())

    def open_store(self, target_id: str) -> ERKGStore:
        paths = self.paths(target_id)
        if not paths.db.exists():
            raise EngineError(f"investigation not found: {target_id}")
        return ERKGStore(paths.db, investigation_id=target_id)

    # ── public operations ──────────────────────────────────────────

    async def investigate(self, raw_input: str,
                          overrides: Optional[dict[str, Any]] = None,
                          *, structured_seeds: Optional[dict[str, Any]] = None
                          ) -> InvestigationOutcome:
        """Create an investigation and run the autonomous loop to a stop condition."""
        config = build_config(raw_input, overrides)
        paths = self.paths(config.target_id)
        paths.ensure()
        store = ERKGStore(paths.db, investigation_id=config.target_id)
        runner = self._ensure_runner(config)
        try:
            investigation = self._create_investigation(
                store, config, paths, structured_seeds=structured_seeds)
            outcome: InvestigationOutcome | None = None
            max_loop = config.budgets.max_iterations + 3
            for _ in range(max_loop):
                if config.parallel_pivots > 1:
                    wave = await self._step_wave_internal(
                        store, paths, max_pivots=config.parallel_pivots, runner=runner
                    )
                    if wave.get("stopped"):
                        break
                else:
                    step = await self._step_internal(store, paths, forced_pivot_id=None,
                                                     runner=runner)
                    if step.stopped:
                        break
            final = self._outcome(store, paths, config.target_id)
            return final
        finally:
            await self._close_runner(runner)
            store.close()

    async def create(self, raw_input: str,
                     overrides: Optional[dict[str, Any]] = None,
                     *, structured_seeds: Optional[dict[str, Any]] = None
                     ) -> InvestigationOutcome:
        """Create an investigation without executing any pivot (legacy --init path)."""
        config = build_config(raw_input, overrides)
        paths = self.paths(config.target_id)
        paths.ensure()
        store = ERKGStore(paths.db, investigation_id=config.target_id)
        try:
            self._create_investigation(store, config, paths,
                                       structured_seeds=structured_seeds)
            outcome = self._outcome(store, paths, config.target_id)
            return outcome
        finally:
            store.close()

    async def resume(self, target_id: str) -> InvestigationOutcome:
        """Resume an existing investigation loop from committed state."""
        store = self.open_store(target_id)
        investigation = store.get_investigation(target_id)
        if investigation is None:
            store.close()
            raise EngineError(f"investigation not found: {target_id}")
        if investigation.status != RunStatus.ACTIVE:
            outcome = self._outcome(store, self.paths(target_id), target_id)
            store.close()
            return outcome
        paths = self.paths(target_id)
        runner = self._ensure_runner(investigation.config)
        try:
            for _ in range(investigation.config.budgets.max_iterations + 3):
                if investigation.config.parallel_pivots > 1:
                    wave = await self._step_wave_internal(
                        store, paths,
                        max_pivots=investigation.config.parallel_pivots,
                        runner=runner,
                    )
                    if wave.get("stopped"):
                        break
                else:
                    step = await self._step_internal(store, paths, forced_pivot_id=None,
                                                     runner=runner)
                    if step.stopped:
                        break
            return self._outcome(store, paths, target_id)
        finally:
            await self._close_runner(runner)
            store.close()

    async def step(self, target_id: str, *,
                   pivot_id: Optional[str] = None) -> IterationOutcome:
        """Execute exactly one Plan/Execute/Normalize/Correlate cycle."""
        store = self.open_store(target_id)
        investigation = store.get_investigation(target_id)
        if investigation is None:
            store.close()
            raise EngineError(f"investigation not found: {target_id}")
        paths = self.paths(target_id)
        runner = self._ensure_runner(investigation.config)
        try:
            return await self._step_internal(store, paths, forced_pivot_id=pivot_id,
                                             runner=runner)
        finally:
            await self._close_runner(runner)
            store.close()

    async def step_batch(self, target_id: str, max_pivots: int = 3) -> dict[str, Any]:
        """Execute up to ``max_pivots`` non-conflicting pivots concurrently."""
        store = self.open_store(target_id)
        investigation = store.get_investigation(target_id)
        if investigation is None:
            store.close()
            raise EngineError(f"investigation not found: {target_id}")
        paths = self.paths(target_id)
        runner = self._ensure_runner(investigation.config)
        try:
            return await self._step_wave_internal(
                store, paths, max_pivots=max(1, int(max_pivots)), runner=runner
            )
        finally:
            await self._close_runner(runner)
            store.close()

    def preview(self, target_id: str) -> dict[str, Any]:
        """Read-only current state + ranked pivots (no execution)."""
        store = self.open_store(target_id)
        try:
            investigation = store.get_investigation(target_id)
            if investigation is None:
                raise EngineError(f"investigation not found: {target_id}")
            graph = GraphView(store, target_id, investigation.seed_entity_ids)
            ranking = self._rank_pivots(store, investigation, graph)
            return {
                "state": investigation.model_dump(mode="json"),
                "graph_summary": graph.summary(),
                "stats": store.stats(target_id),
                "objectives": [o.model_dump(mode="json") for o in investigation.objectives],
                "next_pivots": [p.model_dump(mode="json") for p in ranking.selected],
                "open_hypotheses": [
                    h.model_dump(mode="json") for h in
                    store.list_hypotheses(target_id, statuses=[HypothesisStatus.OPEN])
                ],
            }
        finally:
            store.close()

    # ── creation / seeding ─────────────────────────────────────────

    def _create_investigation(self, store: ERKGStore, config: InvestigationConfig,
                              paths: "InvestigationPaths",
                              *, structured_seeds: Optional[dict[str, Any]] = None
                              ) -> InvestigationState:
        target_id = config.target_id
        now = utc_now()
        investigation = InvestigationState(
            target_id=target_id,
            raw_input=config.raw_input,
            created_at=now, updated_at=now,
            status=RunStatus.ACTIVE,
            config=config,
        )
        seeds = self._seed_candidates(config.raw_input, config, structured_seeds)
        seeds = self._enforce_seed_scope(seeds, config.scope)
        store.create_investigation(investigation)
        seed_ids: list[str] = []
        with store.transaction():
            artifact = EvidenceArtifact(
                artifact_id=short_id("art", target_id, "seed", sha256_text(config.raw_input)),
                investigation_id=target_id,
                source_tool=SourceKind.SEED.value,
                invocation_params_hash=param_hash("seed_intake", {"raw_input": config.raw_input}),
                timestamp_utc=now,
                raw_evidence_snippet=config.raw_input[:EVIDENCE_SNIPPET_LIMIT],
                raw_output_sha256=sha256_text(config.raw_input),
                parser_version="intake-2.0.0",
                epistemic_status=EpistemicStatus.SINGLE_SOURCE_LEAD,
                confidence=0.90,
                stdout_bytes=len(config.raw_input.encode("utf-8")),
            )
            store.add_artifact(artifact)
            if seeds:
                parse_output = ParseOutput(entities=seeds)
                EvidenceIngestor(store).ingest(
                    target_id, parse_output, artifact_id=artifact.artifact_id,
                    tool_id=SourceKind.SEED.value,
                    accepted_types=[],
                    timestamp=now,
                )
                for candidate in seeds:
                    drafts, _ = derive_entity_drafts(candidate.type, candidate.value)
                    if not drafts:
                        continue
                    entity = store.get_entity_by_value(
                        target_id, drafts[0].entity_type, drafts[0].canonical_value)
                    if entity is not None and entity.entity_id not in seed_ids:
                        seed_ids.append(entity.entity_id)
            # Phase 12: an institutional/custom mail domain derived from a seed
            # email must be a seed-wave entity so domain collectors are scheduled.
            # ERKG classifies hostnames into DOMAIN/SUBDOMAIN nodes, so promote
            # every matching node's provenance and include it in the seed set.
            derived_domain_ids = self._promote_email_derived_domains(
                store, target_id, seeds, seed_ids)
            self._promote_email_derived_usernames(
                store, target_id, seeds, seed_ids)
            # Phase 8: link all user-provided clues to the primary subject so
            # cross-tool corroboration works across every clue in the graph.
            self._link_seed_entities(store, target_id, seeds, seed_ids,
                                     artifact.artifact_id, now,
                                     derived_domain_ids=derived_domain_ids)
            hypothesis_ids = self._seed_hypothesis_entities(
                store, target_id, config, now, structured_seeds=structured_seeds)

            # Scope is derived deterministically from explicit seed identifiers.
            scope = self._derive_scope(store, target_id, config.scope, seed_ids)
            investigation.config = config.model_copy(update={"scope": scope})
            objectives = self._initial_objectives(store, target_id, seed_ids)
            store.update_investigation(
                target_id,
                config_json=json.dumps(investigation.config.model_dump(mode="json")),
                seed_entity_ids_json=json.dumps(seed_ids),
                objectives_json=json.dumps([o.model_dump(mode="json") for o in objectives]),
                updated_at=now,
            )
        refreshed = store.get_investigation(target_id)
        assert refreshed is not None
        return refreshed

    def _seed_candidates(self, raw_input: str, config: InvestigationConfig,
                         structured_seeds: Optional[dict[str, Any]] = None
                         ) -> list[EntityCandidate]:
        """Extract ALL user-provided clues with USER_PROVIDED_SEED provenance."""
        return MultiClueIntake().seed_candidates(raw_input, structured_seeds)

    def _promote_email_derived_domains(self, store: ERKGStore, target_id: str,
                                       seeds: list[EntityCandidate],
                                       seed_ids: list[str]) -> set[str]:
        """Promote custom mail-domain nodes to EMAIL_DERIVED_DOMAIN seed wave."""
        promoted: set[str] = set()
        for candidate in seeds:
            if (candidate.metadata or {}).get("provenance") != EMAIL_DERIVED_DOMAIN:
                continue
            value = str(candidate.value or "").strip().lower()
            if not value:
                continue
            for entity_type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
                entity = store.get_entity_by_value(target_id, entity_type, value)
                if entity is None:
                    continue
                store.merge_entity_metadata(entity.entity_id, {
                    "provenance": EMAIL_DERIVED_DOMAIN,
                    "seed_wave": True,
                    "derived_from_email": (candidate.metadata or {}).get(
                        "derived_from_email", ""),
                })
                promoted.add(entity.entity_id)
                if entity.entity_id not in seed_ids:
                    seed_ids.append(entity.entity_id)
        return promoted

    def _promote_email_derived_usernames(self, store: ERKGStore, target_id: str,
                                         seeds: list[EntityCandidate],
                                         seed_ids: list[str]) -> None:
        """Promote non-role e-mail local-parts to the primary seed wave."""
        values: list[tuple[str, str]] = []
        for candidate in seeds:
            provenance = (candidate.metadata or {}).get("provenance")
            if provenance == EMAIL_DERIVED_USERNAME:
                values.append((str(candidate.value or "").strip().lower(),
                               str((candidate.metadata or {}).get(
                                   "derived_from_email") or "")))
            elif candidate.type == EntityType.EMAIL:
                derived = _email_derived_username(str(candidate.value or ""))
                if derived:
                    values.append((derived, str(candidate.value or "")))
        for value, email_value in values:
            if not value:
                continue
            entity = store.get_entity_by_value(target_id, EntityType.USERNAME,
                                               value)
            if entity is None:
                continue
            store.merge_entity_metadata(entity.entity_id, {
                "provenance": EMAIL_DERIVED_USERNAME,
                "seed_wave": True,
                "derived_from_email": email_value,
                "derived_confidence": 0.64,
                "confidence": 0.64,
            })
            if entity.entity_id not in seed_ids:
                seed_ids.append(entity.entity_id)

    def _link_seed_entities(self, store: ERKGStore, target_id: str,
                            seeds: list[EntityCandidate], seed_ids: list[str],
                            artifact_id: str, timestamp: str,
                            *, derived_domain_ids: Optional[set[str]] = None) -> None:
        """Connect every user-provided seed to the primary subject.

        A person clue becomes the anchor whenever one exists; otherwise the first
        extracted seed anchors the rest. This keeps hop distances at 1 and lets
        ``GraphView.shares_corroborated_identifier`` see the whole clue set.
        """
        if len(seed_ids) < 2:
            return
        person_ids = [entity_id for entity_id in seed_ids
                      if (entity := store.get_entity(entity_id)) is not None
                      and entity.type == EntityType.PERSON]
        anchor_id = person_ids[0] if person_ids else seed_ids[0]
        anchor = store.get_entity(anchor_id)
        if anchor is None:
            return
        person_link = {
            EntityType.USERNAME: "HAS_USERNAME",
            EntityType.EMAIL: "HAS_EMAIL",
            EntityType.DOMAIN: "OWNS",
            EntityType.SUBDOMAIN: "OWNS",
            EntityType.REPOSITORY: "OWNS",
            EntityType.LOCATION: "LOCATED_IN",
            EntityType.ORGANIZATION: "ASSOCIATED_WITH",
            EntityType.PHONE: "ASSOCIATED_WITH",
            EntityType.URL: "ASSOCIATED_WITH",
            EntityType.IP: "ASSOCIATED_WITH",
            EntityType.SOCIAL_PROFILE: "HAS_USERNAME",
        }
        for entity_id in seed_ids:
            if entity_id == anchor_id:
                continue
            other = store.get_entity(entity_id)
            if other is None:
                continue
            if (derived_domain_ids and entity_id in derived_domain_ids
                    and other.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN)):
                # Email-derived domains are associated with the subject, not
                # personally owned (explicitly supplied domains keep OWNS).
                predicate = "ASSOCIATED_WITH"
            else:
                predicate = (person_link.get(other.type, "ASSOCIATED_WITH")
                             if anchor.type == EntityType.PERSON else "ASSOCIATED_WITH")
            try:
                store.upsert_claim(
                    target_id, anchor_id, predicate, object_id=entity_id,
                    artifact_id=artifact_id, source_tool="seed",
                    timestamp=timestamp, direct=True,
                    snippet=f"{USER_PROVIDED_SEED}: linked {other.type.value} clue",
                )
            except ValueError:
                continue

    def _seed_hypothesis_entities(self, store: ERKGStore, target_id: str,
                                  config: InvestigationConfig, timestamp: str,
                                  *, structured_seeds: Optional[dict[str, Any]] = None
                                  ) -> list[str]:
        """Bounded username/email HYPOTHESIS entities from user-provided clues.

        Deterministic permutations only; confidence <= 0.35; every hypothesis is
        linked to the primary person when one exists so the pivot scorer can
        target it with passive collectors.
        """
        if not config.allow_hypothesis_expansion:
            return []
        drafts = MultiClueIntake().hypothesis_drafts(
            config.raw_input, structured_seeds)
        if not drafts:
            return []
        resolver = EntityResolver(store)
        person_ids = [entity.entity_id
                      for entity in store.list_entities(target_id,
                                                        types=[EntityType.PERSON])]
        primary_person = person_ids[0] if person_ids else None
        created: list[str] = []
        for draft in drafts[:30]:
            metadata = {
                "origin": "hypothesis",
                "generator": draft.generator,
                "provenance": "USER_DERIVED_HYPOTHESIS",
                "rationale": draft.rationale,
            }
            entity_drafts, _ = derive_entity_drafts(
                draft.entity_type, draft.value, metadata=metadata)
            if not entity_drafts:
                continue
            entity, is_new = resolver.resolve_draft(
                target_id, entity_drafts[0], artifact_id=None,
                timestamp=timestamp)
            if entity is None:
                continue
            if is_new:
                store.add_hypothesis_claim(
                    target_id, entity.entity_id, "IDENTIFIED_AS",
                    object_literal=entity.canonical_value, timestamp=timestamp,
                    confidence=draft.confidence)
            if primary_person is not None:
                # Non-functional predicates keep speculative links out of the
                # contradiction machinery (a hypothesis cannot contradict evidence).
                predicate = {
                    EntityType.USERNAME: "HAS_USERNAME",
                    EntityType.EMAIL: "ASSOCIATED_WITH",
                }.get(draft.entity_type, "ASSOCIATED_WITH")
                store.add_hypothesis_claim(
                    target_id, primary_person, predicate,
                    object_id=entity.entity_id, timestamp=timestamp,
                    confidence=draft.confidence)
            created.append(entity.entity_id)
        return created[:30]

    @staticmethod
    def _host_within(host: str, domains: Iterable[str]) -> bool:
        from hub.erkg.resolution import normalize_domain

        normalized_host = normalize_domain(host)
        for domain in domains:
            normalized_domain = normalize_domain(domain)
            if not normalized_domain:
                continue
            if normalized_host == normalized_domain or \
                    normalized_host.endswith("." + normalized_domain):
                return True
        return False

    def _enforce_seed_scope(self, seeds: list[EntityCandidate],
                            scope: ScopeConfig) -> list[EntityCandidate]:
        """Reject seeds that fall outside an explicitly supplied allowlist.

        An explicit ``allow_domains`` / ``allow_entities`` is a hard authorization
        boundary: the investigation must not even start on an out-of-scope seed.
        """
        if not (scope.allow_domains or scope.allow_entities):
            kept = list(seeds)
        else:
            kept = []
            allow_entities = {value.strip().lower()
                              for value in scope.allow_entities if value}
            host_types = {EntityType.DOMAIN, EntityType.SUBDOMAIN,
                          EntityType.EMAIL, EntityType.URL}
            for candidate in seeds:
                value = candidate.value.strip()
                lowered = value.lower()
                if (lowered in allow_entities
                        or f"{candidate.type.value}:{lowered}" in allow_entities):
                    kept.append(candidate)
                    continue
                if candidate.type not in host_types:
                    # Person/username/org/location/phone/IP clues are subjects,
                    # not collection hosts; active tools remain scope-gated.
                    kept.append(candidate)
                    continue
                if scope.allow_domains:
                    host = ""
                    if candidate.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
                        host = value
                    elif candidate.type == EntityType.EMAIL and "@" in value:
                        host = value.split("@", 1)[1]
                    elif candidate.type == EntityType.URL:
                        host = _url_host(value)
                    if host and self._host_within(host, scope.allow_domains):
                        kept.append(candidate)
                        continue
                # Explicit allow_entities but no host allowlist match: drop host clue.
                if scope.allow_entities and not scope.allow_domains:
                    continue
        denied = False
        if scope.deny_domains:
            filtered: list[EntityCandidate] = []
            for candidate in kept:
                host = ""
                if candidate.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
                    host = candidate.value
                elif candidate.type == EntityType.EMAIL and "@" in candidate.value:
                    host = candidate.value.split("@", 1)[1]
                if host and self._host_within(host, scope.deny_domains):
                    denied = True
                    continue
                filtered.append(candidate)
            kept = filtered
        if not kept:
            raise EngineError(
                "seed target is outside the explicitly configured scope allowlist "
                f"(allow_domains={scope.allow_domains}, "
                f"allow_entities={scope.allow_entities}"
                + (", seed matched deny_domains" if denied else "") + ")")
        return kept

    def _derive_scope(self, store: ERKGStore, target_id: str,
                      scope: ScopeConfig, seed_ids: list[str]) -> ScopeConfig:
        domains: list[str] = list(scope.allow_domains)
        # Never widen an explicitly configured allowlist with seed-derived domains.
        # Phase 11: seed EMAIL addresses do NOT auto-lock scope to their mail
        # domain (an email clue is an identity seed, not an authorization grant);
        # only explicit user allow_domains and genuine DOMAIN/SUBDOMAIN seeds do.
        if not domains and not scope.allow_entities:
            for entity in store.list_entities(target_id):
                if (entity.entity_id in seed_ids
                        and (entity.metadata or {}).get("provenance")
                        == EMAIL_DERIVED_DOMAIN):
                    continue
                if entity.entity_id in seed_ids and entity.type in (
                        EntityType.DOMAIN, EntityType.SUBDOMAIN):
                    if entity.canonical_value not in domains:
                        domains.append(entity.canonical_value)
        return scope.model_copy(update={"allow_domains": domains})

    def _initial_objectives(self, store: ERKGStore, target_id: str,
                            seed_ids: list[str]) -> list[Objective]:
        objectives: list[Objective] = []
        for entity_id in seed_ids:
            entity = store.get_entity(entity_id)
            if entity is None:
                continue
            objectives.append(Objective(
                objective_id=short_id("obj", target_id, entity_id),
                description=(f"Corroborate identity of {entity.type.value} "
                             f"'{entity.canonical_value}' with an independent source"),
                entity_id=entity_id,
                required_status=EpistemicStatus.CORROBORATED,
            ))
        return objectives

    # ── one loop iteration ─────────────────────────────────────────

    async def _step_internal(self, store: ERKGStore, paths: "InvestigationPaths",
                             *, forced_pivot_id: Optional[str],
                             runner: Any) -> IterationOutcome:
        investigation = store.get_investigation(paths.target_id)
        if investigation is None:
            raise EngineError(f"investigation not found: {paths.target_id}")
        target_id = investigation.target_id
        if investigation.status != RunStatus.ACTIVE:
            graph = GraphView(store, target_id, investigation.seed_entity_ids)
            return IterationOutcome(
                target_id=target_id, stopped=True,
                stop_reason=investigation.stop_reason or investigation.status.value,
                iteration=investigation.iteration_count,
                graph_summary=graph.summary(),
                stats=store.stats(target_id),
                objectives=[o.model_dump(mode="json") for o in investigation.objectives],
            )

        elapsed = self._elapsed_seconds(investigation)
        pre_decision = evaluate_stop(investigation=investigation, elapsed_seconds=elapsed)
        if pre_decision.should_stop:
            return self._finalize(store, investigation, pre_decision)

        graph = GraphView(store, target_id, investigation.seed_entity_ids)
        available = self._available_tool_ids(investigation)
        available -= self._circuit_breaker_tools(store, target_id)
        new_hypotheses = self._hypothesis_generator(store, investigation).generate(
            investigation, graph, available)
        if new_hypotheses:
            graph = GraphView(store, target_id, investigation.seed_entity_ids)

        ranking = self._rank_pivots(store, investigation, graph,
                                    available_tool_ids=available)
        post_decision = evaluate_stop(
            investigation=investigation, elapsed_seconds=elapsed,
            pivot_generated=ranking.generated,
            pivot_above_threshold=ranking.above_threshold,
        )
        forced_pivot: Optional[PivotCandidate] = None
        if forced_pivot_id:
            forced_pivot = next((p for p in ranking.all_candidates
                                 if p.pivot_id == forced_pivot_id), None)
            if forced_pivot is None:
                raise EngineError(
                    f"unknown or stale pivot_id '{forced_pivot_id}'. "
                    f"Available: {[p.pivot_id for p in ranking.selected]}")
        # An explicit caller override may bypass pivot-score staleness but never
        # budget or objective stop conditions.
        if post_decision.should_stop and (
                forced_pivot is None
                or post_decision.reason not in {"min_pivot_threshold", "no_candidates"}):
            return self._finalize(store, investigation, post_decision)

        pivot = forced_pivot or ranking.selected[0]

        iteration_no = investigation.iteration_count + 1
        timestamp = utc_now()
        started_monotonic = time.monotonic()
        capability = cap_registry.get_tool(pivot.tool_id)
        errors: list[str] = []
        parse_output = ParseOutput()
        ingest = IngestResult()
        run_status = ExecutionStatus.ERROR
        error_code: Optional[ErrorCode] = None
        error_message = ""
        stdout = ""
        duration_ms = 0
        tool_called = False
        policy_denied = False

        if capability is None:
            error_code = ErrorCode.UNKNOWN_TOOL
            error_message = f"unknown tool '{pivot.tool_id}'"
        else:
            try:
                decision = self._policy_check(capability, pivot, investigation)
            except Exception as exc:  # noqa: BLE001 - policy must fail closed
                decision = None
                error_code = ErrorCode.SCOPE_BLOCKED
                error_message = f"policy gate error: {type(exc).__name__}: {exc}"
            if decision is not None and not decision.allowed:
                policy_denied = True
                error_code = decision.error_code or ErrorCode.SCOPE_BLOCKED
                error_message = decision.reason
            else:
                # Cross-process zero-duplicate-run claim: the winner may execute,
                # everyone else observes an in-flight/finished ledger row.
                claimed = store.try_claim_execution(ExecutionRecord(
                    investigation_id=target_id,
                    entity_id=pivot.entity_id,
                    tool_id=pivot.tool_id,
                    param_hash=param_hash(pivot.tool_id, pivot.params),
                    status=ExecutionStatus.ERROR,
                    error_code=ErrorCode.SPAWN_ERROR,
                    artifact_id=None,
                    run_at=timestamp,
                    duration_ms=0,
                    error_message="in_flight: claimed by another worker",
                ))
                if not claimed:
                    return IterationOutcome(
                        target_id=target_id,
                        stopped=False,
                        stop_reason="pivot_in_flight",
                        stop_detail={"pivot_id": pivot.pivot_id,
                                     "tool_id": pivot.tool_id},
                        iteration=investigation.iteration_count,
                        error=("execution already claimed by another worker; "
                               "re-run status/step"),
                        graph_summary=graph.summary(),
                        stats=store.stats(target_id),
                        objectives=[o.model_dump(mode="json")
                                    for o in investigation.objectives],
                    )
                try:
                    run_result = await self._run_capability(
                        runner, capability, pivot, investigation, paths)
                except Exception as exc:  # noqa: BLE001
                    run_result = ToolRunResult(
                        tool_id=capability.tool_id, entity_id=pivot.entity_id,
                        params=pivot.params, status=ExecutionStatus.ERROR,
                        error_code=ErrorCode.SPAWN_ERROR,
                        error_message=f"{type(exc).__name__}: {exc}",
                        started_at=timestamp,
                    )
                tool_called = True
                stdout = run_result.stdout or ""
                run_status = run_result.status
                error_code = run_result.error_code
                error_message = run_result.error_message
                if error_code == ErrorCode.RATE_LIMITED:
                    try:
                        from hub.tools import cooldown

                        if pivot.tool_id in cooldown.COOLDOWN_TOOLS:
                            cooldown.mark_rate_limited(pivot.tool_id)
                    except Exception:  # noqa: BLE001 - cooldown must never break a run
                        pass
                duration_ms = run_result.duration_ms or int(
                    (time.monotonic() - started_monotonic) * 1000)
                if run_status == ExecutionStatus.SUCCESS:
                    try:
                        parser = self._parser_for(capability)
                        target_value = _primary_param_value(pivot.params)
                        parsed_raw = parser(stdout, target_value)
                        parse_output = coerce_parse_output(
                            parsed_raw, parser_version=capability.parser_version)
                        errors.extend(parse_output.warnings)
                    except Exception as exc:  # noqa: BLE001
                        parse_output = ParseOutput()
                        run_status = ExecutionStatus.ERROR
                        error_code = ErrorCode.PARSE_ERROR
                        error_message = (f"parser failed: {type(exc).__name__}: {exc}")
                        errors.append(error_message)

        phash = param_hash(pivot.tool_id, pivot.params)
        raw_path = self._write_raw_artifact(paths, iteration_no, pivot.tool_id, stdout)
        snippet = self._evidence_snippet(parse_output, error_message)
        artifact = EvidenceArtifact(
            artifact_id=short_id("art", target_id, pivot.tool_id, phash, timestamp),
            investigation_id=target_id,
            source_tool=pivot.tool_id,
            invocation_params_hash=phash,
            timestamp_utc=timestamp,
            raw_evidence_snippet=snippet,
            raw_output_sha256=sha256_text(stdout),
            parser_version=(capability.parser_version if capability else "unknown"),
            epistemic_status=(EpistemicStatus.SINGLE_SOURCE_LEAD
                              if run_status == ExecutionStatus.SUCCESS and error_code is None
                              else EpistemicStatus.COLLECTION_FAILURE),
            confidence=(capability.reliability if capability and run_status == ExecutionStatus.SUCCESS
                        else 0.0),
            raw_output_path=raw_path,
            stdout_bytes=len(stdout.encode("utf-8", errors="replace")),
            truncated=len(stdout) >= self._raw_output_limit,
        )

        if run_status == ExecutionStatus.SUCCESS and error_code is None:
            ledger_status = (ExecutionStatus.EMPTY if parse_output.is_empty
                             else ExecutionStatus.SUCCESS)
            if ledger_status == ExecutionStatus.EMPTY:
                error_code = ErrorCode.EMPTY_RESULT
        elif run_status == ExecutionStatus.TIMEOUT:
            ledger_status = ExecutionStatus.TIMEOUT
        else:
            ledger_status = ExecutionStatus.ERROR

        closed_before = len(store.list_hypotheses(target_id,
                                                  statuses=[HypothesisStatus.OPEN]))
        with store.transaction():
            store.add_artifact(artifact)
            if ledger_status in (ExecutionStatus.SUCCESS, ExecutionStatus.EMPTY):
                try:
                    ingest = EvidenceIngestor(store).ingest(
                        target_id, parse_output, artifact_id=artifact.artifact_id,
                        tool_id=pivot.tool_id,
                        accepted_types=capability.accepted_entity_types,
                        timestamp=timestamp,
                    )
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"ingest failed: {type(exc).__name__}: {exc}")
                    ledger_status = ExecutionStatus.ERROR
                    error_code = ErrorCode.PARSE_ERROR
            store.record_execution(ExecutionRecord(
                investigation_id=target_id,
                entity_id=pivot.entity_id,
                tool_id=pivot.tool_id,
                param_hash=phash,
                status=ledger_status,
                error_code=error_code,
                artifact_id=artifact.artifact_id,
                run_at=timestamp,
                duration_ms=duration_ms,
                error_message=error_message,
            ))
            # Active recon on infrastructure discovered *through* an allow-listed
            # domain is in scope; record those public IPs in scope.allow_ips.
            self._refresh_scope_ips(store, store.get_investigation(target_id))
            hypothesis_mod.correlate_after_run(
                store, target_id,
                executed_entity_id=pivot.entity_id,
                executed_tool_id=pivot.tool_id,
                run_status=ledger_status,
                new_claims=ingest.new_claims,
            )
            self._refresh_objectives(store, investigation)
            refreshed = store.get_investigation(target_id)
            assert refreshed is not None
            record = IterationRecord(
                iteration=iteration_no,
                timestamp_utc=timestamp,
                action={
                    "pivot_id": pivot.pivot_id,
                    "tool": pivot.tool_id,
                    "params": pivot.params,
                    "entity_id": pivot.entity_id,
                    "hypothesis_id": pivot.hypothesis_id,
                    "score": pivot.score,
                    "policy_denied": policy_denied,
                },
                result={
                    "status": ledger_status.value,
                    "error_code": error_code.value if error_code else None,
                    "error_message": error_message,
                    "duration_ms": duration_ms,
                    "stdout_bytes": artifact.stdout_bytes,
                    "parse": parse_output.summary(),
                    "ingest": ingest.as_dict() if ledger_status != ExecutionStatus.ERROR else {},
                    "warnings": errors[:5],
                },
                artifact_ids=[artifact.artifact_id],
                new_entity_ids=ingest.new_entity_ids,
                new_claims=ingest.new_claims,
                contradictions=ingest.contradictions,
                hypotheses_opened=len(new_hypotheses),
                hypotheses_closed=max(0, closed_before - len(store.list_hypotheses(
                    target_id, statuses=[HypothesisStatus.OPEN]))),
                candidates_considered=ranking.generated,
                candidate_count=ranking.above_threshold,
                duration_ms=duration_ms,
            )
            store.record_iteration(target_id, record)
            store.bump_counters(target_id, iterations=1,
                                tool_calls=1 if tool_called else 0,
                                timestamp=timestamp)

        # ── post-iteration state for the caller ────────────────────
        graph_after = GraphView(store, target_id,
                                store.get_investigation(target_id).seed_entity_ids)
        refreshed = store.get_investigation(target_id)
        assert refreshed is not None
        elapsed_after = self._elapsed_seconds(refreshed)
        ranking_after = self._rank_pivots(store, refreshed, graph_after,
                                          available_tool_ids=available)
        decision_after = evaluate_stop(
            investigation=refreshed, elapsed_seconds=elapsed_after,
            pivot_generated=ranking_after.generated,
            pivot_above_threshold=ranking_after.above_threshold,
        )
        reflection = None
        if refreshed.config.reflection_enabled:
            try:
                reflection = build_reflection_packet(
                    investigation=refreshed, graph=graph_after,
                    executed={"pivot_id": pivot.pivot_id, "tool": pivot.tool_id,
                              "status": ledger_status.value},
                    ingest=ingest,
                    open_hypotheses=store.list_hypotheses(
                        target_id, statuses=[HypothesisStatus.OPEN]),
                    next_pivots=ranking_after.selected,
                    new_entity_ids=ingest.new_entity_ids,
                    target_entity_id=pivot.entity_id,
                )
            except Exception as exc:  # noqa: BLE001 - reflection is advisory
                errors.append(f"reflection packet failed: {type(exc).__name__}: {exc}")
                reflection = None
        if refreshed.config.ai_reflection_auto and refreshed.config.reflection_enabled:
            await self._maybe_run_ai_reflection(store, target_id)
        if decision_after.should_stop:
            finalized = self._finalize(store, refreshed, decision_after)
            finalized.record = record
            finalized.pivot = pivot
            finalized.ledger_status = ledger_status
            finalized.reflection = reflection
            finalized.stats = store.stats(target_id)
            return finalized

        return IterationOutcome(
            target_id=target_id,
            stopped=False,
            stop_reason="continue",
            stop_detail=decision_after.detail,
            iteration=iteration_no,
            record=record,
            pivot=pivot,
            next_pivots=ranking_after.selected,
            reflection=reflection,
            ledger_status=ledger_status,
            error=error_message or None,
            graph_summary=graph_after.summary(),
            stats=store.stats(target_id),
            objectives=[o.model_dump(mode="json") for o in refreshed.objectives],
        )

    async def _maybe_run_ai_reflection(self, store: ERKGStore, target_id: str) -> None:
        """Safely invoke optional post-iteration AI reflection (never fails core loop)."""
        try:
            from hub.ai import run_case_reflection

            await run_case_reflection(store, target_id)
        except Exception:  # noqa: BLE001 - missing/offline AI never breaks deterministic core
            pass

    @staticmethod
    def _select_wave_pivots(ranking: PivotRanking, max_pivots: int) -> list[PivotCandidate]:
        """Select up to ``max_pivots`` non-conflicting above-threshold pivots."""
        above = [c for c in ranking.all_candidates if c.score >= ranking.threshold]
        ordered = list(ranking.selected)
        seen_ids = {c.pivot_id for c in ordered}
        for candidate in above:
            if candidate.pivot_id not in seen_ids:
                ordered.append(candidate)
                seen_ids.add(candidate.pivot_id)
        chosen: list[PivotCandidate] = []
        seen_pairs: set[tuple[str, str]] = set()
        for candidate in ordered:
            if len(chosen) >= max_pivots:
                break
            pair = (candidate.entity_id, candidate.tool_id)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            chosen.append(candidate)
        return chosen

    async def _step_wave_internal(
        self,
        store: ERKGStore,
        paths: "InvestigationPaths",
        *,
        max_pivots: int,
        runner: Any,
    ) -> dict[str, Any]:
        """Execute a bounded parallel wave of non-conflicting pivots."""
        investigation = store.get_investigation(paths.target_id)
        if investigation is None:
            raise EngineError(f"investigation not found: {paths.target_id}")
        target_id = investigation.target_id
        if investigation.status != RunStatus.ACTIVE:
            graph = GraphView(store, target_id, investigation.seed_entity_ids)
            return {
                "target_id": target_id,
                "status": "stopped",
                "stopped": True,
                "stop_reason": investigation.stop_reason or investigation.status.value,
                "iteration": investigation.iteration_count,
                "executed": [],
                "next_pivots": [],
                "graph_summary": graph.summary(),
                "stats": store.stats(target_id),
                "objectives": [o.model_dump(mode="json") for o in investigation.objectives],
            }

        elapsed = self._elapsed_seconds(investigation)
        pre_decision = evaluate_stop(investigation=investigation, elapsed_seconds=elapsed)
        if pre_decision.should_stop:
            return self._finalize(store, investigation, pre_decision).as_dict()

        graph = GraphView(store, target_id, investigation.seed_entity_ids)
        available = self._available_tool_ids(investigation)
        available -= self._circuit_breaker_tools(store, target_id)
        new_hypotheses = self._hypothesis_generator(store, investigation).generate(
            investigation, graph, available
        )
        if new_hypotheses:
            graph = GraphView(store, target_id, investigation.seed_entity_ids)

        ranking = self._rank_pivots(
            store, investigation, graph, available_tool_ids=available
        )
        post_decision = evaluate_stop(
            investigation=investigation,
            elapsed_seconds=elapsed,
            pivot_generated=ranking.generated,
            pivot_above_threshold=ranking.above_threshold,
        )
        if post_decision.should_stop:
            return self._finalize(store, investigation, post_decision).as_dict()

        remaining_calls = max(
            1, investigation.config.budgets.max_tool_calls - investigation.tool_calls
        )
        remaining_iters = max(
            1, investigation.config.budgets.max_iterations - investigation.iteration_count
        )
        wave_limit = max(1, min(int(max_pivots), remaining_calls, remaining_iters))
        wave_pivots = self._select_wave_pivots(ranking, wave_limit)
        if not wave_pivots:
            return self._finalize(store, investigation, post_decision).as_dict()

        timestamp = utc_now()
        prepared: list[tuple[PivotCandidate, Any, bool, Optional[ErrorCode], str]] = []
        runnable_indices: list[int] = []

        for pivot in wave_pivots:
            capability = cap_registry.get_tool(pivot.tool_id)
            if capability is None:
                prepared.append((pivot, None, False, ErrorCode.UNKNOWN_TOOL, f"unknown tool '{pivot.tool_id}'"))
                continue
            try:
                decision = self._policy_check(capability, pivot, investigation)
            except Exception as exc:  # noqa: BLE001 - fail closed
                prepared.append((pivot, capability, True, ErrorCode.SCOPE_BLOCKED,
                                 f"policy gate error: {type(exc).__name__}: {exc}"))
                continue
            if not decision.allowed:
                prepared.append((pivot, capability, True,
                                 decision.error_code or ErrorCode.SCOPE_BLOCKED, decision.reason))
                continue
            phash = param_hash(pivot.tool_id, pivot.params)
            claimed = store.try_claim_execution(ExecutionRecord(
                investigation_id=target_id,
                entity_id=pivot.entity_id,
                tool_id=pivot.tool_id,
                param_hash=phash,
                status=ExecutionStatus.ERROR,
                error_code=ErrorCode.SPAWN_ERROR,
                artifact_id=None,
                run_at=timestamp,
                duration_ms=0,
                error_message="in_flight: claimed by another worker",
            ))
            if not claimed:
                continue
            runnable_indices.append(len(prepared))
            prepared.append((pivot, capability, False, None, ""))

        if not prepared:
            return {
                "target_id": target_id,
                "status": "active",
                "stopped": False,
                "stop_reason": "pivot_in_flight",
                "iteration": investigation.iteration_count,
                "executed": [],
                "next_pivots": [p.model_dump(mode="json") for p in ranking.selected],
                "graph_summary": graph.summary(),
                "stats": store.stats(target_id),
                "objectives": [o.model_dump(mode="json") for o in investigation.objectives],
            }

        async def _exec_one(idx: int) -> tuple[int, ToolRunResult, int]:
            piv, cap, _pd, _ec, _em = prepared[idx]
            t0 = time.monotonic()
            try:
                res = await self._run_capability(runner, cap, piv, investigation, paths)
            except Exception as exc:  # noqa: BLE001
                res = ToolRunResult(
                    tool_id=cap.tool_id,
                    entity_id=piv.entity_id,
                    params=piv.params,
                    status=ExecutionStatus.ERROR,
                    error_code=ErrorCode.SPAWN_ERROR,
                    error_message=f"{type(exc).__name__}: {exc}",
                    started_at=timestamp,
                )
            elapsed_ms = res.duration_ms or int((time.monotonic() - t0) * 1000)
            return idx, res, elapsed_ms

        exec_results: dict[int, tuple[ToolRunResult, int]] = {}
        if runnable_indices:
            gathered = await asyncio.gather(
                *(_exec_one(idx) for idx in runnable_indices),
                return_exceptions=False,
            )
            for idx, res, elapsed_ms in gathered:
                exec_results[idx] = (res, elapsed_ms)

        executed_summaries: list[dict[str, Any]] = []
        last_record: Optional[IterationRecord] = None
        last_ingest = IngestResult()
        last_pivot: Optional[PivotCandidate] = None
        last_status: Optional[ExecutionStatus] = None

        for idx, (pivot, capability, policy_denied, pre_err_code, pre_err_msg) in enumerate(prepared):
            current_inv = store.get_investigation(target_id)
            assert current_inv is not None
            iteration_no = current_inv.iteration_count + 1
            pivot_ts = utc_now()
            errors: list[str] = []
            parse_output = ParseOutput()
            ingest = IngestResult()
            stdout = ""
            duration_ms = 0
            tool_called = False
            run_status = ExecutionStatus.ERROR
            error_code = pre_err_code
            error_message = pre_err_msg

            if idx in exec_results:
                run_result, duration_ms = exec_results[idx]
                tool_called = True
                stdout = run_result.stdout or ""
                run_status = run_result.status
                error_code = run_result.error_code
                error_message = run_result.error_message
                if error_code == ErrorCode.RATE_LIMITED:
                    try:
                        from hub.tools import cooldown

                        if pivot.tool_id in cooldown.COOLDOWN_TOOLS:
                            cooldown.mark_rate_limited(pivot.tool_id)
                    except Exception:  # noqa: BLE001
                        pass
                if run_status == ExecutionStatus.SUCCESS and capability is not None:
                    try:
                        parser = self._parser_for(capability)
                        target_value = _primary_param_value(pivot.params)
                        parsed_raw = parser(stdout, target_value)
                        parse_output = coerce_parse_output(
                            parsed_raw, parser_version=capability.parser_version
                        )
                        errors.extend(parse_output.warnings)
                    except Exception as exc:  # noqa: BLE001
                        parse_output = ParseOutput()
                        run_status = ExecutionStatus.ERROR
                        error_code = ErrorCode.PARSE_ERROR
                        error_message = f"parser failed: {type(exc).__name__}: {exc}"
                        errors.append(error_message)

            phash = param_hash(pivot.tool_id, pivot.params)
            raw_path = self._write_raw_artifact(paths, iteration_no, pivot.tool_id, stdout)
            snippet = self._evidence_snippet(parse_output, error_message)
            artifact = EvidenceArtifact(
                artifact_id=short_id("art", target_id, pivot.tool_id, phash, pivot_ts),
                investigation_id=target_id,
                source_tool=pivot.tool_id,
                invocation_params_hash=phash,
                timestamp_utc=pivot_ts,
                raw_evidence_snippet=snippet,
                raw_output_sha256=sha256_text(stdout),
                parser_version=(capability.parser_version if capability else "unknown"),
                epistemic_status=(
                    EpistemicStatus.SINGLE_SOURCE_LEAD
                    if run_status == ExecutionStatus.SUCCESS and error_code is None
                    else EpistemicStatus.COLLECTION_FAILURE
                ),
                confidence=(
                    capability.reliability
                    if capability and run_status == ExecutionStatus.SUCCESS
                    else 0.0
                ),
                raw_output_path=raw_path,
                stdout_bytes=len(stdout.encode("utf-8", errors="replace")),
                truncated=len(stdout) >= self._raw_output_limit,
            )

            if run_status == ExecutionStatus.SUCCESS and error_code is None:
                ledger_status = (
                    ExecutionStatus.EMPTY if parse_output.is_empty else ExecutionStatus.SUCCESS
                )
                if ledger_status == ExecutionStatus.EMPTY:
                    error_code = ErrorCode.EMPTY_RESULT
            elif run_status == ExecutionStatus.TIMEOUT:
                ledger_status = ExecutionStatus.TIMEOUT
            else:
                ledger_status = ExecutionStatus.ERROR

            closed_before = len(
                store.list_hypotheses(target_id, statuses=[HypothesisStatus.OPEN])
            )
            with store.transaction():
                store.add_artifact(artifact)
                if ledger_status in (ExecutionStatus.SUCCESS, ExecutionStatus.EMPTY) and capability is not None:
                    try:
                        ingest = EvidenceIngestor(store).ingest(
                            target_id,
                            parse_output,
                            artifact_id=artifact.artifact_id,
                            tool_id=pivot.tool_id,
                            accepted_types=capability.accepted_entity_types,
                            timestamp=pivot_ts,
                        )
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"ingest failed: {type(exc).__name__}: {exc}")
                        ledger_status = ExecutionStatus.ERROR
                        error_code = ErrorCode.PARSE_ERROR
                store.record_execution(
                    ExecutionRecord(
                        investigation_id=target_id,
                        entity_id=pivot.entity_id,
                        tool_id=pivot.tool_id,
                        param_hash=phash,
                        status=ledger_status,
                        error_code=error_code,
                        artifact_id=artifact.artifact_id,
                        run_at=pivot_ts,
                        duration_ms=duration_ms,
                        error_message=error_message,
                    )
                )
                self._refresh_scope_ips(store, store.get_investigation(target_id))
                hypothesis_mod.correlate_after_run(
                    store,
                    target_id,
                    executed_entity_id=pivot.entity_id,
                    executed_tool_id=pivot.tool_id,
                    run_status=ledger_status,
                    new_claims=ingest.new_claims,
                )
                self._refresh_objectives(store, current_inv)
                record = IterationRecord(
                    iteration=iteration_no,
                    timestamp_utc=pivot_ts,
                    action={
                        "pivot_id": pivot.pivot_id,
                        "tool": pivot.tool_id,
                        "params": pivot.params,
                        "entity_id": pivot.entity_id,
                        "hypothesis_id": pivot.hypothesis_id,
                        "score": pivot.score,
                        "policy_denied": policy_denied,
                        "parallel_wave": True,
                    },
                    result={
                        "status": ledger_status.value,
                        "error_code": error_code.value if error_code else None,
                        "error_message": error_message,
                        "duration_ms": duration_ms,
                        "stdout_bytes": artifact.stdout_bytes,
                        "parse": parse_output.summary(),
                        "ingest": ingest.as_dict() if ledger_status != ExecutionStatus.ERROR else {},
                        "warnings": errors[:5],
                    },
                    artifact_ids=[artifact.artifact_id],
                    new_entity_ids=ingest.new_entity_ids,
                    new_claims=ingest.new_claims,
                    contradictions=ingest.contradictions,
                    hypotheses_opened=len(new_hypotheses) if idx == 0 else 0,
                    hypotheses_closed=max(
                        0,
                        closed_before
                        - len(store.list_hypotheses(target_id, statuses=[HypothesisStatus.OPEN])),
                    ),
                    candidates_considered=ranking.generated,
                    candidate_count=ranking.above_threshold,
                    duration_ms=duration_ms,
                )
                store.record_iteration(target_id, record)
                store.bump_counters(
                    target_id,
                    iterations=1,
                    tool_calls=1 if tool_called else 0,
                    timestamp=pivot_ts,
                )

            executed_summaries.append({
                "iteration": iteration_no,
                "pivot_id": pivot.pivot_id,
                "tool_id": pivot.tool_id,
                "entity_id": pivot.entity_id,
                "status": ledger_status.value,
                "error_code": error_code.value if error_code else None,
                "new_entities": len(ingest.new_entity_ids),
                "new_claims": ingest.new_claims,
                "duration_ms": duration_ms,
            })
            last_record = record
            last_ingest = ingest
            last_pivot = pivot
            last_status = ledger_status

        refreshed = store.get_investigation(target_id)
        assert refreshed is not None
        graph_after = GraphView(store, target_id, refreshed.seed_entity_ids)
        elapsed_after = self._elapsed_seconds(refreshed)
        ranking_after = self._rank_pivots(
            store, refreshed, graph_after, available_tool_ids=available
        )
        decision_after = evaluate_stop(
            investigation=refreshed,
            elapsed_seconds=elapsed_after,
            pivot_generated=ranking_after.generated,
            pivot_above_threshold=ranking_after.above_threshold,
        )
        reflection = None
        if refreshed.config.reflection_enabled and last_pivot is not None:
            try:
                reflection = build_reflection_packet(
                    investigation=refreshed,
                    graph=graph_after,
                    executed={
                        "pivot_id": last_pivot.pivot_id,
                        "tool": last_pivot.tool_id,
                        "status": last_status.value if last_status else "ERROR",
                        "wave_size": len(executed_summaries),
                    },
                    ingest=last_ingest,
                    open_hypotheses=store.list_hypotheses(
                        target_id, statuses=[HypothesisStatus.OPEN]
                    ),
                    next_pivots=ranking_after.selected,
                    new_entity_ids=last_ingest.new_entity_ids,
                    target_entity_id=last_pivot.entity_id,
                )
            except Exception:  # noqa: BLE001
                reflection = None
        if refreshed.config.ai_reflection_auto and refreshed.config.reflection_enabled:
            await self._maybe_run_ai_reflection(store, target_id)

        if decision_after.should_stop:
            finalized = self._finalize(store, refreshed, decision_after)
            finalized.record = last_record
            finalized.pivot = last_pivot
            finalized.ledger_status = last_status
            finalized.reflection = reflection
            payload = finalized.as_dict()
            payload["status"] = "stopped"
            payload["executed"] = executed_summaries
            payload["wave_count"] = len(executed_summaries)
            return payload

        return {
            "target_id": target_id,
            "status": "active",
            "stopped": False,
            "stop_reason": "continue",
            "stop_detail": decision_after.detail,
            "iteration": refreshed.iteration_count,
            "wave_count": len(executed_summaries),
            "executed": executed_summaries,
            "action": last_pivot.model_dump(mode="json") if last_pivot else None,
            "record": last_record.model_dump(mode="json") if last_record else None,
            "next_pivots": [p.model_dump(mode="json") for p in ranking_after.selected],
            "reflection": reflection.model_dump(mode="json") if reflection else None,
            "ledger_status": last_status.value if last_status else None,
            "graph_summary": graph_after.summary(),
            "stats": store.stats(target_id),
            "objectives": [o.model_dump(mode="json") for o in refreshed.objectives],
        }

    # ── helpers: planning / execution / persistence ────────────────

    def _rank_pivots(self, store: ERKGStore, investigation: InvestigationState,
                     graph: GraphView,
                     available_tool_ids: Optional[set[str]] = None) -> PivotRanking:
        available = (available_tool_ids if available_tool_ids is not None
                     else self._available_tool_ids(investigation))
        scorer = PivotScorer(
            weights=investigation.config.weights,
            min_threshold=investigation.config.min_pivot_threshold,
            top_k=investigation.config.top_k_pivots,
            max_entities=investigation.config.max_entities,
        )
        ledger = store.list_ledger(investigation.target_id)
        executed_keys = {
            (entry.entity_id, entry.tool_id, entry.param_hash)
            for entry in ledger
        }
        blocked = self._circuit_breaker_tools(store, investigation.target_id,
                                              ledger=ledger)
        try:
            from hub.tools import cooldown

            blocked |= cooldown.cooled_tool_ids()
        except Exception:  # noqa: BLE001
            pass
        available = {tool_id for tool_id in available
                     if tool_id.lower() not in blocked}
        successful_entities = {
            entry.entity_id for entry in ledger
            if entry.status == ExecutionStatus.SUCCESS
        }
        open_hypotheses = store.list_hypotheses(
            investigation.target_id, statuses=[HypothesisStatus.OPEN])
        return scorer.rank(graph, open_hypotheses,
                           allowed_tool_ids=available,
                           executed_keys=executed_keys,
                           blocked_tool_ids=blocked,
                           successful_entity_ids=successful_entities)

    #: Error codes that permanently trip a tool's circuit breaker in one run.
    _CIRCUIT_BREAKER_CODES = frozenset({
        ErrorCode.RATE_LIMITED,
        ErrorCode.AUTHORIZATION_REQUIRED,
        ErrorCode.MISSING_BINARY,
    })

    def _circuit_breaker_tools(self, store: ERKGStore, target_id: str, *,
                               ledger=None) -> set[str]:
        """Tool ids already failed hard in this investigation (never retried)."""
        records = ledger if ledger is not None else store.list_ledger(target_id)
        blocked: set[str] = set()
        for entry in records:
            if entry.error_code in self._CIRCUIT_BREAKER_CODES:
                blocked.add(str(entry.tool_id).lower())
        return blocked

    def _hypothesis_generator(self, store: ERKGStore,
                              investigation: InvestigationState) -> hypothesis_mod.HypothesisGenerator:
        return hypothesis_mod.HypothesisGenerator(
            store,
            max_per_entity=investigation.config.max_hypotheses_per_entity,
        )

    def _available_tool_ids(self, investigation: InvestigationState) -> set[str]:
        scope = investigation.config.scope
        available: set[str] = set()
        for capability in cap_registry.all_capabilities():
            if capability.execution_mode.value == "INTRUSIVE_BLOCKED":
                continue
            if (capability.execution_mode.value == "ACTIVE_RECON"
                    and not scope.allow_active_recon):
                continue
            if capability.authorization_required and not scope.allow_authorized_tools:
                continue
            try:
                healthy = (self._health_probe(capability)
                           if self._health_probe is not None
                           else self._default_health(capability))
            except Exception:  # noqa: BLE001 - unhealthy is a safe default
                healthy = False
            if healthy and cap_registry.capability_auth_ready(capability):
                available.add(capability.tool_id)
        try:
            from hub.tools import cooldown

            available -= {tool_id.lower() for tool_id in cooldown.cooled_tool_ids()}
        except Exception:  # noqa: BLE001
            pass
        return available

    @staticmethod
    def _default_health(capability) -> bool:
        status = cap_registry.health_check(capability.tool_id)
        return bool(status and status.available and status.auth_ready)

    @staticmethod
    def _policy_check(capability, pivot: PivotCandidate,
                      investigation: InvestigationState):
        from hub.security.policy import check_capability

        return check_capability(
            capability, pivot.params, investigation.config.scope,
            allow_authorized_tools=investigation.config.scope.allow_authorized_tools,
            allow_intrusive=investigation.config.scope.allow_intrusive,
        )

    async def _run_capability(self, runner: Any, capability,
                              pivot: PivotCandidate,
                              investigation: InvestigationState,
                              paths: "InvestigationPaths") -> ToolRunResult:
        from hub.tools.runtime import RunContext

        context = RunContext(
            investigation_id=investigation.target_id,
            entity_id=pivot.entity_id,
            scope=investigation.config.scope,
            allow_authorized_tools=investigation.config.scope.allow_authorized_tools,
            allow_intrusive=investigation.config.scope.allow_intrusive,
            max_concurrent_tools=investigation.config.max_concurrent_tools,
            scratch_dir=str(paths.scratch),
        )
        return await runner.run(capability, pivot.params, context)

    def _parser_for(self, capability):
        if self._parser_resolver is not None:
            return self._parser_resolver(capability)
        return capability.parser()

    def _ensure_runner(self, config: InvestigationConfig):
        if self._runner is not None:
            return self._runner
        if self._runtime is None:
            from hub.tools.runtime import ToolRuntime

            self._runtime = ToolRuntime(
                max_concurrent_tools=config.max_concurrent_tools,
                scratch_root=self.state_root() / "_scratch",
            )
        return self._runtime

    async def _close_runner(self, runner: Any) -> None:
        if runner is self._runtime:
            close = getattr(runner, "aclose", None)
            if close is not None:
                try:
                    await close()
                except Exception:  # noqa: BLE001
                    pass
            self._runtime = None

    # ── state helpers ──────────────────────────────────────────────

    def _now(self) -> datetime:
        if self._now_provider is not None:
            return self._now_provider()
        return datetime.now(timezone.utc)

    def _elapsed_seconds(self, investigation: InvestigationState) -> float:
        try:
            start = datetime.fromisoformat(investigation.created_at)
            now = self._now()
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            return max(0.0, (now - start).total_seconds())
        except (ValueError, TypeError):
            return 0.0

    def _refresh_scope_ips(self, store: ERKGStore,
                           investigation: Optional[InvestigationState]) -> None:
        """Extend scope.allow_ips with public IPs of allow-listed domains.

        A domain allowlist authorizes reconnaissance of that domain's
        infrastructure. Only IPs *observed via evidence-backed RESOLVES_TO
        claims* from entities inside the allowlist are added, and private /
        loopback / metadata addresses are excluded regardless.
        """
        if investigation is None:
            return
        from hub.erkg.resolution import is_public_ip, normalize_domain, split_hostname

        scope = investigation.config.scope
        if not scope.allow_domains:
            return
        allowed_domains = {normalize_domain(domain) for domain in scope.allow_domains
                           if domain}
        current = set(scope.allow_ips)
        added: set[str] = set()
        for claim in store.get_edges(investigation.target_id):
            if claim.predicate != "RESOLVES_TO" or claim.object_id is None:
                continue
            subject = store.get_entity(claim.subject_id)
            obj = store.get_entity(claim.object_id)
            if subject is None or obj is None or obj.type != EntityType.IP:
                continue
            parts = split_hostname(subject.canonical_value)
            if parts is None:
                continue
            host, registrable, _is_sub = parts
            if not any(host == domain or host.endswith("." + domain)
                       for domain in allowed_domains):
                continue
            if is_public_ip(obj.canonical_value) and obj.canonical_value not in current:
                added.add(obj.canonical_value)
        if not added:
            return
        new_scope = scope.model_copy(update={"allow_ips": sorted(current | added)})
        new_config = investigation.config.model_copy(update={"scope": new_scope})
        store.update_investigation(
            investigation.target_id,
            config_json=json.dumps(new_config.model_dump(mode="json")),
            updated_at=utc_now(),
        )

    def _refresh_objectives(self, store: ERKGStore,
                            investigation: InvestigationState) -> list[Objective]:
        objectives: list[Objective] = []
        for objective in investigation.objectives:
            claims = store.list_claims(investigation.target_id,
                                       subject_id=objective.entity_id)
            status = compute_objective_status([claim.status for claim in claims])
            objectives.append(objective.model_copy(update={
                "status": status,
                "achieved": status in (EpistemicStatus.CONFIRMED,
                                       EpistemicStatus.CORROBORATED),
            }))
        store.set_objectives(investigation.target_id, objectives)
        return objectives

    def _finalize(self, store: ERKGStore, investigation: InvestigationState,
                  decision: StopDecision) -> IterationOutcome:
        hypothesis_mod.mark_stale_hypotheses(store, investigation.target_id)
        status = RunStatus.TERMINATED if decision.is_budget_stop else RunStatus.COMPLETED
        store.finish_investigation(investigation.target_id, status, decision.reason)
        refreshed = store.get_investigation(investigation.target_id)
        graph = GraphView(store, investigation.target_id,
                          refreshed.seed_entity_ids if refreshed else [])
        return IterationOutcome(
            target_id=investigation.target_id,
            stopped=True,
            stop_reason=decision.reason,
            stop_detail=decision.detail,
            iteration=(refreshed.iteration_count if refreshed
                       else investigation.iteration_count),
            graph_summary=graph.summary(),
            stats=store.stats(investigation.target_id),
            objectives=[o.model_dump(mode="json")
                        for o in (refreshed.objectives if refreshed else [])],
        )

    def _outcome(self, store: ERKGStore, paths: "InvestigationPaths",
                 target_id: str, *, store_override_ready: bool = True
                 ) -> InvestigationOutcome:
        investigation = store.get_investigation(target_id)
        if investigation is None:
            raise EngineError(f"investigation not found: {target_id}")
        graph = GraphView(store, target_id, investigation.seed_entity_ids)
        try:
            ranking = self._rank_pivots(store, investigation, graph)
        except Exception:  # noqa: BLE001
            ranking = PivotRanking()
        return InvestigationOutcome(
            target_id=target_id,
            status=investigation.status,
            stop_reason=investigation.stop_reason or investigation.status.value,
            iterations=investigation.iteration_count,
            tool_calls=investigation.tool_calls,
            state_path=str(paths.root),
            stats=store.stats(target_id),
            objectives=[o.model_dump(mode="json") for o in investigation.objectives],
            next_pivots=(ranking.selected if investigation.status == RunStatus.ACTIVE else []),
        )

    # ── raw evidence / snippets ────────────────────────────────────

    def _write_raw_artifact(self, paths: "InvestigationPaths", iteration: int,
                            tool_id: str, stdout: str) -> Optional[str]:
        if not stdout:
            return None
        paths.ensure()
        safe_tool = re.sub(r"[^a-z0-9_]+", "_", tool_id.lower())
        filename = f"{iteration:03d}_{safe_tool}.txt"
        payload = stdout[: self._raw_output_limit]
        (paths.raw / filename).write_text(payload, encoding="utf-8",
                                          errors="replace")
        return f"raw/{filename}"

    @staticmethod
    def _evidence_snippet(parse_output: ParseOutput, error_message: str) -> str:
        snippets: list[str] = []
        for entity in parse_output.entities:
            if entity.evidence:
                snippets.append(entity.evidence)
        for relation in parse_output.relations:
            if relation.evidence:
                snippets.append(relation.evidence)
        if not snippets and error_message:
            return error_message[:EVIDENCE_SNIPPET_LIMIT]
        unique: list[str] = []
        for snippet in snippets:
            if snippet not in unique:
                unique.append(snippet)
        return "\n".join(unique)[:EVIDENCE_SNIPPET_LIMIT]


# ════════════════════════════════════════════════════════════════════════
# Paths & config helpers
# ════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class InvestigationPaths:
    root: Path

    @property
    def target_id(self) -> str:
        return self.root.name

    @property
    def db(self) -> Path:
        return self.root / "erkg.sqlite3"

    @property
    def raw(self) -> Path:
        return self.root / "raw"

    @property
    def scratch(self) -> Path:
        return self.root / "scratch"

    def ensure(self) -> "InvestigationPaths":
        self.root.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        self.scratch.mkdir(parents=True, exist_ok=True)
        return self


def make_target_id(raw_input: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = sha256_text(f"{raw_input}|{time.time_ns()}")[:4]
    return f"case_{stamp}_{suffix}"


def build_config(raw_input: str,
                 overrides: Optional[dict[str, Any]] = None) -> InvestigationConfig:
    """Build a validated config from raw CLI/MCP overrides."""
    overrides = dict(overrides or {})
    target_id = str(overrides.pop("target_id", "") or "") or make_target_id(raw_input)
    data: dict[str, Any] = {"target_id": target_id, "raw_input": raw_input}
    if isinstance(overrides.get("budgets"), dict):
        data["budgets"] = overrides.pop("budgets")
    if isinstance(overrides.get("scope"), dict):
        data["scope"] = overrides.pop("scope")
    if isinstance(overrides.get("weights"), dict):
        data["weights"] = overrides.pop("weights")
    allowed_keys = {
        "min_pivot_threshold", "top_k_pivots", "max_concurrent_tools",
        "max_hypotheses_per_entity", "max_entities", "allow_hypothesis_expansion",
        "collect_raw_artifacts", "reflection_enabled",
        "parallel_pivots", "ai_reflection_auto", "ai_vision_enabled",
    }
    for key in list(overrides):
        if key in allowed_keys:
            data[key] = overrides.pop(key)
    # Convenience flat budget flags (CLI UX).
    budget_overrides = dict(data.get("budgets") or {})
    alias_map = {
        "max_iterations": "max_iterations",
        "max_tool_calls": "max_tool_calls",
        "wall_clock_timeout_sec": "wall_clock_timeout_sec",
        "timeout_sec": "wall_clock_timeout_sec",
    }
    for source_key in list(overrides):
        if source_key in alias_map:
            budget_overrides[alias_map[source_key]] = overrides.pop(source_key)
    if budget_overrides:
        data["budgets"] = BudgetConfig(**{**budget_overrides}).model_dump(mode="json")
    data["budgets"] = BudgetConfig.model_validate(data.get("budgets") or {}).model_dump(
        mode="json")
    return InvestigationConfig.model_validate(data)


def _url_host(value: str) -> str:
    from urllib.parse import urlsplit

    text = str(value or "").strip()
    if "://" not in text:
        text = "//" + text.lstrip("/")
    try:
        return (urlsplit(text).hostname or "").lower()
    except ValueError:
        return ""


def _primary_param_value(params: dict[str, Any]) -> str:
    if not params:
        return ""
    value = next(iter(params.values()))
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value)


__all__ = [
    "InvestigationEngine",
    "InvestigationOutcome",
    "IterationOutcome",
    "InvestigationPaths",
    "EngineError",
    "build_config",
    "make_target_id",
]
