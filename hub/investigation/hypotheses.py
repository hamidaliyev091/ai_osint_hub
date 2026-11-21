"""Explicit structured hypotheses (Spec 2, Plan stage).

Before tools are selected, the planner states hypotheses linking known graph
nodes to unanswered investigative questions:

  CORROBORATION  — an independent source should confirm/refute a lead claim.
  RESOLUTION     — a contradiction between two claims needs resolution.
  EXPANSION      — an entity may reveal additional entity types.
  IDENTITY_LINK  — an email/username variant may be the same identity.
  VERIFICATION   — a planner-generated hypothesis entity should be checked.

Hypotheses are persisted and scored: pivots that address an OPEN hypothesis
get the maximum CorroborationValue boost. All generation is deterministic.
"""

from __future__ import annotations

from typing import Iterable, Optional

from hub.erkg.graph import GraphView
from hub.erkg.resolution import derive_entity_drafts
from hub.erkg.store import ERKGStore
from hub.models import (
    EdgeType,
    EntityType,
    EpistemicStatus,
    ExecutionStatus,
    Hypothesis,
    HypothesisStatus,
    HypothesisType,
    InvestigationState,
    short_id,
    utc_now,
)
from hub.tools import capabilities as cap_registry


#: Internal bookkeeping attributes that must never generate OSINT hypotheses.
_INTERNAL_ATTRIBUTE_KEYS = frozenset({
    "clue_field", "clue_source", "provenance", "role", "seed_wave",
    "derived_from_email",
})
#: Generic role mailboxes are not personal identity handles.
_ROLE_MAILBOX_LOCALPARTS = frozenset({
    "info", "contact", "admin", "support", "office", "mail", "hr", "sales",
    "press", "help",
})


def _is_internal_claim(claim) -> bool:
    predicate = str(claim.predicate or "")
    if not predicate.upper().startswith("HAS_ATTRIBUTE:"):
        return False
    key = predicate.split(":", 1)[1].strip().lower()
    return key in _INTERNAL_ATTRIBUTE_KEYS


def _open_hypothesis(investigation_id: str, hypothesis_type: HypothesisType,
                     target_entity_id: Optional[str], target_claim_id: Optional[str],
                     proposed_tool_ids: list[str], question: str, rationale: str,
                     timestamp: str) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=short_id("hyp", investigation_id, hypothesis_type.value,
                               target_entity_id or "", target_claim_id or "",
                               ",".join(sorted(proposed_tool_ids))),
        investigation_id=investigation_id,
        hypothesis_type=hypothesis_type,
        question=question,
        target_entity_id=target_entity_id,
        target_claim_id=target_claim_id,
        proposed_tool_ids=sorted(set(proposed_tool_ids)),
        rationale=rationale,
        status=HypothesisStatus.OPEN,
        created_by="planner",
        created_at=timestamp,
        updated_at=timestamp,
    )


class HypothesisGenerator:
    """Deterministic hypothesis generation from ERKG state."""

    def __init__(self, store: ERKGStore, *, max_per_entity: int = 3,
                 max_new_per_iteration: int = 25):
        self.store = store
        self.max_per_entity = max_per_entity
        self.max_new_per_iteration = max_new_per_iteration

    def generate(self, investigation: InvestigationState, graph: GraphView,
                 available_tool_ids: Iterable[str]) -> list[Hypothesis]:
        inv = investigation.target_id
        now = utc_now()
        available = {t.lower() for t in available_tool_ids}
        new_hypotheses: list[Hypothesis] = []

        def add(hypothesis: Hypothesis) -> None:
            if len(new_hypotheses) >= self.max_new_per_iteration:
                return
            if self.store.hypothesis_exists(inv, hypothesis.hypothesis_type.value,
                                            hypothesis.target_entity_id,
                                            hypothesis.target_claim_id):
                return
            existing = self.store.list_hypotheses(inv, target_entity_id=hypothesis.target_entity_id)
            if len(existing) >= self.max_per_entity:
                return
            self.store.add_hypothesis(hypothesis)
            new_hypotheses.append(hypothesis)

        # ── 1. Corroboration of single-source lead claims ──────────
        lead_claims = sorted(
            [c for c in graph.claims
             if c.status == EpistemicStatus.SINGLE_SOURCE_LEAD
             and not _is_internal_claim(c)],
            key=lambda c: (-c.confidence, c.claim_id),
        )
        for claim in lead_claims[:10]:
            subject = graph.entity(claim.subject_id)
            if subject is None:
                continue
            tools = [
                cap.tool_id for cap in cap_registry.for_entity(subject.type)
                if cap.tool_id.lower() in available
                and cap.tool_id not in claim.independent_sources
            ]
            if not tools:
                continue
            add(_open_hypothesis(
                inv, HypothesisType.CORROBORATION, claim.subject_id, claim.claim_id,
                tools,
                question=(f"Can an independent source corroborate '{claim.predicate}' "
                          f"on {subject.canonical_value}?"),
                rationale=(f"Claim is SINGLE_SOURCE_LEAD (confidence {claim.confidence:.2f}) "
                           f"from {', '.join(claim.independent_sources) or 'unknown source'}."),
                timestamp=now,
            ))

        # ── 2. Resolution of contradictions ────────────────────────
        for contradiction in self.store.list_contradictions(inv)[:10]:
            claim = self.store.get_claim(contradiction.claim_a)
            if claim is None:
                continue
            subject = graph.entity(claim.subject_id)
            if subject is None:
                continue
            tools = [cap.tool_id for cap in cap_registry.for_entity(subject.type)
                     if cap.tool_id.lower() in available]
            if not tools:
                continue
            add(_open_hypothesis(
                inv, HypothesisType.RESOLUTION, claim.subject_id, claim.claim_id, tools,
                question=(f"Which value is correct for '{claim.predicate}' on "
                          f"{subject.canonical_value}?"),
                rationale="Two functional claims disagree; collect an independent source.",
                timestamp=now,
            ))

        # ── 3. Expansion for seed / verified entities ──────────────
        seed_ids = set(investigation.seed_entity_ids)
        for entity_id in sorted(seed_ids):
            entity = graph.entity(entity_id)
            if entity is None:
                continue
            for capability in cap_registry.for_entity(entity.type):
                if capability.tool_id.lower() not in available:
                    continue
                if self.store.has_execution(inv, entity_id, capability.tool_id,
                                            param_hash_for(capability, entity.type,
                                                           entity.canonical_value)):
                    continue
                add(_open_hypothesis(
                    inv, HypothesisType.EXPANSION, entity_id, None, [capability.tool_id],
                    question=(f"What does {capability.tool_id} reveal about "
                              f"{entity.type.value} {entity.canonical_value}?"),
                    rationale=(f"Seed entity has not been queried with "
                               f"{capability.tool_id} (expected yield "
                               f"{capability.prior_yield:.2f})."),
                    timestamp=now,
                ))

        # ── 4. Identity link: email prefix ↔ username ──────────────
        for email_entity in graph.entities.values():
            if email_entity.type != EntityType.EMAIL:
                continue
            prefix = email_entity.canonical_value.split("@", 1)[0]
            if len(prefix) < 2:
                continue
            # info@/contact@/… are role mailboxes, not personal usernames.
            if prefix.lower().split("+", 1)[0] in _ROLE_MAILBOX_LOCALPARTS:
                continue
            existing = self.store.get_entity_by_value(inv, EntityType.USERNAME, prefix)
            if existing is not None:
                username_id = existing.entity_id
            else:
                drafts, _ = derive_entity_drafts(EntityType.USERNAME, prefix,
                                                 metadata={"origin": "hypothesis",
                                                           "derived_from": email_entity.entity_id})
                if not drafts:
                    continue
                username_entity, _ = self._resolver().resolve_draft(
                    inv, drafts[0], artifact_id=None, timestamp=now)
                username_entity.metadata.setdefault("origin", "hypothesis")
                username_id = username_entity.entity_id
                if not [c for c in graph.claims_for(username_id)
                        if c.predicate == EdgeType.IDENTIFIED_AS.value]:
                    self.store.add_hypothesis_claim(
                        inv, username_id, EdgeType.IDENTIFIED_AS.value,
                        object_literal=username_entity.canonical_value,
                        timestamp=now, confidence=0.30)
            tools = [cap.tool_id for cap in cap_registry.for_entity(EntityType.USERNAME)
                     if cap.tool_id.lower() in available
                     and not self.store.has_execution(
                         inv, username_id, cap.tool_id,
                         param_hash_for(cap, EntityType.USERNAME, prefix))]
            if not tools:
                continue
            add(_open_hypothesis(
                inv, HypothesisType.IDENTITY_LINK, username_id, None, tools,
                question=(f"Is username '{prefix}' linked to {email_entity.canonical_value}?"),
                rationale="Email local-part is a plausible username hypothesis.",
                timestamp=now,
            ))

        # ── 5. Verification of HYPOTHESIS-only entities ────────────
        for entity_id, entity in sorted(graph.entities.items()):
            claims = graph.subject_claims(entity_id)
            if not claims:
                continue
            if all(claim.status == EpistemicStatus.HYPOTHESIS for claim in claims):
                tools = [cap.tool_id for cap in cap_registry.for_entity(entity.type)
                         if cap.tool_id.lower() in available]
                if not tools:
                    continue
                add(_open_hypothesis(
                    inv, HypothesisType.VERIFICATION, entity_id, claims[0].claim_id,
                    tools,
                    question=f"Does any source confirm {entity.type.value} '{entity.canonical_value}'?",
                    rationale="Entity currently exists only as a planner hypothesis.",
                    timestamp=now,
                ))

        return new_hypotheses

    def _resolver(self):
        from hub.erkg.resolution import EntityResolver

        return EntityResolver(self.store)


def param_hash_for(capability, entity_type, entity_value: str) -> str:
    """Compute the invocation hash for the canonical pivot params of one entity."""
    from hub.models import param_hash

    params = cap_registry.build_params_for_entity(capability, entity_type, entity_value)
    return param_hash(capability.tool_id, params or {})


def correlate_after_run(store: ERKGStore, investigation_id: str, *,
                        executed_entity_id: str, executed_tool_id: str,
                        run_status: ExecutionStatus, new_claims: int) -> int:
    """Close hypotheses whose question is answered by the executed run."""
    closed = 0
    open_hypotheses = store.list_hypotheses(investigation_id,
                                            statuses=[HypothesisStatus.OPEN])
    for hypothesis in open_hypotheses:
        if hypothesis.target_entity_id != executed_entity_id:
            continue
        if hypothesis.proposed_tool_ids and executed_tool_id not in hypothesis.proposed_tool_ids:
            continue
        if hypothesis.hypothesis_type == HypothesisType.CORROBORATION:
            claim = store.get_claim(hypothesis.target_claim_id) if hypothesis.target_claim_id else None
            if claim is None:
                continue
            if claim.status in (EpistemicStatus.CONFIRMED, EpistemicStatus.CORROBORATED):
                store.update_hypothesis(hypothesis.hypothesis_id,
                                        status=HypothesisStatus.SUPPORTED,
                                        closing_note="independent corroboration found")
                closed += 1
            elif claim.status == EpistemicStatus.CONTRADICTED:
                store.update_hypothesis(hypothesis.hypothesis_id,
                                        status=HypothesisStatus.REFUTED,
                                        closing_note="claim contradicted by new evidence")
                closed += 1
        elif hypothesis.hypothesis_type in (HypothesisType.EXPANSION,
                                            HypothesisType.IDENTITY_LINK,
                                            HypothesisType.VERIFICATION):
            if run_status == ExecutionStatus.EMPTY:
                store.update_hypothesis(hypothesis.hypothesis_id,
                                        status=HypothesisStatus.REFUTED,
                                        closing_note="tool returned no new evidence")
                closed += 1
            elif new_claims > 0:
                store.update_hypothesis(hypothesis.hypothesis_id,
                                        status=HypothesisStatus.SUPPORTED,
                                        closing_note=f"{new_claims} claim(s) collected")
                closed += 1
        elif hypothesis.hypothesis_type == HypothesisType.RESOLUTION:
            claim = store.get_claim(hypothesis.target_claim_id) if hypothesis.target_claim_id else None
            if claim is not None and claim.status in (EpistemicStatus.CONFIRMED,
                                                      EpistemicStatus.CORROBORATED):
                store.update_hypothesis(hypothesis.hypothesis_id,
                                        status=HypothesisStatus.SUPPORTED,
                                        closing_note="winning value corroborated")
                closed += 1
    return closed


def mark_stale_hypotheses(store: ERKGStore, investigation_id: str) -> int:
    """At investigation end: mark still-OPEN hypotheses INCONCLUSIVE for the report."""
    count = 0
    for hypothesis in store.list_hypotheses(investigation_id,
                                            statuses=[HypothesisStatus.OPEN]):
        store.update_hypothesis(hypothesis.hypothesis_id,
                                status=HypothesisStatus.INCONCLUSIVE,
                                closing_note="budget exhausted before answer")
        count += 1
    return count


__all__ = ["HypothesisGenerator", "correlate_after_run", "mark_stale_hypotheses",
           "param_hash_for"]
