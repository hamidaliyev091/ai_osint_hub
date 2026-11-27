"""Evidence ingestion — the Normalize stage of the investigation loop.

Turns a deterministic :class:`~hub.tools.base.ParseOutput` into ERKG state:

1. every entity candidate is canonicalized/derived/resolved (aliases merge);
2. every entity gets an ``IDENTIFIED_AS`` claim plus ``HAS_ATTRIBUTE:*`` claims
   for structured parser facts, each citing the run's immutable artifact;
3. every relation candidate becomes an evidence-backed edge claim;
4. all claims are scored deterministically (single source vs corroboration)
   and functional-predicate conflicts are recorded as contradictions.

This is pure deterministic Python — no LLM involvement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from hub.erkg.resolution import (
    EntityResolver,
    derive_entity_drafts,
    is_noreply_email,
    is_valid_username,
)
from hub.erkg.store import ERKGStore
from hub.models import EdgeType, Entity, EntityType, EpistemicStatus, param_hash
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

_ROLE_LOCALPARTS = frozenset({
    "info", "contact", "admin", "support", "office", "mail", "hr", "sales",
    "press", "help", "staff", "team", "user", "users", "noreply", "no-reply",
})


@dataclass
class IngestResult:
    """Summary of one ingest transaction."""

    new_entity_ids: list[str] = field(default_factory=list)
    entities_seen: int = 0
    new_claims: int = 0
    contradictions: int = 0
    relation_claims: int = 0
    identity_claims: int = 0
    attribute_claims: int = 0
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "new_entities": len(self.new_entity_ids),
            "entities_seen": self.entities_seen,
            "new_claims": self.new_claims,
            "contradictions": self.contradictions,
            "relation_claims": self.relation_claims,
            "identity_claims": self.identity_claims,
            "attribute_claims": self.attribute_claims,
            "warnings": self.warnings[:10],
        }


class EvidenceIngestor:
    """Deterministic Normalize/Correlate implementation for one artifact."""

    def __init__(self, store: ERKGStore):
        self.store = store
        self.resolver = EntityResolver(store)

    # ── public API ─────────────────────────────────────────────────

    def ingest(self, investigation_id: str, parse_output: ParseOutput, *,
               artifact_id: str, tool_id: str, accepted_types: Iterable[EntityType],
               timestamp: str) -> IngestResult:
        result = IngestResult(warnings=list(parse_output.warnings))
        before_claims = self.store.count_claims(investigation_id)
        before_contradictions = len(self.store.list_contradictions(investigation_id))
        accepted = {EntityType.coerce(t) for t in accepted_types}

        for candidate in parse_output.entities:
            try:
                entity, is_new = self.ingest_entity(
                    investigation_id, candidate, artifact_id=artifact_id,
                    tool_id=tool_id, timestamp=timestamp)
            except Exception as exc:  # noqa: BLE001 - one bad entity must not kill a run
                result.warnings.append(
                    f"entity ingest failed ({candidate.type.value}:{candidate.value}): "
                    f"{type(exc).__name__}: {exc}")
                continue
            result.entities_seen += 1
            if is_new:
                result.new_entity_ids.append(entity.entity_id)
            result.identity_claims += 1
            result.attribute_claims += self._ingest_attributes(
                investigation_id, entity, candidate, artifact_id=artifact_id,
                tool_id=tool_id, timestamp=timestamp)

        for relation in parse_output.relations:
            try:
                created = self.ingest_relation(
                    investigation_id, relation, artifact_id=artifact_id,
                    tool_id=tool_id, timestamp=timestamp)
            except Exception as exc:  # noqa: BLE001
                result.warnings.append(
                    f"relation ingest failed ({relation.predicate.value}): "
                    f"{type(exc).__name__}: {exc}")
                continue
            if created:
                result.relation_claims += 1

        result.new_claims = max(0, self.store.count_claims(investigation_id) - before_claims)
        result.contradictions = max(
            0, len(self.store.list_contradictions(investigation_id)) - before_contradictions)
        self._unify_duplicate_persons(investigation_id, timestamp, result)
        return result

    def _unify_duplicate_persons(
        self,
        investigation_id: str,
        timestamp: str,
        result: IngestResult,
    ) -> None:
        """Merge duplicate PERSON nodes sharing a verified unique username or email."""
        persons = self.store.list_entities(investigation_id, types=[EntityType.PERSON])
        if len(persons) < 2:
            return
        inv = self.store.get_investigation(investigation_id)
        seed_set = set(inv.seed_entity_ids) if inv is not None else set()
        entities = {e.entity_id: e for e in self.store.list_entities(investigation_id)}
        claims = self.store.list_claims(investigation_id)

        ident_map: dict[str, set[str]] = {p.entity_id: set() for p in persons}
        ignored_statuses = {
            EpistemicStatus.HYPOTHESIS,
            EpistemicStatus.CONTRADICTED,
            EpistemicStatus.COLLECTION_FAILURE,
        }
        for claim in claims:
            if claim.subject_id not in ident_map or claim.status in ignored_statuses:
                continue
            if claim.object_id and claim.object_id in entities:
                obj = entities[claim.object_id]
                if (
                    obj.type == EntityType.USERNAME
                    and claim.predicate in {
                        EdgeType.HAS_USERNAME.value,
                        EdgeType.IDENTIFIED_AS.value,
                        EdgeType.OWNS.value,
                    }
                    and is_valid_username(obj.canonical_value)
                ):
                    ident_map[claim.subject_id].add(f"u:{obj.canonical_value.lower()}")
                elif (
                    obj.type == EntityType.EMAIL
                    and claim.predicate == EdgeType.HAS_EMAIL.value
                    and not is_noreply_email(obj.canonical_value)
                ):
                    local = obj.canonical_value.split("@", 1)[0].split("+", 1)[0].lower()
                    if local not in _ROLE_LOCALPARTS:
                        ident_map[claim.subject_id].add(f"e:{obj.canonical_value.lower()}")
            elif (
                claim.predicate == "HAS_ATTRIBUTE:login"
                and isinstance(claim.object_literal, str)
                and is_valid_username(claim.object_literal)
            ):
                ident_map[claim.subject_id].add(f"u:{claim.object_literal.strip().lower()}")

        parent = {p.entity_id: p.entity_id for p in persons}
        person_by_id = {p.entity_id: p for p in persons}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def priority(pid: str) -> tuple:
            ent = person_by_id[pid]
            prov = str((ent.metadata or {}).get("provenance") or "")
            return (
                1 if pid in seed_set else 0,
                1 if prov == "USER_PROVIDED_SEED" else 0,
                len(ent.canonical_value.split()),
                len(ent.canonical_value),
            )

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra == rb:
                return
            pa, pb = priority(ra), priority(rb)
            if pa > pb or (pa == pb and (person_by_id[ra].first_seen, ra) <= (person_by_id[rb].first_seen, rb)):
                parent[rb] = ra
            else:
                parent[ra] = rb

        by_ident: dict[str, list[str]] = {}
        for pid, keys in ident_map.items():
            for key in keys:
                by_ident.setdefault(key, []).append(pid)
        for pids in by_ident.values():
            if len(pids) > 1:
                base = pids[0]
                for other in pids[1:]:
                    union(base, other)

        merged_drops: dict[str, str] = {}
        for pid in list(parent):
            root = find(pid)
            if pid != root:
                self.store.merge_entities(
                    investigation_id, root, pid, timestamp=timestamp
                )
                merged_drops[pid] = root

        if merged_drops and result.new_entity_ids:
            updated_new: list[str] = []
            for eid in result.new_entity_ids:
                if eid in merged_drops:
                    continue
                if eid not in updated_new:
                    updated_new.append(eid)
            result.new_entity_ids = updated_new

    def ingest_entity(self, investigation_id: str, candidate: EntityCandidate, *,
                      artifact_id: str, tool_id: str, timestamp: str) -> tuple[Entity, bool]:
        if not str(candidate.value or "").strip():
            raise ValueError("empty entity value rejected")
        if candidate.type == EntityType.USERNAME:
            from hub.erkg.resolution import is_valid_username

            if not is_valid_username(candidate.value):
                if "@" in str(candidate.value) and "://" not in str(candidate.value):
                    # Parser mistake: an e-mail address labelled as USERNAME.
                    candidate = candidate.model_copy(update={"type": EntityType.EMAIL})
                else:
                    raise ValueError(
                        f"invalid USERNAME value rejected: {candidate.value!r}")
        drafts, relation_drafts = derive_entity_drafts(
            candidate.type, candidate.value, metadata=candidate.metadata,
            aliases=candidate.aliases)
        primary: Optional[Entity] = None
        primary_is_new = False
        for index, draft in enumerate(drafts):
            entity, is_new = self.resolver.resolve_draft(
                investigation_id, draft, artifact_id=artifact_id, timestamp=timestamp)
            if index == 0:
                primary, primary_is_new = entity, is_new
            # Every node (primary or derived) records this artifact as evidence for
            # its identity claim; upserts are idempotent per (claim, artifact, tool).
            self._identity_claim(investigation_id, entity, artifact_id=artifact_id,
                                 tool_id=tool_id, timestamp=timestamp,
                                 snippet=candidate.evidence or candidate.value,
                                 direct=candidate.direct)
        assert primary is not None
        # Relations implied by derivation (email -> mail domain, subdomain -> parent...)
        for relation_draft in relation_drafts:
            relation = RelationCandidate(
                subject_type=relation_draft.subject_type,
                subject_value=relation_draft.subject_raw,
                predicate=relation_draft.predicate,
                object_type=relation_draft.object_type,
                object_value=relation_draft.object_raw,
                confidence=candidate.confidence,
                evidence=candidate.evidence,
                metadata=relation_draft.metadata,
                direct=candidate.direct,
            )
            self.ingest_relation(investigation_id, relation, artifact_id=artifact_id,
                                 tool_id=tool_id, timestamp=timestamp)
        return primary, primary_is_new

    def ingest_relation(self, investigation_id: str, relation: RelationCandidate, *,
                        artifact_id: str, tool_id: str, timestamp: str) -> bool:
        subject = self._resolve_endpoint(investigation_id, relation.subject_type,
                                         relation.subject_value, artifact_id=artifact_id,
                                         tool_id=tool_id, timestamp=timestamp,
                                         snippet=relation.evidence)
        obj = self._resolve_endpoint(investigation_id, relation.object_type,
                                     relation.object_value, artifact_id=artifact_id,
                                     tool_id=tool_id, timestamp=timestamp,
                                     snippet=relation.evidence)
        if subject is None or obj is None or subject.entity_id == obj.entity_id:
            return False
        before = self.store.count_claims(investigation_id)
        self.store.upsert_claim(
            investigation_id, subject.entity_id, relation.predicate.value,
            object_id=obj.entity_id, artifact_id=artifact_id, source_tool=tool_id,
            timestamp=timestamp, direct=relation.direct,
            snippet=relation.evidence or f"{subject.canonical_value} "
                                         f"{relation.predicate.value} {obj.canonical_value}",
        )
        self._ingest_attributes(investigation_id, obj, _relation_attributes(relation),
                                artifact_id=artifact_id, tool_id=tool_id,
                                timestamp=timestamp)
        return self.store.count_claims(investigation_id) > before

    # ── internals ──────────────────────────────────────────────────

    def _resolve_endpoint(self, investigation_id: str, entity_type: EntityType,
                          value: str, *, artifact_id: str, tool_id: str,
                          timestamp: str, snippet: str = "") -> Optional[Entity]:
        try:
            drafts, _ = derive_entity_drafts(entity_type, value)
        except Exception:  # noqa: BLE001
            return None
        if not drafts:
            return None
        entity, is_new = self.resolver.resolve_draft(
            investigation_id, drafts[0], artifact_id=artifact_id, timestamp=timestamp)
        if is_new:
            self._identity_claim(investigation_id, entity, artifact_id=artifact_id,
                                 tool_id=tool_id, timestamp=timestamp,
                                 snippet=snippet or value, direct=True)
        return entity

    def _identity_claim(self, investigation_id: str, entity: Entity, *,
                        artifact_id: str, tool_id: str, timestamp: str,
                        snippet: str, direct: bool) -> None:
        self.store.upsert_claim(
            investigation_id, entity.entity_id, EdgeType.IDENTIFIED_AS.value,
            object_literal=entity.canonical_value, artifact_id=artifact_id,
            source_tool=tool_id, timestamp=timestamp, direct=direct,
            snippet=snippet or entity.display_value,
        )

    def _ingest_attributes(self, investigation_id: str, entity: Entity,
                           holder, *, artifact_id: str, tool_id: str,
                           timestamp: str) -> int:
        attributes = getattr(holder, "attributes", None) or {}
        created = 0
        for key, value in attributes.items():
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            before = self.store.count_claims(investigation_id)
            self.store.upsert_claim(
                investigation_id, entity.entity_id, f"HAS_ATTRIBUTE:{key}",
                object_literal=value, artifact_id=artifact_id, source_tool=tool_id,
                timestamp=timestamp, direct=getattr(holder, "direct", True),
                snippet=getattr(holder, "evidence", "") or key,
            )
            if self.store.count_claims(investigation_id) > before:
                created += 1
        return created


def _relation_attributes(relation: RelationCandidate) -> EntityCandidate:
    """Wrap relation metadata so it can be stored as object-entity attributes."""
    return EntityCandidate(
        type=relation.object_type, value=relation.object_value,
        confidence=relation.confidence, metadata=relation.metadata,
        evidence=relation.evidence, attributes=dict(relation.metadata),
        direct=relation.direct,
    )


def invocation_hash(tool_id: str, params: dict) -> str:
    """Public helper mirroring the ledger/artifact invocation hash."""
    return param_hash(tool_id, params)


__all__ = ["EvidenceIngestor", "IngestResult", "invocation_hash"]
