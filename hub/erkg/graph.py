"""In-memory graph view over the SQLite ERKG (synced read model).

The SQLite store is the source of truth; ``GraphView`` is rebuilt cheaply per
engine iteration and provides the graph algorithms the pivot engine needs:
neighborhood queries, hop distances from the seed set (scope-explosion guard)
and the "shares a corroborated identifier" test used to exempt far entities
from the hop-distance penalty.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Iterable, Optional

from hub.erkg.store import ERKGStore
from hub.models import (
    Claim,
    Entity,
    EntityType,
    EpistemicStatus,
    SATISFIED_STATUSES,
)

# Predicates that link entities but do not assert identity continuity. They are
# still traversed for hop distance (an association is a legitimate pivot path).
_RELATION_PREDICATES = {
    "OWNS", "RESOLVES_TO", "REGISTERED_BY", "ASSOCIATED_WITH", "COMMITTED_TO",
    "MENTIONED_IN", "SUBDOMAIN_OF", "REGISTERED_ON", "EXPOSED_IN", "HAS_USERNAME",
    "HAS_EMAIL", "HAS_PHONE", "LOCATED_IN", "FOUND_IN",
}
_IDENTIFIER_PREDICATES = {
    "IDENTIFIED_AS", "HAS_EMAIL", "HAS_USERNAME", "HAS_PHONE", "REGISTERED_ON",
    "REGISTERED_BY",
}


class GraphView:
    """Read-only, in-memory view of one investigation's ERKG."""

    def __init__(self, store: ERKGStore, investigation_id: str,
                 seed_entity_ids: Iterable[str] = ()):
        self.store = store
        self.investigation_id = investigation_id
        self.seed_entity_ids: list[str] = list(seed_entity_ids)
        self.entities: dict[str, Entity] = {
            e.entity_id: e for e in store.list_entities(investigation_id)
        }
        self.claims: list[Claim] = store.list_claims(investigation_id)
        self._adjacency: dict[str, set[str]] = {eid: set() for eid in self.entities}
        self._edges: list[Claim] = []
        for claim in self.claims:
            if claim.object_id and claim.object_id in self.entities:
                self._edges.append(claim)
                self._adjacency.setdefault(claim.subject_id, set()).add(claim.object_id)
                self._adjacency.setdefault(claim.object_id, set()).add(claim.subject_id)
        self._hop_cache: Optional[dict[str, int]] = None

    # ── basic accessors ─────────────────────────────────────────────

    def entity(self, entity_id: str) -> Optional[Entity]:
        return self.entities.get(entity_id)

    def neighbors(self, entity_id: str) -> list[str]:
        return sorted(self._adjacency.get(entity_id, set()))

    def get_edges(self) -> list[Claim]:
        return list(self._edges)

    def claims_for(self, entity_id: str) -> list[Claim]:
        return [c for c in self.claims
                if c.subject_id == entity_id or c.object_id == entity_id]

    def subject_claims(self, entity_id: str) -> list[Claim]:
        return [c for c in self.claims if c.subject_id == entity_id]

    def entities_by_type(self) -> dict[str, list[Entity]]:
        grouped: dict[str, list[Entity]] = {}
        for entity in self.entities.values():
            grouped.setdefault(entity.type.value, []).append(entity)
        return grouped

    # ── hop distance (scope explosion guard) ────────────────────────

    def hop_distances(self) -> dict[str, int]:
        """Shortest undirected path length from any seed entity."""
        if self._hop_cache is not None:
            return self._hop_cache
        distances: dict[str, int] = {}
        queue: deque[tuple[str, int]] = deque()
        for seed_id in self.seed_entity_ids:
            if seed_id in self.entities:
                distances[seed_id] = 0
                queue.append((seed_id, 0))
        while queue:
            node_id, depth = queue.popleft()
            for neighbor in self._adjacency.get(node_id, ()):
                if neighbor not in distances:
                    distances[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))
        self._hop_cache = distances
        return distances

    def hop_distance(self, entity_id: str) -> int:
        """Distance from seeds; unknown/disconnected entities are treated as far."""
        return self.hop_distances().get(entity_id, 3)

    # ── corroborated identifier sharing ────────────────────────────

    def _seed_identifier_values(self) -> set[str]:
        """Canonical identifiers corroborated for the seed set."""
        values: set[str] = set()
        seed_set = set(self.seed_entity_ids)
        for seed_id in seed_set:
            entity = self.entities.get(seed_id)
            if entity is None:
                continue
            values.add(entity.canonical_value)
            values.update(alias.strip().lower() for alias in entity.aliases if alias)
        for claim in self.claims:
            if claim.status not in SATISFIED_STATUSES:
                continue
            if claim.subject_id in seed_set or (claim.object_id in seed_set):
                if claim.predicate in _IDENTIFIER_PREDICATES:
                    if claim.object_literal is not None:
                        values.add(str(claim.object_literal).strip().lower())
                    if claim.object_id and claim.object_id in self.entities:
                        peer = self.entities[claim.object_id]
                        values.add(peer.canonical_value)
                        values.update(a.strip().lower() for a in peer.aliases if a)
        return {v for v in values if v}

    def shares_corroborated_identifier(self, entity_id: str) -> bool:
        """True if the entity shares a corroborated identifier with a seed entity."""
        entity = self.entities.get(entity_id)
        if entity is None:
            return False
        seed_values = self._seed_identifier_values()
        if not seed_values:
            return False
        candidates = {entity.canonical_value.lower()}
        candidates.update(a.strip().lower() for a in entity.aliases if a)
        candidates.add(entity.display_value.strip().lower())
        if candidates & seed_values:
            return True
        seed_set = set(self.seed_entity_ids)
        for claim in self.claims:
            if claim.status not in SATISFIED_STATUSES:
                continue
            if claim.subject_id == entity_id and claim.object_id in seed_set:
                return True
            if claim.subject_id in seed_set and claim.object_id == entity_id:
                return True
            if claim.subject_id == entity_id and claim.object_literal is not None:
                if str(claim.object_literal).strip().lower() in seed_values:
                    return True
        return False

    # ── neighborhood / summaries ────────────────────────────────────

    def local_neighborhood(self, entity_id: str, radius: int = 1) -> dict[str, Any]:
        """Bounded neighborhood payload for the LLM correlation stage."""
        if entity_id not in self.entities:
            return {"entity": None, "nodes": [], "edges": []}
        distances = {entity_id: 0}
        frontier = [entity_id]
        for depth in range(1, radius + 1):
            next_frontier: list[str] = []
            for node_id in frontier:
                for neighbor in self._adjacency.get(node_id, ()):
                    if neighbor not in distances:
                        distances[neighbor] = depth
                        next_frontier.append(neighbor)
            frontier = next_frontier
        node_ids = set(distances)
        nodes = [
            {
                **self.entities[nid].summary(),
                "hop": distances[nid],
            }
            for nid in sorted(node_ids, key=lambda n: (distances[n], n))
            if nid in self.entities
        ]
        edges = []
        for claim in self._edges:
            if claim.subject_id in node_ids and claim.object_id in node_ids:
                edges.append({
                    "subject": claim.subject_id,
                    "predicate": claim.predicate,
                    "object": claim.object_id,
                    "status": claim.status.value,
                    "confidence": claim.confidence,
                })
        return {"entity": entity_id, "nodes": nodes[:60], "edges": edges[:120]}

    def summary(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for entity in self.entities.values():
            type_counts[entity.type.value] = type_counts.get(entity.type.value, 0) + 1
        status_counts = self.store.claim_status_counts(self.investigation_id)
        return {
            "total_nodes": len(self.entities),
            "total_edges": len(self._edges),
            "entity_types": type_counts,
            "claim_statuses": status_counts,
            "contradictions": len(self.store.list_contradictions(self.investigation_id)),
            "seed_entities": len(self.seed_entity_ids),
        }

    def unverified_claims(self) -> list[Claim]:
        return [c for c in self.claims
                if c.status in (EpistemicStatus.SINGLE_SOURCE_LEAD,
                                EpistemicStatus.HYPOTHESIS)]

    def satisfied_claims(self) -> list[Claim]:
        return [c for c in self.claims if c.status in SATISFIED_STATUSES]


__all__ = ["GraphView", "EntityType"]
