"""Entity-Resolved Knowledge Graph (ERKG) package.

``ERKGStore`` is the persistent source of truth (SQLite/WAL); ``GraphView`` is
the in-memory algorithmic read model; ``resolution`` canonicalizes and merges
entities; ``confidence`` implements deterministic epistemic scoring.
"""

from hub.erkg.confidence import (
    assess,
    confidence_explanation,
    is_satisfied,
    is_unverified,
    reliability_for_tool,
    status_rank,
)
from hub.erkg.graph import GraphView
from hub.erkg.resolution import (
    EntityDraft,
    EntityResolver,
    RelationDraft,
    canonical_entity_id,
    derive_entity_drafts,
    normalize_value,
    split_hostname,
)
from hub.erkg.store import ERKGStore, default_home

__all__ = [
    "ERKGStore",
    "GraphView",
    "EntityResolver",
    "EntityDraft",
    "RelationDraft",
    "default_home",
    "assess",
    "confidence_explanation",
    "is_satisfied",
    "is_unverified",
    "reliability_for_tool",
    "status_rank",
    "canonical_entity_id",
    "derive_entity_drafts",
    "normalize_value",
    "split_hostname",
]
