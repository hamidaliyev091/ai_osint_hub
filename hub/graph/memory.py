"""Lightweight exposure graph — dict-based adjacency.

Node types: person, email, username, domain, ip, phone, service, breach, credential
Edge types: HAS_USERNAME, HAS_EMAIL, REGISTERED_ON, EXPOSED_IN, LINKED_TO,
            RESOLVES_TO, RELATED_TO, INFERRED_FROM

No NetworkX. Plain Python dicts. JSON serializable.
"""

from dataclasses import dataclass, field
from typing import Optional
import hashlib
import json


# ── Origin Priority ────────────────────────────────────────

_ORIGIN_PRIORITY = {"raw_input": 3, "tool": 2, "hypothesis_expansion": 1}


def _merge_metadata_preserve_origin(existing: dict, incoming: dict):
    """Merge metadata dicts, preserving the highest-priority origin.

    raw_input (3) > tool (2) > hypothesis_expansion (1).
    A hypothesis expansion must never overwrite a raw_input origin.
    """
    existing_origin = existing.get("origin", "")
    incoming_origin = incoming.get("origin", "")

    if existing_origin and incoming_origin:
        existing_priority = _ORIGIN_PRIORITY.get(existing_origin, 0)
        incoming_priority = _ORIGIN_PRIORITY.get(incoming_origin, 0)
        if incoming_priority > existing_priority:
            existing.update(incoming)
        else:
            # Merge everything EXCEPT origin (keep existing higher-priority origin)
            safe = {k: v for k, v in incoming.items() if k != "origin"}
            existing.update(safe)
    else:
        existing.update(incoming)


# ── Node / Edge Models ─────────────────────────────────────

@dataclass
class Node:
    node_id: str
    type: str                       # person, email, username, domain, ip, service, etc.
    value: str                      # Canonical value (lowercase email, stripped URL, etc.)
    confidence: float = 0.5         # 0.0–1.0
    sources: list[str] = field(default_factory=list)   # Where this came from
    first_seen: str = ""            # ISO timestamp
    last_seen: str = ""             # ISO timestamp
    metadata: dict = field(default_factory=dict)        # Tool-specific extras

    @staticmethod
    def make_id(type_: str, value: str) -> str:
        """Generate deterministic node_id from type + value."""
        return f"{type_}:{value.lower().strip()}"


@dataclass
class Edge:
    source: str                     # node_id
    target: str                     # node_id
    type: str                       # HAS_USERNAME, REGISTERED_ON, etc.
    confidence: float = 0.5
    source_tool: str = ""           # Which tool discovered this relationship
    metadata: dict = field(default_factory=dict)


# ── Exposure Graph ─────────────────────────────────────────

class ExposureGraph:
    """Dict-based adjacency graph for tracking discovered entities and relationships."""

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adjacency: dict[str, list[str]] = {}  # node_id → [neighbor node_ids]

    # ── Node Operations ────────────────────────────────

    def add_node(self, type_: str, value: str, confidence: float = 0.5,
                 source: str = "", metadata: dict = None,
                 timestamp: str = "") -> tuple[str, bool]:
        """Add a node. Deduplicates by type+value.

        Returns (node_id, is_new) where is_new is True if this node
        was actually created (not just updated).
        """
        node_id = Node.make_id(type_, value)
        if node_id in self.nodes:
            existing = self.nodes[node_id]
            existing.confidence = max(existing.confidence, confidence)
            if source and source not in existing.sources:
                existing.sources.append(source)
            if timestamp:
                existing.last_seen = timestamp
            if metadata:
                # Merge metadata but preserve the highest-priority origin.
                # Priority: raw_input > tool > hypothesis_expansion.
                # A hypothesis expansion must never downgrade a raw_input origin.
                _merge_metadata_preserve_origin(existing.metadata, metadata)
            return node_id, False

        self.nodes[node_id] = Node(
            node_id=node_id,
            type=type_,
            value=value.lower().strip() if isinstance(value, str) else str(value),
            confidence=confidence,
            sources=[source] if source else [],
            first_seen=timestamp,
            last_seen=timestamp,
            metadata=metadata or {},
        )
        self._adjacency[node_id] = []
        return node_id, True

    def get_node(self, node_id: str) -> Optional[Node]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def query(self, type_: str, value: str) -> Optional[str]:
        """Find a node by type+value. Returns node_id or None."""
        node_id = Node.make_id(type_, value)
        return node_id if node_id in self.nodes else None

    def get_nodes_by_type(self, type_: str) -> list[Node]:
        """Get all nodes of a given type."""
        return [n for n in self.nodes.values() if n.type == type_]

    # ── Edge Operations ────────────────────────────────

    def add_edge(self, source: str, target: str, type_: str,
                 confidence: float = 0.5, source_tool: str = "",
                 metadata: dict = None):
        """Add a directed relationship between two nodes.

        Deduplicates: if an edge with same (source, target, type) exists, skips.
        """
        # Ensure both nodes exist
        if source not in self.nodes or target not in self.nodes:
            return

        # Dedup
        for e in self.edges:
            if e.source == source and e.target == target and e.type == type_:
                e.confidence = max(e.confidence, confidence)
                return

        edge = Edge(
            source=source,
            target=target,
            type=type_,
            confidence=confidence,
            source_tool=source_tool,
            metadata=metadata or {},
        )
        self.edges.append(edge)

        # Update adjacency
        if source in self._adjacency:
            if target not in self._adjacency[source]:
                self._adjacency[source].append(target)
        if target in self._adjacency:
            if source not in self._adjacency[target]:
                self._adjacency[target].append(source)

    def get_neighbors(self, node_id: str) -> list[str]:
        """Get all neighbor node_ids."""
        return self._adjacency.get(node_id, [])

    def count_unexplored_neighbors(self, node_id: str) -> int:
        """Count neighbors with confidence < 0.7 (unverified)."""
        count = 0
        for nid in self.get_neighbors(node_id):
            node = self.nodes.get(nid)
            if node and node.confidence < 0.7:
                count += 1
        return count

    # ── Graph-Wide Queries ─────────────────────────────

    def entity_types_present(self) -> set[str]:
        """Return set of entity types currently in the graph."""
        return {n.type for n in self.nodes.values()}

    def entities_with_low_confidence(self, threshold: float = 0.7) -> list[Node]:
        """Return nodes with confidence below threshold."""
        return [n for n in self.nodes.values() if n.confidence < threshold]

    def entities_with_high_confidence(self, threshold: float = 0.9) -> list[Node]:
        """Return nodes with confidence at or above threshold."""
        return [n for n in self.nodes.values() if n.confidence >= threshold]

    def is_fully_investigated(self, node_id: str) -> bool:
        """Check if a node has been thoroughly investigated.

        Heuristic: confidence > 0.95 AND has edges AND neighbors are all high-confidence.
        """
        node = self.nodes.get(node_id)
        if not node or node.confidence <= 0.95:
            return False
        neighbors = self.get_neighbors(node_id)
        if not neighbors:
            return False
        return all(
            self.nodes[n].confidence >= 0.9
            for n in neighbors if n in self.nodes
        )

    # ── Serialization ──────────────────────────────────

    def summary(self) -> dict:
        """Compact summary for AI context inclusion (~2KB target)."""
        type_counts = {}
        for n in self.nodes.values():
            type_counts[n.type] = type_counts.get(n.type, 0) + 1
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "entity_types": type_counts,
            "confidence_distribution": {
                "high": len(self.entities_with_high_confidence(0.9)),
                "medium": len([n for n in self.nodes.values() if 0.5 <= n.confidence < 0.9]),
                "low": len([n for n in self.nodes.values() if n.confidence < 0.5]),
            },
        }

    def to_dict(self) -> dict:
        """Full serialization for state persistence."""
        return {
            "nodes": {
                nid: {
                    "node_id": n.node_id,
                    "type": n.type,
                    "value": n.value,
                    "confidence": n.confidence,
                    "sources": n.sources,
                    "first_seen": n.first_seen,
                    "last_seen": n.last_seen,
                    "metadata": n.metadata,
                }
                for nid, n in self.nodes.items()
            },
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.type,
                    "confidence": e.confidence,
                    "source_tool": e.source_tool,
                    "metadata": e.metadata,
                }
                for e in self.edges
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ExposureGraph":
        """Deserialize from to_dict() output."""
        g = cls()
        for nid, ndata in data.get("nodes", {}).items():
            node = Node(
                node_id=ndata["node_id"],
                type=ndata["type"],
                value=ndata["value"],
                confidence=ndata.get("confidence", 0.5),
                sources=ndata.get("sources", []),
                first_seen=ndata.get("first_seen", ""),
                last_seen=ndata.get("last_seen", ""),
                metadata=ndata.get("metadata", {}),
            )
            g.nodes[nid] = node
            g._adjacency[nid] = []
        for edata in data.get("edges", []):
            g.add_edge(
                source=edata["source"],
                target=edata["target"],
                type_=edata["type"],
                confidence=edata.get("confidence", 0.5),
                source_tool=edata.get("source_tool", ""),
                metadata=edata.get("metadata", {}),
            )
        return g


# ── Entity Ingestion (Relationship Dispatch) ──────────────

def ingest_entity(graph: ExposureGraph, entity: dict, source_params: dict,
                  tool_name: str, timestamp: str) -> tuple[str, bool]:
    """Ingest a cooked entity into the graph with correct relationships.

    Returns (node_id, is_new) where is_new is True if the entity was
    actually created (not a duplicate of an existing node).
    """
    etype = entity["type"]
    evalue = entity["value"]
    conf = entity.get("confidence", 0.7)
    src = entity.get("sources", [f"{tool_name}"])[0]

    # Merge origin: tool-discovered entities are marked "tool".
    # Preserve any existing metadata from the parser.
    merged_metadata = {**entity.get("metadata", {}), "origin": "tool"}

    nid, is_new = graph.add_node(etype, evalue, confidence=conf,
                                  source=src, metadata=merged_metadata,
                                  timestamp=timestamp)

    # Dispatch relationships by entity type
    if etype == "service":
        for param_val in source_params.values():
            targets = [param_val] if not isinstance(param_val, list) else param_val
            for tv in targets:
                target_nid = graph.query("email", str(tv)) or graph.query("username", str(tv))
                if target_nid:
                    link_email_to_service(graph, target_nid, nid,
                                         confidence=conf, source_tool=tool_name)

    elif etype == "breach":
        for param_val in source_params.values():
            targets = [param_val] if not isinstance(param_val, list) else param_val
            for tv in targets:
                target_nid = graph.query("email", str(tv))
                if target_nid:
                    link_email_to_breach(graph, target_nid, nid,
                                        confidence=conf, source_tool=tool_name)

    return nid, is_new


# ── Relationship Helpers ───────────────────────────────────

def link_person_to_username(graph: ExposureGraph, person_node_id: str,
                            username_node_id: str, confidence: float = 0.7,
                            source_tool: str = ""):
    """Convenience: link a person to their username."""
    graph.add_edge(person_node_id, username_node_id, "HAS_USERNAME",
                   confidence=confidence, source_tool=source_tool)


def link_email_to_service(graph: ExposureGraph, email_node_id: str,
                          service_node_id: str, confidence: float = 0.9,
                          source_tool: str = ""):
    """Convenience: link an email to a service it's registered on."""
    graph.add_edge(email_node_id, service_node_id, "REGISTERED_ON",
                   confidence=confidence, source_tool=source_tool)


def link_email_to_breach(graph: ExposureGraph, email_node_id: str,
                         breach_node_id: str, confidence: float = 0.9,
                         source_tool: str = ""):
    """Convenience: link an email to a breach it was found in."""
    graph.add_edge(email_node_id, breach_node_id, "EXPOSED_IN",
                   confidence=confidence, source_tool=source_tool)


def link_username_to_email(graph: ExposureGraph, username_node_id: str,
                           email_node_id: str, confidence: float = 0.6,
                           source_tool: str = ""):
    """Convenience: link a username to an inferred/confirmed email."""
    graph.add_edge(username_node_id, email_node_id, "LINKED_TO",
                   confidence=confidence, source_tool=source_tool)
