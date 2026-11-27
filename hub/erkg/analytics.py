"""Graph analytics, perceptual-hash correlation, timeline & investigation diffing.

All algorithms run in deterministic pure Python (no external graph library
required) on top of :class:`hub.erkg.graph.GraphView` and
:class:`hub.erkg.store.ERKGStore`.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Optional

from hub.erkg.confidence import status_rank
from hub.erkg.graph import GraphView
from hub.erkg.store import ERKGStore
from hub.models import Claim, Entity, EntityType, EpistemicStatus

__all__ = [
    "degree_centrality",
    "betweenness_centrality",
    "connected_components",
    "label_propagation_communities",
    "find_bridges",
    "shortest_path",
    "correlate_perceptual_hashes",
    "build_timeline",
    "diff_investigations",
    "analyze_graph",
]


def _sorted_neighbors(graph: GraphView, node_id: str) -> list[str]:
    return sorted(graph._adjacency.get(node_id, ()))


def degree_centrality(graph: GraphView) -> dict[str, float]:
    """Normalized undirected degree centrality for every entity in ``graph``."""
    nodes = sorted(graph.entities)
    n = len(nodes)
    if n <= 1:
        return {nid: 0.0 for nid in nodes}
    denom = float(n - 1)
    return {
        nid: round(len(graph._adjacency.get(nid, set())) / denom, 6)
        for nid in nodes
    }


def betweenness_centrality(graph: GraphView) -> dict[str, float]:
    """Normalized Brandes (2001) betweenness centrality for undirected ERKG."""
    nodes = sorted(graph.entities)
    n = len(nodes)
    cb: dict[str, float] = {nid: 0.0 for nid in nodes}
    if n <= 2:
        return cb

    adj = {nid: _sorted_neighbors(graph, nid) for nid in nodes}
    for s in nodes:
        stack: list[str] = []
        pred: dict[str, list[str]] = {w: [] for w in nodes}
        sigma: dict[str, int] = {w: 0 for w in nodes}
        sigma[s] = 1
        dist: dict[str, int] = {w: -1 for w in nodes}
        dist[s] = 0
        queue: deque[str] = deque([s])

        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in adj.get(v, ()):
                if dist[w] < 0:
                    queue.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        delta: dict[str, float] = {w: 0.0 for w in nodes}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                cb[w] += delta[w]

    # Undirected normalization: Brandes accumulates each pair twice (s->t and t->s).
    scale = 1.0 / ((n - 1) * (n - 2))
    return {nid: round(cb[nid] * scale, 6) for nid in nodes}


def connected_components(graph: GraphView) -> list[list[str]]:
    """Deterministic undirected connected components, largest first."""
    visited: set[str] = set()
    components: list[list[str]] = []
    for start in sorted(graph.entities):
        if start in visited:
            continue
        comp: list[str] = []
        queue: deque[str] = deque([start])
        visited.add(start)
        while queue:
            cur = queue.popleft()
            comp.append(cur)
            for nxt in _sorted_neighbors(graph, cur):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        components.append(sorted(comp))
    components.sort(key=lambda c: (-len(c), c[0] if c else ""))
    return components


def label_propagation_communities(
    graph: GraphView, *, max_iter: int = 30
) -> list[list[str]]:
    """Deterministic label-propagation community detection on the ERKG."""
    nodes = sorted(graph.entities)
    if not nodes:
        return []
    labels: dict[str, str] = {nid: nid for nid in nodes}
    for _ in range(max_iter):
        changed = False
        for nid in nodes:
            neighbors = _sorted_neighbors(graph, nid)
            if not neighbors:
                continue
            counts: dict[str, int] = {}
            for nb in neighbors:
                lbl = labels[nb]
                counts[lbl] = counts.get(lbl, 0) + 1
            best_label = min(counts.items(), key=lambda item: (-item[1], item[0]))[0]
            if best_label != labels[nid]:
                labels[nid] = best_label
                changed = True
        if not changed:
            break

    groups: dict[str, list[str]] = {}
    for nid, lbl in labels.items():
        groups.setdefault(lbl, []).append(nid)
    communities = [sorted(members) for members in groups.values()]
    communities.sort(key=lambda c: (-len(c), c[0] if c else ""))
    return communities


def find_bridges(
    graph: GraphView, *, communities: Optional[list[list[str]]] = None
) -> dict[str, Any]:
    """Identify Tarjan bridge edges, articulation points and cross-cluster bridges."""
    nodes = sorted(graph.entities)
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    timer = 0
    bridge_pairs: list[tuple[str, str]] = []
    articulation: set[str] = set()

    def _dfs(root: str) -> None:
        nonlocal timer
        # Iterative Tarjan to avoid recursion limit on large graphs.
        parent: dict[str, Optional[str]] = {root: None}
        child_count: dict[str, int] = {root: 0}
        neighbors_iter: dict[str, list[str]] = {}
        idx: dict[str, int] = {}

        disc[root] = low[root] = timer
        timer += 1
        neighbors_iter[root] = _sorted_neighbors(graph, root)
        idx[root] = 0
        stack: list[str] = [root]

        while stack:
            u = stack[-1]
            nbrs = neighbors_iter[u]
            if idx[u] < len(nbrs):
                v = nbrs[idx[u]]
                idx[u] += 1
                if v not in disc:
                    parent[v] = u
                    child_count[u] = child_count.get(u, 0) + 1
                    child_count[v] = 0
                    disc[v] = low[v] = timer
                    timer += 1
                    neighbors_iter[v] = _sorted_neighbors(graph, v)
                    idx[v] = 0
                    stack.append(v)
                elif v != parent[u]:
                    if disc[v] < low[u]:
                        low[u] = disc[v]
            else:
                stack.pop()
                p = parent[u]
                if p is not None:
                    if low[u] < low[p]:
                        low[p] = low[u]
                    if low[u] > disc[p]:
                        a, b = (p, u) if p < u else (u, p)
                        bridge_pairs.append((a, b))
                    if parent[p] is not None and low[u] >= disc[p]:
                        articulation.add(p)
                else:
                    if child_count.get(u, 0) > 1:
                        articulation.add(u)

    for node in nodes:
        if node not in disc:
            _dfs(node)

    bridge_edges: list[dict[str, Any]] = []
    for u, v in sorted(set(bridge_pairs)):
        claims = graph.edge_claims_between(u, v)
        bridge_edges.append({
            "source": u,
            "target": v,
            "claims": [
                {
                    "claim_id": c.claim_id,
                    "predicate": c.predicate,
                    "status": c.status.value,
                    "artifact_ids": list(c.artifact_ids),
                }
                for c in claims
            ],
        })

    # Include cross-community connectors alongside articulation points.
    node_cluster: dict[str, int] = {}
    if communities is None:
        communities = label_propagation_communities(graph)
    for idx_c, members in enumerate(communities):
        for m in members:
            node_cluster[m] = idx_c
    cross_cluster: set[str] = set()
    for claim in graph.get_edges():
        if claim.object_id and node_cluster.get(claim.subject_id) != node_cluster.get(claim.object_id):
            cross_cluster.add(claim.subject_id)
            cross_cluster.add(claim.object_id)

    bridge_entities = sorted(articulation | cross_cluster)
    return {
        "bridge_entities": bridge_entities,
        "articulation_points": sorted(articulation),
        "bridge_edges": bridge_edges,
    }


def _best_edge_claim(claims: list[Claim]) -> Optional[Claim]:
    if not claims:
        return None
    return max(
        claims,
        key=lambda c: (status_rank(c.status), c.confidence, len(c.artifact_ids), c.claim_id),
    )


def shortest_path(graph: GraphView, source_id: str, dest_id: str) -> dict[str, Any]:
    """Find shortest undirected path between two entity IDs with edge provenance."""
    if source_id not in graph.entities or dest_id not in graph.entities:
        return {
            "found": False,
            "source_id": source_id,
            "dest_id": dest_id,
            "length": None,
            "path": [],
            "nodes": [],
            "edges": [],
        }
    if source_id == dest_id:
        ent = graph.entities[source_id]
        return {
            "found": True,
            "source_id": source_id,
            "dest_id": dest_id,
            "length": 0,
            "path": [source_id],
            "nodes": [ent.summary()],
            "edges": [],
        }

    parent: dict[str, Optional[str]] = {source_id: None}
    queue: deque[str] = deque([source_id])
    found = False
    while queue and not found:
        cur = queue.popleft()
        for nxt in _sorted_neighbors(graph, cur):
            if nxt not in parent:
                parent[nxt] = cur
                if nxt == dest_id:
                    found = True
                    break
                queue.append(nxt)

    if not found:
        return {
            "found": False,
            "source_id": source_id,
            "dest_id": dest_id,
            "length": None,
            "path": [],
            "nodes": [],
            "edges": [],
        }

    path: list[str] = []
    cur_node: Optional[str] = dest_id
    while cur_node is not None:
        path.append(cur_node)
        cur_node = parent[cur_node]
    path.reverse()

    nodes = [graph.entities[nid].summary() for nid in path if nid in graph.entities]
    edges: list[dict[str, Any]] = []
    for u, v in zip(path, path[1:]):
        claims = graph.edge_claims_between(u, v)
        best = _best_edge_claim(claims)
        if best is not None:
            edges.append({
                "from": u,
                "to": v,
                "claim_id": best.claim_id,
                "subject_id": best.subject_id,
                "object_id": best.object_id,
                "predicate": best.predicate,
                "status": best.status.value,
                "confidence": best.confidence,
                "artifact_ids": list(best.artifact_ids),
                "all_claims": [
                    {
                        "claim_id": c.claim_id,
                        "predicate": c.predicate,
                        "status": c.status.value,
                        "artifact_ids": list(c.artifact_ids),
                    }
                    for c in claims
                ],
            })
        else:
            edges.append({
                "from": u,
                "to": v,
                "claim_id": "",
                "subject_id": u,
                "object_id": v,
                "predicate": "ASSOCIATED_WITH",
                "status": EpistemicStatus.HYPOTHESIS.value,
                "confidence": 0.0,
                "artifact_ids": [],
                "all_claims": [],
            })

    return {
        "found": True,
        "source_id": source_id,
        "dest_id": dest_id,
        "length": len(edges),
        "path": path,
        "nodes": nodes,
        "edges": edges,
    }


def _parse_hex64(value: Any) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip().lower()
    for prefix in ("phash:", "dhash:", "0x"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if not text or len(text) > 16:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _parse_mmh3(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower().startswith("mmh3:"):
        text = text[5:].strip()
    if not text:
        return None
    try:
        return str(int(text))
    except ValueError:
        return None


def _entity_hash_signals(graph: GraphView) -> dict[str, dict[str, Any]]:
    """Collect phash, dhash, and mmh3 values attached to each entity."""
    signals: dict[str, dict[str, Any]] = {}

    def _put(eid: str, kind: str, raw_val: Any) -> None:
        if eid not in graph.entities:
            return
        bucket = signals.setdefault(eid, {})
        if kind in ("phash", "dhash"):
            parsed = _parse_hex64(raw_val)
            if parsed is not None:
                bucket[kind] = (parsed, f"{parsed:016x}")
        elif kind == "mmh3":
            parsed = _parse_mmh3(raw_val)
            if parsed is not None:
                bucket[kind] = parsed

    for eid, entity in graph.entities.items():
        meta = entity.metadata or {}
        for kind in ("phash", "dhash", "mmh3"):
            if kind in meta and meta[kind] is not None:
                _put(eid, kind, meta[kind])
        if entity.type == EntityType.HASH:
            val = entity.canonical_value
            if val.startswith("mmh3:"):
                _put(eid, "mmh3", val)
            elif val.startswith("phash:"):
                _put(eid, "phash", val)
            elif val.startswith("dhash:"):
                _put(eid, "dhash", val)
            else:
                hash_kind = str(meta.get("hash_kind") or meta.get("kind") or "").lower()
                if hash_kind in ("phash", "dhash", "mmh3"):
                    _put(eid, hash_kind, val)

    for claim in graph.claims:
        if claim.predicate.startswith("HAS_ATTRIBUTE:") and claim.object_literal is not None:
            attr_key = claim.predicate.split(":", 1)[1].strip().lower()
            if attr_key in ("phash", "dhash", "mmh3"):
                _put(claim.subject_id, attr_key, claim.object_literal)

    return signals


def correlate_perceptual_hashes(
    graph: GraphView, *, max_hamming: int = 6
) -> list[dict[str, Any]]:
    """Group entities sharing identical mmh3 or <= ``max_hamming`` pHash/dHash."""
    signals = _entity_hash_signals(graph)
    eids = sorted(signals)
    if len(eids) < 2:
        return []

    parent = {eid: eid for eid in eids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            if ra < rb:
                parent[rb] = ra
            else:
                parent[ra] = rb

    pair_matches: list[dict[str, Any]] = []
    for i in range(len(eids)):
        for j in range(i + 1, len(eids)):
            a, b = eids[i], eids[j]
            sa, sb = signals[a], signals[b]
            matched_reasons: list[dict[str, Any]] = []

            if "mmh3" in sa and "mmh3" in sb and sa["mmh3"] == sb["mmh3"]:
                matched_reasons.append({
                    "kind": "mmh3",
                    "distance": 0,
                    "value": sa["mmh3"],
                })
            for kind in ("phash", "dhash"):
                if kind in sa and kind in sb:
                    int_a, hex_a = sa[kind]
                    int_b, hex_b = sb[kind]
                    dist = (int_a ^ int_b).bit_count()
                    if dist <= max_hamming:
                        matched_reasons.append({
                            "kind": kind,
                            "distance": dist,
                            "values": [hex_a, hex_b],
                        })
            if matched_reasons:
                union(a, b)
                pair_matches.append({
                    "entity_a": a,
                    "entity_b": b,
                    "reasons": matched_reasons,
                })

    clusters_map: dict[str, list[str]] = {}
    for eid in eids:
        clusters_map.setdefault(find(eid), []).append(eid)

    clusters: list[dict[str, Any]] = []
    for root in sorted(clusters_map):
        members = sorted(clusters_map[root])
        if len(members) < 2:
            continue
        member_set = set(members)
        matches = [
            m for m in pair_matches
            if m["entity_a"] in member_set and m["entity_b"] in member_set
        ]
        kinds = sorted({r["kind"] for m in matches for r in m["reasons"]})
        max_dist = max(
            (r["distance"] for m in matches for r in m["reasons"]), default=0
        )
        clusters.append({
            "cluster_id": f"hcluster_{root}",
            "hash_kinds": kinds,
            "max_distance": max_dist,
            "entity_ids": members,
            "entities": [graph.entities[eid].summary() for eid in members],
            "matches": matches,
        })
    clusters.sort(key=lambda c: (-len(c["entity_ids"]), c["cluster_id"]))
    return clusters


def build_timeline(store: ERKGStore, target_id: str) -> list[dict[str, Any]]:
    """Build a chronological timeline of events for one investigation."""
    events: list[dict[str, Any]] = []
    investigation = store.get_investigation(target_id)
    if investigation is None:
        return events

    events.append({
        "timestamp_utc": investigation.created_at,
        "event_type": "seed_intake",
        "title": "Investigation initialized",
        "detail": investigation.raw_input[:240],
        "target_id": target_id,
        "entity_ids": list(investigation.seed_entity_ids),
    })

    for artifact in store.list_artifacts(target_id):
        events.append({
            "timestamp_utc": artifact.timestamp_utc,
            "event_type": "artifact",
            "title": f"Artifact from {artifact.source_tool}",
            "detail": artifact.raw_evidence_snippet[:240],
            "artifact_id": artifact.artifact_id,
            "source_tool": artifact.source_tool,
            "epistemic_status": artifact.epistemic_status.value,
            "confidence": artifact.confidence,
        })

    for rec in store.list_ledger(target_id):
        events.append({
            "timestamp_utc": rec.run_at,
            "event_type": "ledger_run",
            "title": f"{rec.tool_id} ({rec.status.value})",
            "detail": rec.error_message[:200] if rec.error_message else f"duration={rec.duration_ms}ms",
            "tool_id": rec.tool_id,
            "entity_id": rec.entity_id,
            "status": rec.status.value,
            "error_code": rec.error_code.value if rec.error_code else None,
            "artifact_id": rec.artifact_id,
            "duration_ms": rec.duration_ms,
        })

    for entity in store.list_entities(target_id):
        events.append({
            "timestamp_utc": entity.first_seen,
            "event_type": "entity_discovered",
            "title": f"Discovered {entity.type.value}: {entity.canonical_value}",
            "detail": entity.display_value,
            "entity_id": entity.entity_id,
            "entity_type": entity.type.value,
            "canonical_value": entity.canonical_value,
            "created_by_artifact": entity.created_by_artifact,
        })

    for con in store.list_contradictions(target_id):
        events.append({
            "timestamp_utc": con.created_at,
            "event_type": "contradiction",
            "title": f"Contradiction on {con.predicate}",
            "detail": f"claims {con.claim_a} vs {con.claim_b}",
            "contradiction_id": con.contradiction_id,
            "subject_id": con.subject_id,
            "predicate": con.predicate,
            "claim_a": con.claim_a,
            "claim_b": con.claim_b,
            "resolved": con.resolved,
        })

    for ins in store.list_ai_insights(target_id):
        events.append({
            "timestamp_utc": ins["created_at"],
            "event_type": "ai_insight",
            "title": f"AI insight ({ins['provider']}/{ins['kind']})",
            "detail": ins["summary"][:240],
            "insight_id": ins["insight_id"],
            "provider": ins["provider"],
            "model": ins["model"],
            "kind": ins["kind"],
            "epistemic_provenance": ins["epistemic_provenance"],
            "cited_artifact_ids": ins["cited_artifact_ids"],
        })

    order_map = {
        "seed_intake": 0,
        "ledger_run": 1,
        "artifact": 2,
        "entity_discovered": 3,
        "contradiction": 4,
        "ai_insight": 5,
    }
    events.sort(
        key=lambda ev: (
            str(ev.get("timestamp_utc") or ""),
            order_map.get(ev.get("event_type", ""), 99),
            str(ev.get("title") or ""),
        )
    )
    return events


def _entity_best_status(claims: list[Claim]) -> dict[str, tuple[EpistemicStatus, float]]:
    best: dict[str, tuple[EpistemicStatus, float]] = {}
    for c in claims:
        cur = best.get(c.subject_id)
        if cur is None or (status_rank(c.status), c.confidence) > (status_rank(cur[0]), cur[1]):
            best[c.subject_id] = (c.status, c.confidence)
    return best


def diff_investigations(
    store_a: ERKGStore, id_a: str, store_b: ERKGStore, id_b: str
) -> dict[str, Any]:
    """Compare two investigations (``id_a`` baseline vs ``id_b`` target)."""
    entities_a = store_a.list_entities(id_a)
    entities_b = store_b.list_entities(id_b)
    claims_a = store_a.list_claims(id_a)
    claims_b = store_b.list_claims(id_b)
    cons_a = store_a.list_contradictions(id_a)
    cons_b = store_b.list_contradictions(id_b)

    map_a: dict[str, Entity] = {e.key: e for e in entities_a}
    map_b: dict[str, Entity] = {e.key: e for e in entities_b}
    id_to_key_a = {e.entity_id: e.key for e in entities_a}
    id_to_key_b = {e.entity_id: e.key for e in entities_b}

    keys_a = set(map_a)
    keys_b = set(map_b)

    added_entities = [
        map_b[k].summary() for k in sorted(keys_b - keys_a)
    ]
    removed_entities = [
        map_a[k].summary() for k in sorted(keys_a - keys_b)
    ]

    best_a = _entity_best_status(claims_a)
    best_b = _entity_best_status(claims_b)
    status_changes: list[dict[str, Any]] = []
    for key in sorted(keys_a & keys_b):
        ent_a = map_a[key]
        ent_b = map_b[key]
        st_a = best_a.get(ent_a.entity_id)
        st_b = best_b.get(ent_b.entity_id)
        if st_a is None or st_b is None:
            continue
        if st_a[0] != st_b[0]:
            status_changes.append({
                "key": key,
                "type": ent_b.type.value,
                "canonical_value": ent_b.canonical_value,
                "entity_id_a": ent_a.entity_id,
                "entity_id_b": ent_b.entity_id,
                "old_status": st_a[0].value,
                "new_status": st_b[0].value,
                "old_confidence": st_a[1],
                "new_confidence": st_b[1],
            })

    con_sig_a = {
        (id_to_key_a.get(c.subject_id, c.subject_id), c.predicate): c
        for c in cons_a
    }
    con_sig_b = {
        (id_to_key_b.get(c.subject_id, c.subject_id), c.predicate): c
        for c in cons_b
    }
    new_contradictions = [
        {
            "contradiction_id": c.contradiction_id,
            "subject_key": sig[0],
            "subject_id": c.subject_id,
            "predicate": c.predicate,
            "claim_a": c.claim_a,
            "claim_b": c.claim_b,
            "created_at": c.created_at,
        }
        for sig, c in sorted(con_sig_b.items())
        if sig not in con_sig_a
    ]
    resolved_contradictions = [
        {
            "contradiction_id": c.contradiction_id,
            "subject_key": sig[0],
            "subject_id": c.subject_id,
            "predicate": c.predicate,
        }
        for sig, c in sorted(con_sig_a.items())
        if sig not in con_sig_b or (con_sig_b[sig].resolved and not c.resolved)
    ]

    return {
        "target_id_a": id_a,
        "target_id_b": id_b,
        "added_entities": added_entities,
        "removed_entities": removed_entities,
        "status_changes": status_changes,
        "new_contradictions": new_contradictions,
        "resolved_contradictions": resolved_contradictions,
        "summary": {
            "entities_a": len(entities_a),
            "entities_b": len(entities_b),
            "common_entities": len(keys_a & keys_b),
            "added_count": len(added_entities),
            "removed_count": len(removed_entities),
            "status_change_count": len(status_changes),
            "new_contradictions_count": len(new_contradictions),
            "resolved_contradictions_count": len(resolved_contradictions),
        },
    }


def analyze_graph(
    graph: GraphView,
    *,
    source_id: Optional[str] = None,
    dest_id: Optional[str] = None,
) -> dict[str, Any]:
    """Run full ERKG analytics suite on ``graph``."""
    deg = degree_centrality(graph)
    betw = betweenness_centrality(graph)
    components = connected_components(graph)
    communities = label_propagation_communities(graph)
    bridges = find_bridges(graph, communities=communities)
    hash_clusters = correlate_perceptual_hashes(graph)

    top_central = sorted(
        graph.entities,
        key=lambda eid: (-betw.get(eid, 0.0), -deg.get(eid, 0.0), eid),
    )[:15]
    top_central_entities = [
        {
            **graph.entities[eid].summary(),
            "degree_centrality": deg.get(eid, 0.0),
            "betweenness_centrality": betw.get(eid, 0.0),
            "degree": len(graph._adjacency.get(eid, set())),
        }
        for eid in top_central
    ]

    path_result = (
        shortest_path(graph, source_id, dest_id)
        if source_id and dest_id
        else None
    )

    return {
        "target_id": graph.investigation_id,
        "node_count": len(graph.entities),
        "edge_count": len(graph.get_edges()),
        "degree_centrality": deg,
        "betweenness_centrality": betw,
        "top_central_entities": top_central_entities,
        "connected_components": components,
        "communities": communities,
        "clusters": communities,
        "bridge_entities": bridges["bridge_entities"],
        "articulation_points": bridges["articulation_points"],
        "bridge_edges": bridges["bridge_edges"],
        "perceptual_hash_clusters": hash_clusters,
        "shortest_path": path_result,
        "summary": {
            "nodes": len(graph.entities),
            "edges": len(graph.get_edges()),
            "components": len(components),
            "communities": len(communities),
            "bridge_entities": len(bridges["bridge_entities"]),
            "bridge_edges": len(bridges["bridge_edges"]),
            "perceptual_hash_clusters": len(hash_clusters),
        },
    }
