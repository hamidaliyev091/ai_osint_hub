"""Candidate action generation with context-sensitive scoring and top-k pruning.

Given a graph state + investigation history, generates all possible next actions,
scores them dynamically, and returns a pruned top-k list with diversity guarantees.
"""

from dataclasses import dataclass, field
from typing import Optional
from hub.registry import (
    get_tool, for_entity, get_tool_class_weight, is_dangerous, is_active
)
from hub.graph.memory import ExposureGraph


@dataclass
class CandidateScore:
    total: float
    base_weight: float
    confidence_multiplier: float
    unexplored_bonus: float
    redundancy_penalty: float
    cost_factor: float


@dataclass
class CandidateAction:
    action_id: str
    tool: str
    params: dict
    entity_target: str
    entity_type: str
    entity_confidence: float
    expected_yield: str
    score: CandidateScore
    tool_cost: dict
    dangerous: bool
    active: bool
    rationale: str = ""


def generate_candidates(graph: ExposureGraph, history: list[dict],
                         top_k: int = 15, min_tool_classes: int = 3,
                         allow_dangerous: bool = False) -> list[CandidateAction]:
    """Generate, score, and prune candidate actions from current graph state.

    Returns at most top_k candidates with at least min_tool_classes represented.

    Note (P2-10): Candidate action_ids are regenerated each turn. The AI MUST
    call --status immediately before --step to get fresh action_ids. A stale
    action_id from a previous --status call may resolve to a different tool
    if another process stepped between calls. The P0-7 file lock prevents
    concurrent steps within the same process, but the TOCTOU window between
    --status and --step remains if multiple MCP/CLI clients share an investigation.
    """
    raw = _generate_all(graph, allow_dangerous)

    # Stage 1: FILTER — remove no-value candidates
    filtered = _filter_no_value(raw, graph, history)

    # Stage 2: GROUP — collapse similar entities
    grouped = _group_similar(filtered)

    # Stage 3: SCORE — context-sensitive dynamic scoring
    scored = [_score(c, graph, history) for c in grouped]
    scored.sort(key=lambda c: c.score.total, reverse=True)

    # Stage 4: TOP-K DIVERSE — ensure tool class diversity
    result = _top_k_diverse(scored, top_k, min_tool_classes)

    # Assign stable, unique action_ids after pruning
    for i, c in enumerate(result):
        c.action_id = f"act_{i:03d}"

    return result


# ── Stage 1: Generate All Candidates ──────────────────────

def _generate_all(graph: ExposureGraph, allow_dangerous: bool = False) -> list[dict]:
    """Generate raw candidates for every entity in the graph.

    Each entity type maps to the tools that accept it via registry.for_entity().
    """
    raw = []
    seen_actions = set()

    for node_id, node in graph.nodes.items():
        tools = for_entity(node.type)
        for tool_name in tools:
            meta = get_tool(tool_name)
            if meta is None:
                continue
            if meta.dangerous and not allow_dangerous:
                continue

            # Build params based on entity type and tool's param schema
            params = _build_params(tool_name, node)
            if params is None:
                continue

            # Dedup key: same tool + same entity value
            dedup_key = f"{tool_name}:{node.type}:{node.value}"
            if dedup_key in seen_actions:
                continue
            seen_actions.add(dedup_key)

            raw.append({
                "tool": tool_name,
                "params": params,
                "entity_target": node_id,
                "entity_type": node.type,
                "entity_confidence": node.confidence,
                "tool_class": meta.tool_class,
                "dangerous": meta.dangerous,
                "active": meta.active,
                "timeout_s": meta.timeout_s,
            })

    # Always include hypothesis expansion as a virtual action
    if graph.nodes:
        raw.append({
            "tool": "_hypothesis_expand",
            "params": {},
            "entity_target": "graph:root",
            "entity_type": "hypothesis",
            "entity_confidence": 0.3,
            "tool_class": "hypothesis_generation",
            "dangerous": False,
            "active": False,
            "timeout_s": 1,
        })

    return raw


def _build_params(tool_name: str, node) -> Optional[dict]:
    """Build tool params from an entity node."""
    meta = get_tool(tool_name)
    if meta is None:
        return None

    params = {}
    for pname, pschema in meta.params.items():
        ptype = pschema.get("type", "string")
        pformat = pschema.get("format", "")

        # Resolve semantic type: format takes precedence for matching
        semantic_type = pformat if pformat else ptype

        # Map format types to entity types
        FORMAT_TO_ENTITY = {
            "email": "email",
            "hostname": "domain",
            "domain": "domain",
            "ipv4": "ip",
            "ip": "ip",
            "username": "username",
        }
        expected_entity = FORMAT_TO_ENTITY.get(semantic_type, semantic_type)

        if expected_entity in ("email", "domain", "hostname", "username", "ip"):
            if node.type == expected_entity:
                params[pname] = node.value
            elif pschema.get("required", False):
                return None  # Required param we can't satisfy
            else:
                continue  # Optional param we can skip
        elif ptype == "array":
            item_type = pschema.get("items", {}).get("type", "string")
            if node.type in ("username", "email", "domain"):
                params[pname] = [node.value]
            else:
                params[pname] = [node.value]
        elif node.type == ptype:
            params[pname] = node.value
        elif not pschema.get("required", False):
            continue  # Skip optional params we can't fill
        else:
            return None  # Can't satisfy required param
    return params


# ── Stage 2: Filter ───────────────────────────────────────

def _filter_no_value(candidates: list[dict], graph: ExposureGraph,
                     history: list[dict]) -> list[dict]:
    """Remove candidates that add no value."""
    filtered = []
    for c in candidates:
        # Check if entity already investigated by same tool
        if _already_investigated(c, history):
            # Same tool already ran successfully on this entity — skip regardless of yield.
            # Running holehe on an email that already returned 45 services is pointless.
            continue

        # Check if same tool on same entity TYPE recently returned 0.
        # Prevents running h8mail on 3 different emails in a row when all return 0.
        if _recent_zero_yield(c, history):
            continue

        # Check if entity is fully investigated
        if graph.is_fully_investigated(c["entity_target"]):
            continue

        filtered.append(c)
    return filtered


def _already_investigated(candidate: dict, history: list[dict]) -> bool:
    """Check if the same tool was already run on the same entity.

    Note (P2-10): This check uses entity values from history which are stable,
    but the candidate.action_id is regenerated each turn. Callers that rely on
    action_ids must be aware of the TOCTOU window — see generate_candidates() docstring.
    """
    for turn in history:
        action = turn.get("action", {})
        if action.get("tool") == candidate["tool"]:
            result = turn.get("result", {})
            if result.get("status") == "success":
                # Extract the entity value from entity_target (format: "type:value")
                target_value = candidate.get("entity_target", "")
                if ":" in target_value:
                    target_value = target_value.split(":", 1)[1]
                # Check if any param value equals the target entity value
                params = action.get("params", {})
                for v in params.values():
                    v_str = str(v) if not isinstance(v, list) else str(v[0]) if v else ""
                    if v_str and v_str == target_value:
                        return True
    return False


def _recent_zero_yield(candidate: dict, history: list[dict]) -> bool:
    """Check if the same tool on the same entity TYPE recently returned 0 yield.

    This prevents running e.g. h8mail on 3 different emails in a row when all
    return 0 — the first zero-yield should deprioritize that tool for that type.
    """
    tool = candidate["tool"]
    etype = candidate["entity_type"]
    for turn in reversed(history[-5:]):
        action = turn.get("action", {})
        if action.get("tool") == tool and action.get("entity_type") == etype:
            result = turn.get("result", {})
            if result.get("new_entity_count", 0) == 0:
                return True
    return False


def _prior_yield(candidate: dict, history: list[dict]) -> Optional[int]:
    """Get new entity count from the last run of this tool on this entity."""
    for turn in reversed(history):
        action = turn.get("action", {})
        if action.get("tool") == candidate["tool"]:
            result = turn.get("result", {})
            return result.get("new_entity_count", 0)
    return None


# ── Stage 3: Group Similar ────────────────────────────────

def _group_similar(candidates: list[dict]) -> list[dict]:
    """Group similar entities (same type, similar value) into one representative."""
    # For V1: simple grouping by entity type — keep highest confidence per (tool, entity_type)
    groups: dict[str, dict] = {}
    for c in candidates:
        key = f"{c['tool']}:{c['entity_type']}"
        if key not in groups or c["entity_confidence"] > groups[key]["entity_confidence"]:
            groups[key] = c
    return list(groups.values())


# ── Stage 4: Score ────────────────────────────────────────

def _score(candidate: dict, graph: ExposureGraph,
           history: list[dict]) -> CandidateAction:
    """Compute context-sensitive dynamic score for a candidate action."""
    tool = candidate["tool"]
    entity_type = candidate["entity_type"]
    entity_confidence = candidate["entity_confidence"]
    entity_target = candidate["entity_target"]
    timeout_s = candidate.get("timeout_s", 120)

    # Base weight from tool class
    base = get_tool_class_weight(tool)

    # Confidence multiplier (tuned: hypothesis penalty prevents junk-email starvation)
    if 0.3 <= entity_confidence <= 0.6:
        conf_mult = 1.3   # High value: confirm what we suspect
    elif entity_confidence >= 0.9:
        conf_mult = 0.5   # Low value: already confirmed
    elif entity_confidence < 0.3:
        conf_mult = 0.5   # Hypothesis: heavy penalty — don't starve real entities
    else:
        conf_mult = 1.0

    # Unexplored neighbors bonus
    if entity_target in graph.nodes:
        unexplored = graph.count_unexplored_neighbors(entity_target)
        total = max(1, len(graph.get_neighbors(entity_target)))
        unexplored_bonus = 0.2 * (unexplored / total)
    else:
        unexplored_bonus = 0.0

    # Redundancy penalty
    redundancy_penalty = 0.0
    recent_same = [h for h in history[-3:]
                   if h.get("action", {}).get("tool") == tool
                   and h.get("action", {}).get("entity_type") == entity_type]
    if recent_same:
        avg_yield = sum(
            h.get("result", {}).get("new_entity_count", 0) for h in recent_same
        ) / len(recent_same)
        if avg_yield < 2:
            redundancy_penalty = 0.5
        elif avg_yield < 5:
            redundancy_penalty = 0.2

    # Cost factor — gentle penalty. Cost is priority #4 (tiebreaker only).
    # Formula: 1.0 / (1.0 + 0.15 * max(0, (timeout_s - 60) / 60))
    #   60s  → 1.00   120s → 0.87   180s → 0.77   300s → 0.63
    # A 300s tool keeps ~2/3 of its score instead of being divided by 5.
    cost_factor = 1.0 / (1.0 + 0.15 * max(0.0, (timeout_s - 60) / 60.0))

    # Total
    score_raw = (base + unexplored_bonus) * conf_mult - redundancy_penalty
    total = max(0.05, score_raw * cost_factor)

    # Rationale
    rationale = _build_rationale(tool, entity_type, entity_confidence,
                                  unexplored_bonus, redundancy_penalty)

    # Expected yield
    expected_yield = _estimate_yield(tool, entity_type)

    return CandidateAction(
        action_id="",  # Assigned after pruning for uniqueness
        tool=tool,
        params=candidate["params"],
        entity_target=entity_target,
        entity_type=entity_type,
        entity_confidence=entity_confidence,
        expected_yield=expected_yield,
        score=CandidateScore(
            total=round(total, 3),
            base_weight=base,
            confidence_multiplier=conf_mult,
            unexplored_bonus=round(unexplored_bonus, 3),
            redundancy_penalty=round(redundancy_penalty, 3),
            cost_factor=round(cost_factor, 3),
        ),
        tool_cost={
            "time_s": timeout_s,
            "passive": not candidate.get("active", False),
            "dangerous": candidate.get("dangerous", False),
        },
        dangerous=candidate.get("dangerous", False),
        active=candidate.get("active", False),
        rationale=rationale,
    )


def _build_rationale(tool: str, entity_type: str, confidence: float,
                     unexplored_bonus: float, redundancy_penalty: float) -> str:
    """Build human-readable rationale for the score."""
    parts = []

    if tool == "_hypothesis_expand":
        return "Generate new investigation hypotheses from all discovered entities"

    if confidence < 0.3:
        parts.append("low-confidence hypothesis worth verifying")
    elif 0.3 <= confidence <= 0.6:
        parts.append("unverified entity — confirming would increase information gain")
    elif confidence >= 0.9:
        parts.append("already highly confirmed")

    if unexplored_bonus > 0.1:
        parts.append("has unexplored neighbors")
    if redundancy_penalty > 0.3:
        parts.append("recent similar action had low yield")

    return "; ".join(parts) if parts else f"Standard {tool} investigation on {entity_type}"


def _estimate_yield(tool: str, entity_type: str) -> str:
    """Estimate expected entity yield for display."""
    estimates = {
        ("holehe", "email"): "15–25 services",
        ("h8mail", "email"): "0–5 breaches",
        ("maigret", "username"): "5–20 profiles",
        ("theHarvester", "domain"): "10–50 emails/domains",
        ("theHarvester", "email"): "5–15 related entities",
    }
    return estimates.get((tool, entity_type), "unknown")


# ── Stage 5: Top-K Diverse ────────────────────────────────

def _top_k_diverse(scored: list[CandidateAction], top_k: int,
                   min_tool_classes: int) -> list[CandidateAction]:
    """Take top K, ensuring at least min_tool_classes tool classes represented."""
    if len(scored) <= top_k:
        return scored

    result = []
    tool_classes_seen: set[str] = set()

    for c in scored:
        if len(result) >= top_k:
            break
        tc = c.tool
        # Diversity check: in the last few slots, ensure variety
        remaining = top_k - len(result)
        if remaining <= min_tool_classes and tc not in tool_classes_seen:
            if len(tool_classes_seen) < min_tool_classes:
                result.append(c)
                tool_classes_seen.add(tc)
                continue
        result.append(c)
        tool_classes_seen.add(tc)

    return result
