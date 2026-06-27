"""Stop evaluation — hard stops (Python-enforced) and soft stops (AI recommendations).

Hard stops CANNOT be overridden. Soft stops are recommendations the AI evaluates.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from hub.graph.memory import ExposureGraph


@dataclass
class StopResult:
    should_stop: bool
    reason: str
    stop_type: str  # "hard", "soft", "none"


# ── Hard Stops (Python-enforced — AI CANNOT override) ──────

def check_hard_stops(graph: ExposureGraph, constraints: dict,
                     turn_count: int, elapsed_seconds: float,
                     candidates: list, history: list[dict] = None) -> list[dict]:
    """Check Python-enforced hard stops. Return list of triggered stops.

    Hard stops CANNOT be overridden by the AI. They force termination.
    """
    stops = []

    # No candidates
    if not candidates:
        stops.append({
            "type": "no_candidates",
            "triggered": True,
            "reason": "No candidate actions remain — graph is fully exhausted",
        })

    # Max depth
    max_depth = constraints.get("max_depth", 5)
    if turn_count >= max_depth:
        stops.append({
            "type": "max_depth",
            "triggered": True,
            "reason": f"Max depth reached ({turn_count}/{max_depth} turns)",
        })

    # Time budget
    time_budget_s = constraints.get("time_budget_seconds",
                                     constraints.get("time_budget_minutes", 30) * 60)
    if elapsed_seconds >= time_budget_s:
        stops.append({
            "type": "time_budget",
            "triggered": True,
            "reason": f"Time budget exhausted ({elapsed_seconds:.0f}s / {time_budget_s}s)",
        })

    # Consecutive zero-yield — 3 turns in a row with 0 new entities.
    # This catches hypothesis-expansion loops and persistent tool failures.
    # Hard stop because the investigation is objectively stalled.
    if history and len(history) >= 3:
        last_3_yields = [
            h.get("result", {}).get("new_entity_count", 0)
            for h in history[-3:]
        ]
        if all(y == 0 for y in last_3_yields):
            stops.append({
                "type": "consecutive_zero_yield",
                "triggered": True,
                "reason": f"Last 3 turns produced 0 new entities each. "
                          f"Investigation stalled — no new information gained.",
            })

    return stops


# ── Soft Stops (AI-evaluated — recommendations) ───────────

def check_soft_stops(graph: ExposureGraph, history: list[dict],
                     candidates: list, turn_count: int,
                     completeness: float) -> list[dict]:
    """Check AI-evaluated soft stops. Return list of recommendations."""
    stops = []

    # Diminishing returns
    if turn_count >= 3:
        last_3_yields = [
            h.get("result", {}).get("new_entity_count", 0)
            for h in history[-3:]
        ]
        if all(y < 2 for y in last_3_yields):
            stops.append({
                "type": "diminishing_returns",
                "confidence": 0.8,
                "reason": f"Last 3 turns produced {last_3_yields} new entities each (< 2 threshold)",
            })

    # Oscillation detection: broaden+execute cycle (P1-4)
    # Pattern: [0, 5, 0, 5, 0] — alternating high/low yield never triggers
    # diminishing_returns but is objectively stalled progress.
    if len(history) >= 5:
        last_5_yields = [
            h.get("result", {}).get("new_entity_count", 0)
            for h in history[-5:]
        ]
        high_count = sum(1 for y in last_5_yields if y >= 3)
        low_count = sum(1 for y in last_5_yields if y < 2)
        if high_count >= 2 and low_count >= 2:
            stops.append({
                "type": "oscillation_detected",
                "confidence": 0.75,
                "reason": f"Oscillation pattern detected in last 5 turns "
                          f"(yields: {last_5_yields}). Broaden+execute cycle.",
            })

    # Completeness threshold
    if completeness >= 0.85:
        stops.append({
            "type": "completeness_threshold",
            "confidence": completeness,
            "reason": f"Completeness score {completeness:.2f} >= 0.85 threshold",
        })

    # Low expected gain
    if candidates:
        max_score = max(c.score.total for c in candidates)
        if max_score < 0.3:
            stops.append({
                "type": "low_expected_gain",
                "confidence": 0.7,
                "reason": f"Highest candidate score is {max_score:.2f} (< 0.3 threshold)",
            })

    # All high confidence
    high_conf = graph.entities_with_high_confidence(0.9)
    total = len(graph.nodes)
    if total > 0 and len(high_conf) == total and turn_count >= 2:
        stops.append({
            "type": "all_high_confidence",
            "confidence": 0.85,
            "reason": f"All {total} entities have confidence >= 0.9",
        })

    return stops


# ── Completeness Heuristic ────────────────────────────────

def compute_completeness(graph: ExposureGraph, history: list[dict]) -> float:
    """Compute investigation completeness (0.0–1.0).

    Factors:
      - Entity coverage: what fraction of entity types have been investigated?
      - Confidence coverage: what fraction of entities have high confidence?
      - Diminishing returns: are we still finding new things?
    """
    if not graph.nodes:
        return 0.0

    # Entity type coverage
    entity_types = graph.entity_types_present()
    # Types that "count" toward completeness (not services, not hypotheses)
    significant_types = {"email", "username", "domain", "ip", "phone", "person"}
    relevant = entity_types & significant_types
    type_coverage = len(relevant) / max(1, len(significant_types))
    type_coverage = min(1.0, type_coverage)

    # Confidence coverage
    total_nodes = len(graph.nodes)
    high_conf_count = len(graph.entities_with_high_confidence(0.9))
    medium_conf_count = len([n for n in graph.nodes.values()
                             if 0.5 <= n.confidence < 0.9])
    conf_coverage = (high_conf_count * 1.0 + medium_conf_count * 0.5) / max(1, total_nodes)
    conf_coverage = min(1.0, conf_coverage)

    # Diminishing returns factor
    if len(history) >= 3:
        last_3_yields = [
            h.get("result", {}).get("new_entity_count", 0) for h in history[-3:]
        ]
        avg_yield = sum(last_3_yields) / max(1, len(last_3_yields))
        if avg_yield >= 5:
            diminishing_factor = 0.0  # Still going strong
        elif avg_yield >= 2:
            diminishing_factor = 0.3
        else:
            diminishing_factor = 0.7  # Slowing down significantly
    else:
        diminishing_factor = 0.0

    # Weighted combination
    raw = (type_coverage * 0.35) + (conf_coverage * 0.35) + ((1.0 - diminishing_factor) * 0.30)
    return round(min(1.0, max(0.0, raw)), 2)
