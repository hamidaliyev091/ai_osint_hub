"""Deterministic stopping conditions (Spec 2).

The loop halts cleanly when:
  1. all remaining pivot candidates score below ``min_pivot_threshold``;
  2. every core objective reaches CORROBORATED / CONFIRMED;
  3. a hard budget is exhausted (``max_iterations``, ``max_tool_calls``,
     ``wall_clock_timeout_sec``).
Order is deliberate: budgets are checked first so a runaway loop can never
overrun, then objectives, then pivot scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from hub.models import (
    InvestigationState,
    Objective,
    SATISFIED_STATUSES,
)


@dataclass
class StopDecision:
    should_stop: bool
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def is_budget_stop(self) -> bool:
        return self.reason in {"max_iterations", "max_tool_calls", "wall_clock_timeout"}


def objectives_achieved(objectives: list[Objective]) -> bool:
    return bool(objectives) and all(
        objective.achieved or objective.status in SATISFIED_STATUSES
        for objective in objectives
    )


def evaluate_stop(*, investigation: InvestigationState,
                  elapsed_seconds: float,
                  pivot_generated: Optional[int] = None,
                  pivot_above_threshold: Optional[int] = None) -> StopDecision:
    """Evaluate all deterministic halt conditions. Pure function."""
    budgets = investigation.config.budgets
    detail: dict[str, Any] = {
        "iterations": investigation.iteration_count,
        "max_iterations": budgets.max_iterations,
        "tool_calls": investigation.tool_calls,
        "max_tool_calls": budgets.max_tool_calls,
        "elapsed_seconds": round(elapsed_seconds, 2),
        "wall_clock_timeout_sec": budgets.wall_clock_timeout_sec,
    }

    if investigation.iteration_count >= budgets.max_iterations:
        return StopDecision(True, "max_iterations", detail)
    if investigation.tool_calls >= budgets.max_tool_calls:
        return StopDecision(True, "max_tool_calls", detail)
    if elapsed_seconds >= budgets.wall_clock_timeout_sec:
        return StopDecision(True, "wall_clock_timeout", detail)

    if objectives_achieved(investigation.objectives):
        detail["objectives"] = [
            {"objective": o.description, "status": o.status.value, "achieved": o.achieved}
            for o in investigation.objectives
        ]
        return StopDecision(True, "objectives_met", detail)

    if pivot_generated is not None:
        detail["pivots_generated"] = pivot_generated
        detail["pivots_above_threshold"] = pivot_above_threshold
        if pivot_generated == 0:
            return StopDecision(True, "no_candidates", detail)
        if pivot_above_threshold is not None and pivot_above_threshold == 0:
            return StopDecision(True, "min_pivot_threshold", detail)

    return StopDecision(False, "continue", detail)


__all__ = ["StopDecision", "evaluate_stop", "objectives_achieved"]
