"""Autonomous investigation package: hypotheses, pivot scoring, loop, reflection."""

from hub.investigation.engine import (
    EngineError,
    InvestigationEngine,
    InvestigationOutcome,
    IterationOutcome,
    build_config,
    make_target_id,
)
from hub.investigation.hypotheses import (
    HypothesisGenerator,
    correlate_after_run,
    mark_stale_hypotheses,
)
from hub.investigation.pivot import PivotRanking, PivotScorer, entity_signals
from hub.investigation.reflection import (
    apply_reflection_response,
    build_reflection_packet,
    packet_to_json,
)
from hub.investigation.stopping import StopDecision, evaluate_stop, objectives_achieved

__all__ = [
    "InvestigationEngine",
    "InvestigationOutcome",
    "IterationOutcome",
    "EngineError",
    "build_config",
    "make_target_id",
    "HypothesisGenerator",
    "correlate_after_run",
    "mark_stale_hypotheses",
    "PivotScorer",
    "PivotRanking",
    "entity_signals",
    "build_reflection_packet",
    "apply_reflection_response",
    "packet_to_json",
    "evaluate_stop",
    "objectives_achieved",
    "StopDecision",
]
