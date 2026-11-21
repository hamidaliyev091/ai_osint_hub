"""Deterministic stopping-condition tests."""

import pytest

from hub.investigation.stopping import (
    StopDecision,
    evaluate_stop,
    objectives_achieved,
)
from hub.models import (
    BudgetConfig,
    EpistemicStatus,
    InvestigationConfig,
    InvestigationState,
    Objective,
    RunStatus,
    utc_now,
)


def make_state(*, iterations=0, tool_calls=0, objectives=None,
               max_iterations=5, max_tool_calls=10, wall_clock=300,
               elapsed=0.0):
    config = InvestigationConfig(
        target_id="inv-stop", raw_input="seed",
        budgets=BudgetConfig(max_iterations=max_iterations,
                             max_tool_calls=max_tool_calls,
                             wall_clock_timeout_sec=wall_clock),
    )
    return InvestigationState(
        target_id="inv-stop", raw_input="seed", created_at=utc_now(),
        updated_at=utc_now(), status=RunStatus.ACTIVE, config=config,
        iteration_count=iterations, tool_calls=tool_calls,
        objectives=objectives or [],
    )


def objective(*, achieved=False, status=EpistemicStatus.SINGLE_SOURCE_LEAD):
    return Objective(objective_id="o1", description="d", entity_id="e1",
                     achieved=achieved, status=status)


class TestBudgets:
    def test_max_iterations(self):
        decision = evaluate_stop(investigation=make_state(iterations=5),
                                 elapsed_seconds=1.0)
        assert decision.should_stop
        assert decision.reason == "max_iterations"
        assert decision.is_budget_stop

    def test_max_tool_calls(self):
        decision = evaluate_stop(investigation=make_state(tool_calls=10),
                                 elapsed_seconds=1.0)
        assert decision.should_stop
        assert decision.reason == "max_tool_calls"
        assert decision.is_budget_stop

    def test_wall_clock_timeout(self):
        decision = evaluate_stop(investigation=make_state(wall_clock=60),
                                 elapsed_seconds=60.0)
        assert decision.should_stop
        assert decision.reason == "wall_clock_timeout"
        assert decision.is_budget_stop

    def test_budget_checked_before_objectives(self):
        decision = evaluate_stop(
            investigation=make_state(iterations=5,
                                     objectives=[objective(achieved=True,
                                                           status=EpistemicStatus.CONFIRMED)]),
            elapsed_seconds=1.0)
        assert decision.reason == "max_iterations"


class TestObjectives:
    def test_all_objectives_met(self):
        objectives = [objective(achieved=True, status=EpistemicStatus.CORROBORATED),
                      objective(achieved=True, status=EpistemicStatus.CONFIRMED)]
        decision = evaluate_stop(investigation=make_state(objectives=objectives),
                                 elapsed_seconds=1.0)
        assert decision.should_stop
        assert decision.reason == "objectives_met"
        assert not decision.is_budget_stop

    def test_partial_objectives_continue(self):
        objectives = [objective(achieved=True, status=EpistemicStatus.CORROBORATED),
                      objective(achieved=False)]
        decision = evaluate_stop(investigation=make_state(objectives=objectives),
                                 elapsed_seconds=1.0)
        assert decision.should_stop is False
        assert decision.reason == "continue"

    def test_satisfied_status_counts_even_if_flag_stale(self):
        objectives = [objective(achieved=False, status=EpistemicStatus.CORROBORATED)]
        assert objectives_achieved(objectives) is True

    def test_empty_objectives_never_satisfied(self):
        assert objectives_achieved([]) is False


class TestPivotThreshold:
    def test_no_candidates(self):
        decision = evaluate_stop(investigation=make_state(), elapsed_seconds=1.0,
                                 pivot_generated=0, pivot_above_threshold=0)
        assert decision.should_stop
        assert decision.reason == "no_candidates"

    def test_all_below_threshold(self):
        decision = evaluate_stop(investigation=make_state(), elapsed_seconds=1.0,
                                 pivot_generated=7, pivot_above_threshold=0)
        assert decision.should_stop
        assert decision.reason == "min_pivot_threshold"

    def test_above_threshold_continues(self):
        decision = evaluate_stop(investigation=make_state(), elapsed_seconds=1.0,
                                 pivot_generated=7, pivot_above_threshold=3)
        assert decision.should_stop is False
        assert decision.reason == "continue"

    def test_stop_decision_dataclass_defaults(self):
        decision = StopDecision(False)
        assert decision.reason == ""
        assert decision.detail == {}
