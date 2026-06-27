"""Tests for hub.planner.evaluate — stop conditions."""
import pytest
import sys
sys.path.insert(0, '/root/ai_osint_hub')

from hub.planner.evaluate import (
    check_hard_stops, check_soft_stops, compute_completeness,
)
from hub.planner.candidates import CandidateAction, CandidateScore
from hub.graph.memory import ExposureGraph


def make_graph(node_count=5):
    g = ExposureGraph()
    for i in range(node_count):
        g.add_node("email", f"test{i}@test.com")
    return g


def make_turn(new_entity_count, tool="holehe"):
    return {
        "turn_id": 1,
        "action": {"tool": tool, "params": {}},
        "result": {"status": "success", "new_entity_count": new_entity_count},
        "hard_stops": [],
        "soft_stops": [],
    }


def make_dummy_candidate(tool="holehe", total_score=0.5):
    """Create a minimal CandidateAction for soft stop testing."""
    return CandidateAction(
        action_id="act_000",
        tool=tool,
        params={},
        entity_target="email:test@test.com",
        entity_type="email",
        entity_confidence=0.5,
        expected_yield="unknown",
        score=CandidateScore(
            total=total_score,
            base_weight=0.5,
            confidence_multiplier=1.0,
            unexplored_bonus=0.0,
            redundancy_penalty=0.0,
            cost_factor=1.0,
        ),
        tool_cost={"time_s": 120, "passive": True, "dangerous": False},
        dangerous=False,
        active=False,
    )


class TestHardStops:
    def test_no_candidates_triggers(self):
        g = make_graph(0)
        stops = check_hard_stops(g, {}, 1, 0, [], [])
        assert any(s["type"] == "no_candidates" for s in stops)

    def test_max_depth_triggers(self):
        g = make_graph(3)
        stops = check_hard_stops(g, {"max_depth": 3}, 3, 0, ["dummy"], [])
        assert any(s["type"] == "max_depth" for s in stops)

    def test_time_budget_triggers(self):
        g = make_graph(3)
        stops = check_hard_stops(g, {"time_budget_seconds": 60}, 1, 65, ["dummy"], [])
        assert any(s["type"] == "time_budget" for s in stops)

    def test_consecutive_zero_yield_triggers(self):
        g = make_graph(3)
        history = [make_turn(0), make_turn(0), make_turn(0)]
        stops = check_hard_stops(g, {}, 4, 0, ["dummy"], history)
        assert any(s["type"] == "consecutive_zero_yield" for s in stops)

    def test_consecutive_zero_yield_not_triggered_with_yield(self):
        g = make_graph(3)
        history = [make_turn(0), make_turn(5), make_turn(0)]
        stops = check_hard_stops(g, {}, 4, 0, ["dummy"], history)
        assert not any(s["type"] == "consecutive_zero_yield" for s in stops)


class TestSoftStops:
    def test_diminishing_returns(self):
        g = make_graph(3)
        history = [make_turn(1), make_turn(0), make_turn(1)]
        dummy = make_dummy_candidate(total_score=0.5)
        stops = check_soft_stops(g, history, [dummy], 4, 0.5)
        assert any(s["type"] == "diminishing_returns" for s in stops)

    def test_completeness_threshold(self):
        g = make_graph(3)
        dummy = make_dummy_candidate(total_score=0.5)
        stops = check_soft_stops(g, [], [dummy], 1, 0.90)
        assert any(s["type"] == "completeness_threshold" for s in stops)


class TestCompleteness:
    def test_empty_graph_zero(self):
        g = ExposureGraph()
        score = compute_completeness(g, [])
        assert score == 0.0

    def test_high_confidence_boosts(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com", confidence=0.95)
        score = compute_completeness(g, [])
        assert 0 <= score <= 1.0
