"""Tests for hub.planner.candidates — action generation and scoring."""
import pytest
import sys
sys.path.insert(0, '/root/ai_osint_hub')

from hub.planner.candidates import (
    generate_candidates, CandidateAction, CandidateScore,
    _generate_all, _filter_no_value, _group_similar, _score,
    _top_k_diverse, _already_investigated, _build_params,
)
from hub.graph.memory import ExposureGraph


class TestGenerateCandidates:
    def test_returns_candidates_for_nonempty_graph(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com")
        g.add_node("username", "testuser")
        candidates = generate_candidates(g, [])
        assert len(candidates) > 0
        assert all(isinstance(c, CandidateAction) for c in candidates)

    def test_hypothesis_expand_always_present(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com")
        candidates = generate_candidates(g, [])
        assert any(c.tool == "_hypothesis_expand" for c in candidates)

    def test_unique_action_ids(self):
        g = ExposureGraph()
        g.add_node("email", "a@b.com")
        g.add_node("email", "c@d.com")
        candidates = generate_candidates(g, [])
        ids = [c.action_id for c in candidates]
        assert len(ids) == len(set(ids))

    def test_top_k_limit(self):
        g = ExposureGraph()
        for i in range(20):
            g.add_node("email", f"test{i}@test.com")
        candidates = generate_candidates(g, [], top_k=5)
        assert len(candidates) <= 5


class TestAlreadyInvestigated:
    def test_same_tool_same_entity_returns_true(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com")
        candidate = {"tool": "holehe", "entity_target": "email:test@test.com"}
        history = [{
            "action": {"tool": "holehe", "params": {"email": "test@test.com"}},
            "result": {"status": "success"},
        }]
        assert _already_investigated(candidate, history) is True

    def test_different_entity_returns_false(self):
        candidate = {"tool": "holehe", "entity_target": "email:other@test.com"}
        history = [{
            "action": {"tool": "holehe", "params": {"email": "test@test.com"}},
            "result": {"status": "success"},
        }]
        assert _already_investigated(candidate, history) is False


class TestGroupSimilar:
    def test_groups_by_tool_and_entity_type(self):
        candidates = [
            {"tool": "holehe", "entity_type": "email", "entity_confidence": 0.8},
            {"tool": "holehe", "entity_type": "email", "entity_confidence": 0.9},
            {"tool": "h8mail", "entity_type": "email", "entity_confidence": 0.7},
        ]
        result = _group_similar(candidates)
        assert len(result) == 2  # holehe:email + h8mail:email

    def test_keeps_highest_confidence(self):
        candidates = [
            {"tool": "holehe", "entity_type": "email", "entity_confidence": 0.3},
            {"tool": "holehe", "entity_type": "email", "entity_confidence": 0.9},
        ]
        result = _group_similar(candidates)
        assert result[0]["entity_confidence"] == 0.9


class TestTopKDiverse:
    def test_respects_top_k(self):
        g = ExposureGraph()
        g.add_node("email", "test@test.com")
        scored = _score({"tool": "holehe", "entity_type": "email", "entity_confidence": 0.5,
                          "entity_target": "email:test@test.com", "timeout_s": 120,
                          "tool_class": "email_service_mapping", "dangerous": False, "active": False,
                          "params": {"email": "test@test.com"}}, g, [])
        result = _top_k_diverse([scored], 3, 1)
        assert len(result) <= 3
