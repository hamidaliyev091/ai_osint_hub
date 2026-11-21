"""Deterministic epistemic scoring tests."""

import pytest

from hub.erkg.confidence import (
    CONTRADICTED_CONFIDENCE,
    SEED_RELIABILITY,
    assess,
    confidence_explanation,
    corroborated_confidence,
    is_satisfied,
    is_unverified,
    reliability_for_tool,
    single_source_confidence,
    status_rank,
)
from hub.models import ClaimSource, EpistemicStatus


def source(tool, reliability=None, artifact="art_x", direct=True):
    if reliability is None:
        reliability = reliability_for_tool(tool)
    return ClaimSource(source_tool=tool, reliability=reliability,
                       artifact_id=artifact, direct=direct)


class TestSingleSource:
    def test_cap_is_065(self):
        assert single_source_confidence(1.0) == 0.65
        assert single_source_confidence(0.95) == 0.65

    def test_formula(self):
        assert single_source_confidence(0.85) == 0.61
        assert single_source_confidence(0.5) == 0.40

    def test_status(self):
        status, confidence = assess([source("holehe")])
        assert status == EpistemicStatus.SINGLE_SOURCE_LEAD
        assert confidence == 0.61

    def test_same_tool_twice_is_not_corroboration(self):
        two_same_tool = [source("holehe", artifact="a1"), source("holehe", artifact="a2")]
        status, confidence = assess(two_same_tool)
        assert status == EpistemicStatus.SINGLE_SOURCE_LEAD
        assert confidence == 0.61


class TestCorroboration:
    def test_two_independent_sources_floor_085(self):
        status, confidence = assess([source("holehe", 0.6), source("maigret", 0.6)])
        assert status in (EpistemicStatus.CORROBORATED, EpistemicStatus.CONFIRMED)
        assert confidence >= 0.85

    def test_high_reliability_confirmed(self):
        status, confidence = assess([source("nmap", 0.95), source("amass", 0.90)])
        assert status == EpistemicStatus.CONFIRMED
        assert confidence >= 0.90

    def test_non_direct_becomes_corroborated_not_confirmed(self):
        status, _ = assess([source("nmap", 0.95, direct=False),
                            source("amass", 0.90, direct=False)])
        assert status == EpistemicStatus.CORROBORATED

    def test_three_sources_raise_confidence(self):
        two = corroborated_confidence([source("a", 0.8), source("b", 0.8)])
        three = corroborated_confidence([source("a", 0.8), source("b", 0.8),
                                         source("c", 0.8)])
        assert three > two

    def test_cap_at_099(self):
        sources = [source(f"t{i}", 1.0) for i in range(20)]
        status, confidence = assess(sources)
        assert confidence <= 0.99
        assert status in (EpistemicStatus.CORROBORATED, EpistemicStatus.CONFIRMED)


class TestHypothesisAndFailure:
    def test_no_sources_is_hypothesis(self):
        status, confidence = assess([])
        assert status == EpistemicStatus.HYPOTHESIS
        assert confidence <= 0.40

    def test_hypothesis_confidence_clamped(self):
        _, confidence = assess([], hypothesis_confidence=0.9)
        assert confidence <= 0.40

    def test_contradicted(self):
        status, confidence = assess([source("holehe"), source("maigret")],
                                    contradicted=True)
        assert status == EpistemicStatus.CONTRADICTED
        assert confidence == CONTRADICTED_CONFIDENCE == 0.30


class TestHelpers:
    def test_reliability_seed(self):
        assert reliability_for_tool("seed") == SEED_RELIABILITY

    def test_reliability_known_tool(self):
        assert reliability_for_tool("holehe") == 0.85

    def test_reliability_unknown_tool(self):
        assert reliability_for_tool("unknown_tool_xyz") == 0.60

    def test_satisfied_and_unverified(self):
        assert is_satisfied(EpistemicStatus.CORROBORATED)
        assert is_satisfied(EpistemicStatus.CONFIRMED)
        assert not is_satisfied(EpistemicStatus.SINGLE_SOURCE_LEAD)
        assert is_unverified(EpistemicStatus.HYPOTHESIS)
        assert is_unverified(EpistemicStatus.SINGLE_SOURCE_LEAD)
        assert not is_unverified(EpistemicStatus.CONFIRMED)

    def test_status_rank_order(self):
        assert status_rank(EpistemicStatus.CONFIRMED) > status_rank(EpistemicStatus.CORROBORATED)
        assert status_rank(EpistemicStatus.CORROBORATED) > status_rank(EpistemicStatus.CONTRADICTED)

    def test_explanation_is_deterministic(self):
        a = confidence_explanation([source("holehe")])
        b = confidence_explanation([source("holehe")])
        assert a == b
        assert a["rule"] == "single_source_cap_0.65"
        assert a["status"] == "SINGLE_SOURCE_LEAD"
