"""Deterministic epistemic scoring — confidence + status from evidence sources.

Rules (fixed by the architecture spec, fully deterministic):
  * 0 independent sources → HYPOTHESIS (or COLLECTION_FAILURE for failed runs).
  * 1 independent source  → SINGLE_SOURCE_LEAD, confidence = min(0.65, 0.10 + 0.60*reliability)
  * 2+ independent sources → CORROBORATED, confidence = 0.85 + 0.05*(n-2)
                             + 0.10*(avg_reliability-0.5), capped at 0.99
  * CONFIRMED requires corroboration (>=2 independent sources), confidence >= 0.90
    and all supporting sources direct (not inferred).
  * Any functional contradiction → CONTRADICTED with confidence 0.30.

"Independent" means different ``source_tool`` ids. Re-running the same tool
(impossible through the execution ledger, but possible through reruns) never
counts as extra corroboration.
"""

from __future__ import annotations

from hub.models import ClaimSource, EpistemicStatus

SEED_SOURCE = "seed"
SEED_RELIABILITY = 0.90
DEFAULT_RELIABILITY = 0.60
CONTRADICTED_CONFIDENCE = 0.30
HYPOTHESIS_CONFIDENCE = 0.30
CONFIRMED_MIN_CONFIDENCE = 0.90


def reliability_for_tool(tool_id: str) -> float:
    """Look up declared reliability in the capability registry (falls back)."""
    if not tool_id:
        return DEFAULT_RELIABILITY
    if tool_id.lower() == SEED_SOURCE:
        return SEED_RELIABILITY
    try:
        from hub.tools.capabilities import get_tool

        cap = get_tool(tool_id)
        if cap is not None:
            return cap.reliability
    except Exception:  # noqa: BLE001 - registry import must never break scoring
        pass
    return DEFAULT_RELIABILITY


def unique_sources(sources: list[ClaimSource]) -> dict[str, ClaimSource]:
    """Collapse sources to one per independent source_tool (max reliability wins)."""
    collapsed: dict[str, ClaimSource] = {}
    for source in sources:
        key = (source.source_tool or "unknown").strip().lower()
        current = collapsed.get(key)
        if current is None or source.reliability > current.reliability:
            collapsed[key] = source
    return collapsed


def single_source_confidence(reliability: float) -> float:
    return round(min(0.65, 0.10 + 0.60 * max(0.0, min(1.0, reliability))), 2)


def corroborated_confidence(sources: list[ClaimSource]) -> float:
    unique = unique_sources(sources)
    if len(unique) < 2:
        return single_source_confidence(next(iter(unique.values())).reliability
                                        if unique else DEFAULT_RELIABILITY)
    avg = sum(s.reliability for s in unique.values()) / len(unique)
    bonus_n = 0.05 * max(0, len(unique) - 2)
    bonus_rel = 0.15 * (avg - 0.5)
    return round(max(0.85, min(0.99, 0.85 + bonus_n + bonus_rel)), 2)


def assess(sources: list[ClaimSource], *,
           contradicted: bool = False,
           hypothesis_confidence: float = HYPOTHESIS_CONFIDENCE
           ) -> tuple[EpistemicStatus, float]:
    """Return the deterministic (status, confidence) for a claim given its sources."""
    if contradicted:
        return EpistemicStatus.CONTRADICTED, CONTRADICTED_CONFIDENCE
    unique = unique_sources(sources)
    if not unique:
        confidence = round(max(0.0, min(0.40, hypothesis_confidence)), 2)
        return EpistemicStatus.HYPOTHESIS, confidence
    if len(unique) == 1:
        source = next(iter(unique.values()))
        return EpistemicStatus.SINGLE_SOURCE_LEAD, single_source_confidence(source.reliability)
    confidence = corroborated_confidence(sources)
    all_direct = all(s.direct for s in unique.values())
    if all_direct and confidence >= CONFIRMED_MIN_CONFIDENCE:
        return EpistemicStatus.CONFIRMED, confidence
    return EpistemicStatus.CORROBORATED, confidence


def is_satisfied(status: EpistemicStatus) -> bool:
    return status in (EpistemicStatus.CONFIRMED, EpistemicStatus.CORROBORATED)


def is_unverified(status: EpistemicStatus) -> bool:
    return status in (EpistemicStatus.HYPOTHESIS, EpistemicStatus.SINGLE_SOURCE_LEAD)


_STATUS_RANK = {
    EpistemicStatus.CONFIRMED: 5,
    EpistemicStatus.CORROBORATED: 4,
    EpistemicStatus.SINGLE_SOURCE_LEAD: 3,
    EpistemicStatus.HYPOTHESIS: 2,
    EpistemicStatus.CONTRADICTED: 1,
    EpistemicStatus.COLLECTION_FAILURE: 0,
}


def status_rank(status: EpistemicStatus) -> int:
    return _STATUS_RANK.get(status, 0)


def confidence_explanation(sources: list[ClaimSource]) -> dict:
    """Human-readable provenance math for reports."""
    unique = unique_sources(sources)
    status, confidence = assess(sources)
    return {
        "status": status.value,
        "confidence": confidence,
        "independent_sources": sorted(unique),
        "source_reliabilities": {k: round(v.reliability, 3) for k, v in unique.items()},
        "rule": (
            "no_evidence" if not unique else
            "single_source_cap_0.65" if len(unique) == 1 else
            "corroboration_bonus_0.85_base"
        ),
        "contradicted": status == EpistemicStatus.CONTRADICTED,
    }


__all__ = [
    "SEED_SOURCE",
    "SEED_RELIABILITY",
    "DEFAULT_RELIABILITY",
    "CONTRADICTED_CONFIDENCE",
    "HYPOTHESIS_CONFIDENCE",
    "CONFIRMED_MIN_CONFIDENCE",
    "reliability_for_tool",
    "unique_sources",
    "single_source_confidence",
    "corroborated_confidence",
    "assess",
    "is_satisfied",
    "is_unverified",
    "status_rank",
    "confidence_explanation",
]
