"""Quarantined Stage-2 AI reflection runner.

Consumes :func:`hub.investigation.reflection.build_reflection_packet`, enforces
:data:`hub.security.quarantine.SECURITY_SYSTEM_PROMPT` and
``<untrusted_osint_data>`` isolation, validates structured JSON against
:class:`~hub.ai.models.ReflectionProposal`, passes through
:func:`~hub.investigation.reflection.apply_reflection_response`, and records
``AI_INFERRED`` insights + optional ``HYPOTHESIS`` entries (confidence <= 0.35,
``created_by="ai_reflection"``) into :class:`~hub.erkg.store.ERKGStore`.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from hub.ai.config import load_ai_config
from hub.ai.models import ReflectionProposal
from hub.ai.providers import chat_completion, parse_json_object
from hub.erkg.graph import GraphView
from hub.investigation.reflection import (
    apply_reflection_response,
    build_reflection_packet,
)
from hub.models import (
    EdgeType,
    Hypothesis,
    HypothesisStatus,
    HypothesisType,
    short_id,
    utc_now,
)
from hub.security.quarantine import sanitize_untrusted


def _format_reflection_prompt(packet) -> str:
    payload = {
        "task": packet.task,
        "normalized_delta": packet.normalized_delta,
        "graph_neighborhood": packet.graph_neighborhood,
        "open_hypotheses": packet.open_hypotheses,
        "quarantined_external_data": packet.quarantined_external_data,
        "expected_response_schema": packet.expected_response_schema,
    }
    return (
        "Analyze the following quarantined OSINT investigation context and respond "
        "ONLY with a single JSON object matching expected_response_schema.\n"
        + json.dumps(payload, indent=2, ensure_ascii=False)
    )


def _record_insight(
    store,
    *,
    investigation_id: str,
    iteration: int,
    provider: str,
    model: str,
    summary: str,
    payload: dict[str, Any],
    cited_artifact_ids: list[str],
) -> str | None:
    if not hasattr(store, "add_ai_insight"):
        return None
    try:
        result = store.add_ai_insight(
            investigation_id=investigation_id,
            iteration=iteration,
            provider=provider,
            model=model,
            kind="reflection",
            summary=summary,
            payload=payload,
            cited_artifact_ids=cited_artifact_ids,
            epistemic_provenance="AI_INFERRED",
        )
        return str(result) if result else None
    except TypeError:
        # Fallback if store implementation uses a slightly different signature.
        return None


async def run_case_reflection(
    store,
    target_id: str,
    *,
    provider_override: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Run quarantined Stage-2 AI reflection on an investigation.

    Returns a clean status dictionary and never raises when AI is disabled or
    unreachable.
    """
    config = load_ai_config()
    effective_provider = (
        str(provider_override).strip().lower()
        if provider_override
        else config.provider.value
    )
    if not config.enabled or effective_provider == "disabled" or not config.reflection_enabled:
        return {
            "status": "disabled",
            "target_id": target_id,
            "provider": effective_provider,
            "accepted": False,
            "reason": "AI reflection is disabled",
        }

    investigation = store.get_investigation(target_id)
    if investigation is None:
        return {
            "status": "error",
            "target_id": target_id,
            "accepted": False,
            "error": f"Unknown investigation: {target_id}",
        }

    graph = GraphView(store, target_id, investigation.seed_entity_ids)
    entity_ids = list(graph.entities.keys())[:40]
    focus_entity_id = (
        investigation.seed_entity_ids[0]
        if investigation.seed_entity_ids
        else (entity_ids[0] if entity_ids else None)
    )
    open_hypotheses = store.list_hypotheses(
        target_id, statuses=[HypothesisStatus.OPEN]
    )

    packet = build_reflection_packet(
        investigation=investigation,
        graph=graph,
        open_hypotheses=open_hypotheses,
        new_entity_ids=entity_ids,
        target_entity_id=focus_entity_id,
    )
    user_prompt = _format_reflection_prompt(packet)

    response = await chat_completion(
        config,
        system_prompt=packet.system_prompt,
        user_prompt=user_prompt,
        provider_override=provider_override,
        json_mode=True,
        max_tokens=min(config.max_tokens, 1500),
        transport=transport,
    )
    if not response.ok:
        return {
            "status": response.status if response.status in {"disabled", "unavailable"} else "unavailable",
            "target_id": target_id,
            "provider": response.provider or effective_provider,
            "model": response.model,
            "accepted": False,
            "error": response.error or "AI provider unavailable",
        }

    try:
        parsed_obj = parse_json_object(response.text)
        proposal = ReflectionProposal.model_validate(parsed_obj)
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "target_id": target_id,
            "provider": response.provider,
            "model": response.model,
            "accepted": False,
            "error": f"Invalid AI reflection JSON output: {exc}",
        }

    applied = apply_reflection_response(packet, proposal.model_dump(mode="json"))
    if not applied.get("accepted"):
        return {
            "status": "error",
            "target_id": target_id,
            "provider": response.provider,
            "model": response.model,
            "accepted": False,
            "error": str(applied.get("reason") or "Reflection response rejected"),
        }

    artifacts = store.list_artifacts(target_id)
    cited_artifact_ids = [a.artifact_id for a in artifacts[:20]]
    raw_summary = applied.get("notes") or (
        f"AI reflection ({response.provider}:{response.model}): "
        f"{len(applied.get('proposed_hypotheses') or [])} hypotheses, "
        f"{len(applied.get('ambiguous_matches') or [])} ambiguous matches, "
        f"{len(applied.get('contradictions') or [])} contradictions"
    )
    summary = sanitize_untrusted(raw_summary, max_len=500)

    insight_id = _record_insight(
        store,
        investigation_id=target_id,
        iteration=investigation.iteration_count,
        provider=response.provider,
        model=response.model,
        summary=summary,
        payload=applied,
        cited_artifact_ids=cited_artifact_ids,
    )

    now = utc_now()
    added_hypotheses: list[str] = []
    for item in (applied.get("proposed_hypotheses") or [])[:3]:
        question = str(item.get("question") or "").strip()
        if not question:
            continue
        candidate_target = str(item.get("target_entity_id") or "").strip()
        resolved_target = (
            candidate_target
            if candidate_target in graph.entities
            else focus_entity_id
        )
        hyp = Hypothesis(
            hypothesis_id=short_id("hyp", target_id, "ai_reflection", question),
            investigation_id=target_id,
            hypothesis_type=HypothesisType.VERIFICATION,
            question=question,
            target_entity_id=resolved_target,
            proposed_tool_ids=[
                str(t).strip()
                for t in (item.get("proposed_tool_ids") or [])
                if str(t).strip()
            ][:5],
            rationale=f"AI_INFERRED ({response.provider}:{response.model}; confidence<=0.35)",
            status=HypothesisStatus.OPEN,
            created_by="ai_reflection",
            created_at=now,
            updated_at=now,
        )
        store.add_hypothesis(hyp)
        added_hypotheses.append(hyp.hypothesis_id)

    added_hypothesis_claims: list[str] = []
    for match in (applied.get("ambiguous_matches") or [])[:5]:
        if not isinstance(match, dict):
            continue
        eid = str(match.get("entity_id") or "").strip()
        cid = str(match.get("candidate_entity_id") or "").strip()
        if not eid or not cid or eid == cid:
            continue
        if eid not in graph.entities or cid not in graph.entities:
            continue
        try:
            raw_conf = float(match.get("confidence", 0.30))
        except (TypeError, ValueError):
            raw_conf = 0.30
        capped_conf = round(max(0.05, min(0.35, raw_conf)), 2)
        claim = store.add_hypothesis_claim(
            target_id,
            eid,
            EdgeType.ASSOCIATED_WITH.value,
            object_id=cid,
            timestamp=now,
            confidence=capped_conf,
        )
        added_hypothesis_claims.append(claim.claim_id)

    return {
        "status": "ok",
        "accepted": True,
        "target_id": target_id,
        "provider": response.provider,
        "model": response.model,
        "epistemic_provenance": "AI_INFERRED",
        "insight_id": insight_id,
        "hypotheses_added": added_hypotheses,
        "hypothesis_claims_added": added_hypothesis_claims,
        "cited_artifact_ids": cited_artifact_ids,
        "result": applied,
    }


__all__ = ["run_case_reflection"]
