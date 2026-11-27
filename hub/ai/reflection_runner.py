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
from hub.ai.embeddings import correlate_texts
from hub.ai.models import AIProviderKind, ReflectionProposal
from hub.ai.providers import chat_completion, parse_json_object
from hub.erkg.analytics import correlate_perceptual_hashes
from hub.erkg.graph import GraphView
from hub.investigation.reflection import (
    apply_reflection_response,
    build_reflection_packet,
)
from hub.models import (
    EdgeType,
    EntityType,
    EpistemicStatus,
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


async def _collect_similarity_signals(
    config,
    graph: GraphView,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Compute quarantined text/visual correlations and likely false-positive accounts."""
    seed_labels: list[str] = []
    for sid in graph.seed_entity_ids:
        ent = graph.entity(sid)
        if ent is not None and ent.type in {EntityType.PERSON, EntityType.USERNAME, EntityType.EMAIL}:
            seed_labels.append(ent.canonical_value)
    anchor_query = sanitize_untrusted(" ".join(seed_labels[:4]), max_len=240)

    account_entities = [
        e for e in graph.entities.values()
        if e.type == EntityType.SOCIAL_PROFILE
    ][:25]
    account_texts: list[str] = []
    ent_by_label: dict[str, str] = {}
    for acc in account_entities:
        handle = str((acc.metadata or {}).get("username") or (acc.metadata or {}).get("handle") or "")
        site = str((acc.metadata or {}).get("site") or (acc.metadata or {}).get("platform") or "")
        label = sanitize_untrusted(f"{site} {handle} {acc.canonical_value}".strip(), max_len=200)
        if label:
            account_texts.append(label)
            ent_by_label[label] = acc.entity_id

    likely_false_positives: list[dict[str, Any]] = []
    text_correlations: list[dict[str, Any]] = []
    if anchor_query and account_texts:
        ranked = await correlate_texts(
            anchor_query, account_texts, config=config, transport=transport, top_k=25
        )
        for item in ranked:
            eid = ent_by_label.get(item["text"], "")
            entry = {
                "entity_id": eid,
                "label": item["text"],
                "score": item["score"],
                "method": item["method"],
            }
            text_correlations.append(entry)
            claims = graph.claims_for(eid) if eid else []
            max_sources = max((len(c.independent_sources) for c in claims), default=0)
            if item["score"] < 0.30 and max_sources <= 1:
                likely_false_positives.append(entry)

    visual_clusters = correlate_perceptual_hashes(graph)
    return {
        "anchor_query": anchor_query,
        "text_correlations": text_correlations[:10],
        "likely_false_positives": likely_false_positives[:5],
        "visual_clusters": visual_clusters[:5],
    }


async def _run_local_embedded_reflection(
    store,
    target_id: str,
    investigation,
    graph: GraphView,
    config,
    focus_entity_id: str | None,
) -> dict[str, Any]:
    """Deterministic + embedding/visual similarity synthesis for ``local_embedded`` mode."""
    signals = await _collect_similarity_signals(config, graph)
    now = utc_now()
    artifacts = store.list_artifacts(target_id)
    cited_artifact_ids = [a.artifact_id for a in artifacts[:20]]

    fps = signals["likely_false_positives"]
    vclusters = signals["visual_clusters"]
    top_corrs = signals["text_correlations"]
    summary_parts = [
        f"Local embedded synthesis: {len(graph.entities)} entities, "
        f"{len(vclusters)} visual hash cluster(s), {len(fps)} low-similarity single-source account(s)."
    ]
    if vclusters:
        summary_parts.append(
            f"Matching perceptual hashes link {len(vclusters[0].get('entity_ids', []))} visual asset(s)."
        )
    if fps:
        summary_parts.append(
            f"Review possible false-positive profile: {fps[0]['label'][:80]} (score {fps[0]['score']:.2f})."
        )
    summary = sanitize_untrusted(" ".join(summary_parts), max_len=500)

    proposed_hyps: list[dict[str, Any]] = []
    for item in fps[:2]:
        proposed_hyps.append({
            "question": f"Verify whether low-similarity profile '{item['label'][:80]}' belongs to subject",
            "target_entity_id": item.get("entity_id") or (focus_entity_id or ""),
            "proposed_tool_ids": ["snscrape"],
        })
    if vclusters:
        first_ids = vclusters[0].get("entity_ids") or []
        if first_ids:
            proposed_hyps.append({
                "question": "Corroborate avatar/image perceptual hash match across platforms",
                "target_entity_id": first_ids[0],
                "proposed_tool_ids": ["media_forensics"],
            })

    payload = {
        "accepted": True,
        "ambiguous_matches": [],
        "contradictions": [],
        "proposed_hypotheses": proposed_hyps[:3],
        "notes": summary,
        "similarity_signals": signals,
        "top_correlations": top_corrs[:5],
    }
    model_name = config.local_embedded_text_model
    insight_id = _record_insight(
        store,
        investigation_id=target_id,
        iteration=investigation.iteration_count,
        provider="local_embedded",
        model=model_name,
        summary=summary,
        payload=payload,
        cited_artifact_ids=cited_artifact_ids,
    )

    added_hypotheses: list[str] = []
    for item in proposed_hyps[:3]:
        q = str(item.get("question") or "").strip()
        if not q:
            continue
        tid = str(item.get("target_entity_id") or "").strip()
        resolved = tid if tid in graph.entities else focus_entity_id
        hyp = Hypothesis(
            hypothesis_id=short_id("hyp", target_id, "ai_reflection", q),
            investigation_id=target_id,
            hypothesis_type=HypothesisType.VERIFICATION,
            question=q,
            target_entity_id=resolved,
            proposed_tool_ids=[str(t) for t in (item.get("proposed_tool_ids") or [])][:5],
            rationale=f"AI_INFERRED (local_embedded:{model_name}; confidence<=0.35)",
            status=HypothesisStatus.OPEN,
            created_by="ai_reflection",
            created_at=now,
            updated_at=now,
        )
        store.add_hypothesis(hyp)
        added_hypotheses.append(hyp.hypothesis_id)

    added_claims: list[str] = []
    for cluster in vclusters[:2]:
        eids = [eid for eid in (cluster.get("entity_ids") or []) if eid in graph.entities]
        if len(eids) >= 2:
            claim = store.add_hypothesis_claim(
                target_id,
                eids[0],
                EdgeType.ASSOCIATED_WITH.value,
                object_id=eids[1],
                timestamp=now,
                confidence=0.35,
            )
            added_claims.append(claim.claim_id)

    return {
        "status": "ok",
        "accepted": True,
        "target_id": target_id,
        "provider": "local_embedded",
        "model": model_name,
        "summary": summary,
        "epistemic_provenance": "AI_INFERRED",
        "insight_id": insight_id,
        "hypotheses_added": added_hypotheses,
        "hypothesis_claims_added": added_claims,
        "cited_artifact_ids": cited_artifact_ids,
        "result": payload,
    }


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
    if effective_provider == AIProviderKind.LOCAL_EMBEDDED.value:
        return await _run_local_embedded_reflection(
            store, target_id, investigation, graph, config, focus_entity_id
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
        "summary": summary,
        "epistemic_provenance": "AI_INFERRED",
        "insight_id": insight_id,
        "hypotheses_added": added_hypotheses,
        "hypothesis_claims_added": added_hypothesis_claims,
        "cited_artifact_ids": cited_artifact_ids,
        "result": applied,
    }


__all__ = ["run_case_reflection"]
