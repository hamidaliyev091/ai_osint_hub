"""Evidence-cited intelligence dossier (Spec 5).

Every finding in the Markdown/JSON dossier cites one or more immutable
``[artifact_id]`` records and states its epistemic status. A dedicated section
lists collection gaps, dead ends and unverified hypotheses so the reader knows
what the investigation did *not* establish.

The dossier is deterministic for a fixed database + ``generated_at`` timestamp:
enough to diff two runs of the same investigation.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable, Optional

from hub.erkg.graph import GraphView
from hub.erkg.store import ERKGStore
from hub.models import (
    Claim,
    Entity,
    EpistemicStatus,
    EvidenceArtifact,
    ExecutionStatus,
    HypothesisStatus,
    InvestigationState,
    SCHEMA_VERSION,
    utc_now,
)
from hub.security.quarantine import detect_injection, sanitize_untrusted

DOSSIER_VERSION = "2.0.0"
_MAX_MD_VALUE = 200

_STATUS_ORDER = {
    EpistemicStatus.CONFIRMED: 0,
    EpistemicStatus.CORROBORATED: 1,
    EpistemicStatus.SINGLE_SOURCE_LEAD: 2,
    EpistemicStatus.HYPOTHESIS: 3,
    EpistemicStatus.CONTRADICTED: 4,
    EpistemicStatus.COLLECTION_FAILURE: 5,
}

_ENTITY_ORDER = [
    "person", "email", "username", "phone", "domain", "subdomain", "ip", "asn",
    "organization", "repository", "social_profile", "breach_record",
    "crypto_address", "service", "credential", "hash", "port", "location", "url",
]


# ════════════════════════════════════════════════════════════════════════
# Dossier construction (JSON)
# ════════════════════════════════════════════════════════════════════════

def _safe(value: Any, max_len: int = _MAX_MD_VALUE) -> str:
    try:
        return sanitize_untrusted(str(value), max_len=max_len)
    except Exception:  # noqa: BLE001 - reporting must never crash
        return str(value)[:max_len]


def _artifact_summary(artifact: EvidenceArtifact) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "source_tool": artifact.source_tool,
        "invocation_params_hash": artifact.invocation_params_hash,
        "timestamp_utc": artifact.timestamp_utc,
        "raw_output_sha256": artifact.raw_output_sha256,
        "parser_version": artifact.parser_version,
        "epistemic_status": artifact.epistemic_status.value,
        "confidence": round(artifact.confidence, 3),
        "raw_evidence_snippet": _safe(artifact.raw_evidence_snippet, 1000),
        "injection_flags": detect_injection(artifact.raw_evidence_snippet),
        "raw_output_path": artifact.raw_output_path,
        "stdout_bytes": artifact.stdout_bytes,
        "truncated": artifact.truncated,
    }


def _claim_payload(claim: Claim, entity_index: dict[str, Entity],
                   artifact_index: dict[str, EvidenceArtifact]) -> dict[str, Any]:
    artifacts = [
        _artifact_summary(artifact_index[artifact_id])
        for artifact_id in claim.artifact_ids if artifact_id in artifact_index
    ]
    if claim.object_id is not None:
        object_payload: Any = {
            "entity_id": claim.object_id,
            "entity": (entity_index[claim.object_id].summary()
                       if claim.object_id in entity_index else None),
        }
    else:
        object_payload = {"literal": claim.object_literal}
    return {
        "claim_id": claim.claim_id,
        "predicate": claim.predicate,
        "object": object_payload,
        "status": claim.status.value,
        "confidence": round(claim.confidence, 3),
        "independent_sources": claim.independent_sources,
        "artifact_ids": list(claim.artifact_ids),
        "evidence": [
            {
                "artifact_id": artifact["artifact_id"],
                "source_tool": artifact["source_tool"],
                "snippet": artifact["raw_evidence_snippet"],
                "injection_flags": artifact["injection_flags"],
            }
            for artifact in artifacts
        ],
        "direct": claim.direct,
        "first_seen": claim.first_seen,
        "updated_at": claim.updated_at,
    }


def build_dossier(store: ERKGStore, target_id: str, *,
                  generated_at: Optional[str] = None) -> dict[str, Any]:
    """Build the full structured dossier. Raises KeyError for unknown target."""
    investigation = store.get_investigation(target_id)
    if investigation is None:
        raise KeyError(f"investigation not found: {target_id}")
    graph = GraphView(store, target_id, investigation.seed_entity_ids)
    entities = store.list_entities(target_id)
    claims = store.list_claims(target_id)
    artifacts = store.list_artifacts(target_id)
    ledger = store.list_ledger(target_id)
    hypotheses = store.list_hypotheses(target_id)
    contradictions = store.list_contradictions(target_id)
    entity_index = {entity.entity_id: entity for entity in entities}
    artifact_index = {artifact.artifact_id: artifact for artifact in artifacts}
    claims_by_subject: dict[str, list[Claim]] = defaultdict(list)
    for claim in claims:
        claims_by_subject[claim.subject_id].append(claim)

    entity_payloads: list[dict[str, Any]] = []
    for entity in sorted(entities, key=lambda e: (
            _ENTITY_ORDER.index(e.type.value) if e.type.value in _ENTITY_ORDER else 99,
            e.canonical_value)):
        subject_claims = sorted(
            claims_by_subject.get(entity.entity_id, []),
            key=lambda c: (_STATUS_ORDER.get(c.status, 9), c.predicate, c.claim_id),
        )
        attributes = {}
        for claim in subject_claims:
            if claim.predicate.startswith("HAS_ATTRIBUTE:"):
                attributes[claim.predicate.split(":", 1)[1]] = claim.object_literal
        entity_payloads.append({
            "entity_id": entity.entity_id,
            "type": entity.type.value,
            "value": _safe(entity.canonical_value),
            "display_value": _safe(entity.display_value),
            "aliases": [_safe(alias) for alias in entity.aliases[:10]],
            "raw_values": [_safe(value) for value in entity.raw_values[:10]],
            "first_seen": entity.first_seen,
            "last_seen": entity.last_seen,
            "attributes": attributes,
            "claims": [_claim_payload(claim, entity_index, artifact_index)
                       for claim in subject_claims],
        })

    relationships = []
    for claim in claims:
        if claim.object_id is None:
            continue
        subject = entity_index.get(claim.subject_id)
        obj = entity_index.get(claim.object_id)
        if subject is None or obj is None:
            continue
        relationships.append({
            "claim_id": claim.claim_id,
            "subject": subject.summary(),
            "predicate": claim.predicate,
            "object": obj.summary(),
            "status": claim.status.value,
            "confidence": round(claim.confidence, 3),
            "artifact_ids": list(claim.artifact_ids),
        })
    relationships.sort(key=lambda r: (r["subject"]["entity_id"], r["predicate"],
                                      r["object"]["entity_id"]))

    contradiction_payloads = []
    claim_index = {claim.claim_id: claim for claim in claims}
    for contradiction in contradictions:
        claim_a = claim_index.get(contradiction.claim_a)
        claim_b = claim_index.get(contradiction.claim_b)
        subject = entity_index.get(contradiction.subject_id)
        contradiction_payloads.append({
            "contradiction_id": contradiction.contradiction_id,
            "subject": subject.summary() if subject else {"entity_id": contradiction.subject_id},
            "predicate": contradiction.predicate,
            "created_at": contradiction.created_at,
            "resolved": contradiction.resolved,
            "claim_a": (_claim_payload(claim_a, entity_index, artifact_index)
                        if claim_a else None),
            "claim_b": (_claim_payload(claim_b, entity_index, artifact_index)
                        if claim_b else None),
        })

    failed_runs = [entry for entry in ledger
                   if entry.status in (ExecutionStatus.ERROR, ExecutionStatus.TIMEOUT)]
    empty_runs = [entry for entry in ledger if entry.status == ExecutionStatus.EMPTY]
    unresolved_hypotheses = [hypothesis for hypothesis in hypotheses
                             if hypothesis.status in (HypothesisStatus.OPEN,
                                                      HypothesisStatus.INCONCLUSIVE)]
    collection_gaps = {
        "failed_runs": [{
            "tool_id": entry.tool_id,
            "entity_id": entry.entity_id,
            "status": entry.status.value,
            "error_code": entry.error_code.value if entry.error_code else None,
            "error_message": _safe(entry.error_message, 500),
            "run_at": entry.run_at,
            "artifact_id": entry.artifact_id,
        } for entry in failed_runs],
        "empty_runs": [{
            "tool_id": entry.tool_id,
            "entity_id": entry.entity_id,
            "error_code": entry.error_code.value if entry.error_code else None,
            "run_at": entry.run_at,
        } for entry in empty_runs],
        "unresolved_hypotheses": [{
            "hypothesis_id": hypothesis.hypothesis_id,
            "type": hypothesis.hypothesis_type.value,
            "status": hypothesis.status.value,
            "question": _safe(hypothesis.question, 500),
            "target_entity_id": hypothesis.target_entity_id,
            "proposed_tool_ids": hypothesis.proposed_tool_ids,
            "rationale": _safe(hypothesis.rationale, 500),
        } for hypothesis in unresolved_hypotheses],
        "unresolved_contradictions": [
            contradiction["contradiction_id"]
            for contradiction in contradiction_payloads if not contradiction["resolved"]
        ],
        "tools_that_never_succeeded": sorted({
            entry.tool_id for entry in ledger
            if entry.status in (ExecutionStatus.ERROR, ExecutionStatus.TIMEOUT)
        } - {entry.tool_id for entry in ledger
             if entry.status == ExecutionStatus.SUCCESS}),
    }

    claim_status_counts: dict[str, int] = {}
    for claim in claims:
        claim_status_counts[claim.status.value] = \
            claim_status_counts.get(claim.status.value, 0) + 1
    entity_type_counts: dict[str, int] = {}
    for entity in entities:
        entity_type_counts[entity.type.value] = \
            entity_type_counts.get(entity.type.value, 0) + 1
    ledger_status_counts: dict[str, int] = {}
    for entry in ledger:
        ledger_status_counts[entry.status.value] = \
            ledger_status_counts.get(entry.status.value, 0) + 1
    hypothesis_status_counts: dict[str, int] = {}
    for hypothesis in hypotheses:
        hypothesis_status_counts[hypothesis.status.value] = \
            hypothesis_status_counts.get(hypothesis.status.value, 0) + 1

    tool_activity: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for entry in ledger:
        tool_activity[entry.tool_id][entry.status.value] += 1

    ai_insights: list[dict[str, Any]] = []
    if hasattr(store, "list_ai_insights"):
        try:
            for row in store.list_ai_insights(target_id) or []:
                ai_insights.append({
                    "insight_id": str(row.get("insight_id", "")),
                    "iteration": int(row.get("iteration", 0) or 0),
                    "provider": _safe(row.get("provider", ""), 80),
                    "model": _safe(row.get("model", ""), 120),
                    "kind": _safe(row.get("kind", "reflection"), 80),
                    "summary": _safe(row.get("summary", ""), 2000),
                    "epistemic_provenance": _safe(
                        row.get("epistemic_provenance", "AI_INFERRED"), 40),
                    "cited_artifact_ids": [
                        str(aid) for aid in (row.get("cited_artifact_ids") or []) if aid
                    ],
                    "created_at": str(row.get("created_at", "")),
                })
        except Exception:  # noqa: BLE001 - optional AI table must not break dossier
            ai_insights = []

    return {
        "dossier_version": DOSSIER_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or utc_now(),
        "investigation": {
            "target_id": investigation.target_id,
            "status": investigation.status.value,
            "stop_reason": investigation.stop_reason,
            "created_at": investigation.created_at,
            "updated_at": investigation.updated_at,
            "iterations": investigation.iteration_count,
            "tool_calls": investigation.tool_calls,
            "seed_entity_ids": investigation.seed_entity_ids,
            "scope": investigation.config.scope.model_dump(mode="json"),
            "budgets": investigation.config.budgets.model_dump(mode="json"),
            "pivot_weights": investigation.config.weights.model_dump(mode="json"),
            "min_pivot_threshold": investigation.config.min_pivot_threshold,
        },
        "summary": {
            "entity_count": len(entities),
            "entity_types": entity_type_counts,
            "claim_count": len(claims),
            "claim_statuses": claim_status_counts,
            "relationship_count": len(relationships),
            "artifact_count": len(artifacts),
            "contradiction_count": len(contradictions),
            "ledger_statuses": ledger_status_counts,
            "hypothesis_statuses": hypothesis_status_counts,
            "graph": graph.summary(),
            "objectives": [objective.model_dump(mode="json")
                           for objective in investigation.objectives],
        },
        "entities": entity_payloads,
        "relationships": relationships,
        "contradictions": contradiction_payloads,
        "hypotheses": [{
            "hypothesis_id": hypothesis.hypothesis_id,
            "type": hypothesis.hypothesis_type.value,
            "question": _safe(hypothesis.question, 500),
            "status": hypothesis.status.value,
            "target_entity_id": hypothesis.target_entity_id,
            "proposed_tool_ids": hypothesis.proposed_tool_ids,
            "rationale": _safe(hypothesis.rationale, 500),
            "closing_note": _safe(hypothesis.closing_note, 300),
        } for hypothesis in hypotheses],
        "collection_gaps": collection_gaps,
        "tool_activity": {tool: dict(counts)
                          for tool, counts in sorted(tool_activity.items())},
        "provenance_artifacts": [_artifact_summary(artifact) for artifact in artifacts],
        "ai_insights": ai_insights,
    }


# ════════════════════════════════════════════════════════════════════════
# Markdown rendering
# ════════════════════════════════════════════════════════════════════════

def _md_value(value: Any, max_len: int = _MAX_MD_VALUE) -> str:
    text = _safe(value, max_len)
    text = text.replace("`", "'").replace("\r", " ").replace("\n", " ")
    return text


def _cite(artifact_ids: Iterable[str]) -> str:
    ids = [artifact_id for artifact_id in artifact_ids if artifact_id]
    if not ids:
        return "_no artifact_"
    return "[" + ", ".join(ids) + "]"


def render_markdown(dossier: dict[str, Any]) -> str:
    investigation = dossier["investigation"]
    summary = dossier["summary"]
    lines: list[str] = []
    target_id = investigation["target_id"]

    lines += [
        f"# Intelligence Dossier — `{target_id}`",
        "",
        "> Evidence-cited OSINT report. Every finding below cites its immutable "
        "[artifact_id] and states its epistemic status. Single-source claims are "
        "leads, not facts.",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Target | `{target_id}` |",
        f"| Status | **{investigation['status']}** |",
        f"| Stop reason | `{investigation['stop_reason'] or 'n/a'}` |",
        f"| Generated | {dossier['generated_at']} |",
        f"| Iterations / tool calls | {investigation['iterations']} / "
        f"{investigation['tool_calls']} |",
        f"| Entities / claims / edges | {summary['entity_count']} / "
        f"{summary['claim_count']} / {summary['relationship_count']} |",
        f"| Evidence artifacts | {summary['artifact_count']} |",
        f"| Contradictions | {summary['contradiction_count']} |",
        f"| Scope (allowed domains) | "
        f"{', '.join(investigation['scope'].get('allow_domains') or []) or 'n/a'} |",
        "",
        "## 1. Executive Summary",
        "",
        "| Epistemic status | Claims |",
        "|---|---|",
    ]
    for status in ("CONFIRMED", "CORROBORATED", "SINGLE_SOURCE_LEAD",
                   "HYPOTHESIS", "CONTRADICTED", "COLLECTION_FAILURE"):
        lines.append(f"| {status} | {summary['claim_statuses'].get(status, 0)} |")
    lines += [
        "",
        f"**Entity coverage:** {json.dumps(summary['entity_types'], sort_keys=True)}",
        "",
        "**Core objectives:**",
        "",
    ]
    objectives = summary.get("objectives") or []
    if objectives:
        for objective in objectives:
            mark = "x" if objective.get("achieved") else " "
            lines.append(f"- [{mark}] {objective.get('description', '')} "
                         f"— `{objective.get('status', '')}`")
    else:
        lines.append("- _no objectives recorded_")
    lines.append("")

    # ── 2. Findings ──
    lines += ["## 2. Findings (evidence-cited)", ""]
    typed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entity in dossier["entities"]:
        typed[entity["type"]].append(entity)
    if not typed:
        lines.append("_No entities were collected._")
        lines.append("")
    for entity_type in sorted(typed, key=lambda t: (
            _ENTITY_ORDER.index(t) if t in _ENTITY_ORDER else 99, t)):
        group = typed[entity_type]
        lines.append(f"### {entity_type.replace('_', ' ').title()} ({len(group)})")
        lines.append("")
        for entity in group[:50]:
            attributes = entity.get("attributes") or {}
            attribute_text = ""
            if attributes:
                attribute_text = " — " + ", ".join(
                    f"`{_md_value(key)}={_md_value(value, 60)}`"
                    for key, value in list(attributes.items())[:6])
            lines.append(f"- **`{_md_value(entity['value'])}`** "
                         f"(`{entity['entity_id']}`){attribute_text}")
            for claim in entity.get("claims", [])[:25]:
                if claim["predicate"] == "IDENTIFIED_AS":
                    continue
                if "entity" in claim["object"] and claim["object"].get("entity"):
                    object_text = (f"{claim['object']['entity']['type']}:"
                                   f"{_md_value(claim['object']['entity']['value'])}")
                elif "literal" in claim["object"]:
                    object_text = f"`{_md_value(claim['object']['literal'], 80)}`"
                else:
                    object_text = str(claim["object"].get("entity_id", "?"))
                lines.append(
                    f"  - `{claim['predicate']}` → {object_text} — "
                    f"**{claim['status']}** (confidence {claim['confidence']:.2f}; "
                    f"sources: {', '.join(claim['independent_sources']) or 'none'}) "
                    f"{_cite(claim['artifact_ids'])}")
            remaining = len(entity.get("claims", [])) - 25
            if remaining > 1:
                lines.append(f"  - _… {remaining} more claim(s) in JSON dossier_")
        lines.append("")

    # ── 3. Relationships ──
    lines += ["## 3. Relationship Map (evidence-cited edges)", ""]
    relationships = dossier["relationships"]
    if not relationships:
        lines.append("_No relationship claims recorded._")
    else:
        lines += ["| Subject | Predicate | Object | Status | Conf. | Evidence |",
                  "|---|---|---|---|---|---|"]
        for relationship in relationships[:100]:
            subject = relationship["subject"]
            obj = relationship["object"]
            lines.append(
                f"| `{_md_value(subject['value'], 60)}` | {relationship['predicate']} | "
                f"`{_md_value(obj['value'], 60)}` | {relationship['status']} | "
                f"{relationship['confidence']:.2f} | "
                f"{_cite(relationship['artifact_ids'])} |")
        if len(relationships) > 100:
            lines.append(f"\n_… {len(relationships) - 100} more edges in JSON dossier._")
    lines.append("")

    # ── 4. Contradictions ──
    lines += ["## 4. Contradictions", ""]
    contradictions = dossier["contradictions"]
    if not contradictions:
        lines.append("_No functional contradictions detected between sources._")
    else:
        for contradiction in contradictions:
            subject = contradiction["subject"]
            subject_text = (f"{subject.get('type', '?')}:"
                            f"{_md_value(subject.get('value', subject.get('entity_id'))) }")
            lines.append(f"### `{contradiction['contradiction_id']}` — "
                         f"{contrast(contradiction)}")
            lines.append("")
            lines.append(f"Subject: `{subject_text}` · predicate "
                         f"`{contradiction['predicate']}` · "
                         f"{'resolved' if contradiction['resolved'] else '**unresolved**'}")
            lines.append("")
            for label in ("claim_a", "claim_b"):
                claim = contradiction.get(label)
                if not claim:
                    continue
                values = claim["object"].get("literal")
                if values is None and claim["object"].get("entity"):
                    values = claim["object"]["entity"].get("value")
                lines.append(
                    f"- {label}: `{_md_value(values, 120)}` — **{claim['status']}** "
                    f"(confidence {claim['confidence']:.2f}; "
                    f"sources: {', '.join(claim['independent_sources']) or 'none'}) "
                    f"{_cite(claim['artifact_ids'])}")
            lines.append("")
    lines.append("")

    # ── 5. Gaps / dead ends / unverified hypotheses ──
    gaps = dossier["collection_gaps"]
    lines += ["## 5. Collection Gaps, Dead Ends & Unverified Hypotheses", ""]
    lines += ["### 5.1 Failed collections", ""]
    if gaps["failed_runs"]:
        lines += ["| Tool | Entity | Status | Error code | Artifact |",
                  "|---|---|---|---|---|"]
        for run in gaps["failed_runs"]:
            lines.append(f"| {run['tool_id']} | `{_md_value(run['entity_id'], 60)}` | "
                         f"{run['status']} | {run['error_code'] or 'n/a'} | "
                         f"{_cite([run['artifact_id']])} |")
    else:
        lines.append("_None._")
    lines += ["", "### 5.2 Empty results (dead ends)", ""]
    if gaps["empty_runs"]:
        for run in gaps["empty_runs"]:
            lines.append(f"- {run['tool_id']} on `{_md_value(run['entity_id'], 80)}` "
                         f"— EMPTY at {run['run_at']}")
    else:
        lines.append("_None._")
    lines += ["", "### 5.3 Unverified / unresolved hypotheses", ""]
    if gaps["unresolved_hypotheses"]:
        for hypothesis in gaps["unresolved_hypotheses"]:
            lines.append(f"- **[{hypothesis['status']}] "
                         f"{hypothesis['type']}** — {hypothesis['question']} "
                         f"(tools: {', '.join(hypothesis['proposed_tool_ids']) or 'n/a'})")
    else:
        lines.append("_All hypotheses were answered or ruled out._")
    lines += ["", "### 5.4 Unresolved contradictions", ""]
    if gaps["unresolved_contradictions"]:
        for contradiction_id in gaps["unresolved_contradictions"]:
            lines.append(f"- `{contradiction_id}`")
    else:
        lines.append("_None._")
    lines += ["", "### 5.5 Tools with no successful collection", ""]
    if gaps["tools_that_never_succeeded"]:
        lines.append("- " + ", ".join(gaps["tools_that_never_succeeded"]))
    else:
        lines.append("_None._")
    lines.append("")

    # ── 6. Provenance appendix ──
    lines += ["## 6. Provenance Appendix — Immutable Evidence Artifacts", ""]
    artifacts = dossier["provenance_artifacts"]
    if not artifacts:
        lines.append("_No artifacts recorded._")
    else:
        lines += ["| Artifact | Tool | Params hash | Timestamp | SHA-256 | Parser | "
                  "Status | Conf. | Snippet |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for artifact in artifacts[:200]:
            lines.append(
                f"| `{artifact['artifact_id']}` | {artifact['source_tool']} | "
                f"`{artifact['invocation_params_hash'][:16]}` | "
                f"{artifact['timestamp_utc']} | "
                f"`{artifact['raw_output_sha256'][:16]}…` | "
                f"{artifact['parser_version']} | {artifact['epistemic_status']} | "
                f"{artifact['confidence']:.2f} | "
                f"{_md_value(artifact['raw_evidence_snippet'], 100)} |")
        if len(artifacts) > 200:
            lines.append(f"\n_… {len(artifacts) - 200} more artifacts in JSON dossier._")
    lines.append("")

    # ── 7. Method ──
    lines += [
        "## 7. Method & Epistemic Model", "",
        "- **CONFIRMED** — ≥2 independent tools agree, deterministic confidence ≥0.90, "
        "all sources direct.",
        "- **CORROBORATED** — ≥2 independent tools agree (confidence ≥0.85).",
        "- **SINGLE_SOURCE_LEAD** — exactly one source; confidence capped at 0.65. "
        "Treat as a lead to verify, not a fact.",
        "- **HYPOTHESIS** — planner-generated, no evidence artifact yet.",
        "- **CONTRADICTED** — functional claims disagree; confidence 0.30; both values "
        "are reported above.",
        "- **COLLECTION_FAILURE** — run failed; recorded as a collection gap.",
        "",
        "External OSINT text is treated as untrusted: control characters are stripped, "
        "literal `<untrusted_osint_data>` tag escapes are neutralized and snippets are "
        "truncated in this dossier.",
        "",
    ]

    ai_insights = dossier.get("ai_insights") or []
    if ai_insights:
        lines += [
            "## 8. AI-Assisted Reflection & Hypotheses (AI_INFERRED — Requires Verification)",
            "",
            "> Advisory AI synthesis generated from quarantined OSINT evidence. "
            "Treat every item below as `AI_INFERRED` until corroborated by deterministic tools.",
            "",
        ]
        for insight in ai_insights:
            prov = _md_value(insight.get("epistemic_provenance") or "AI_INFERRED", 40)
            provider = _md_value(insight.get("provider") or "unknown", 60)
            model = _md_value(insight.get("model") or "unknown", 80)
            kind = _md_value(insight.get("kind") or "reflection", 60)
            summary_txt = _md_value(insight.get("summary") or "", 1000)
            cites = _cite(insight.get("cited_artifact_ids") or [])
            lines.append(
                f"- **[{prov}]** `{kind}` ({provider}/{model}, iter {insight.get('iteration', 0)}): "
                f"{summary_txt} {cites}"
            )
        lines.append("")

    return "\n".join(lines)


def contrast(contradiction: dict[str, Any]) -> str:
    """Short description of what the contradiction is about."""
    subject = contradiction.get("subject") or {}
    return (f"two sources disagree on `{contradiction.get('predicate')}` for "
            f"`{_md_value(subject.get('value', subject.get('entity_id', '')), 80)}`")


def render_json(dossier: dict[str, Any]) -> str:
    return json.dumps(dossier, indent=2, ensure_ascii=False, default=str)


def _h(value: Any, max_len: int = 400) -> str:
    import html as html_module

    return html_module.escape(_safe(value, max_len))


def render_html(dossier: dict[str, Any]) -> str:
    """Standalone, editorial print-ready HTML dossier (Gruvbox Material Light + print CSS)."""
    investigation = dossier["investigation"]
    summary = dossier["summary"]
    target_id = investigation["target_id"]
    generated_at = dossier["generated_at"]
    parts: list[str] = []
    head = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Intelligence Dossier — __TARGET__</title>
<style>
:root {
  color-scheme: light;
  --canvas: #fbf1c7;
  --surface: #f9f5d7;
  --inset: #f2e5bc;
  --ink: #282828;
  --ink-body: #3c3836;
  --muted: #665c54;
  --line: #d5c4a1;
  --accent: #af3a03;
  --green: #427b58;
  --olive: #79740e;
  --ochre: #b57614;
  --crimson: #9d0006;
  --slate: #076678;
}
* { box-sizing: border-box; }
body {{
  margin: 0;
  font: 14px/1.55 "Inter", "Segoe UI", system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif;
  background: var(--canvas);
  color: var(--ink-body);
}}
main {{ max-width: 1120px; margin: 0 auto; padding: 32px 24px 64px; }}
.doc-header {{
  background: var(--surface);
  border: 1px solid var(--line);
  border-top: 4px solid var(--accent);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 24px;
}}
.kicker {{
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 8px;
}}
h1 {{ font-size: 26px; margin: 0 0 8px; color: var(--ink); letter-spacing: -0.01em; }}
h2 {{
  margin: 32px 0 16px;
  padding: 8px 0;
  border-bottom: 1px solid var(--line);
  font-size: 18px;
  color: var(--ink);
  letter-spacing: -0.005em;
}}
h3 {{ margin: 24px 0 8px; font-size: 14.5px; color: var(--ink); font-weight: 700; }}
.meta {{
  color: var(--muted);
  font-size: 12px;
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}}
.mono {{
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.03em;
  border: 1px solid var(--line);
  background: var(--inset);
  color: var(--ink-body);
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}}
.CONFIRMED {{ background: #e8eed8; color: var(--green); border-color: #8ea67c; }}
.CORROBORATED {{ background: #e8eed8; color: var(--olive); border-color: #a39e4b; }}
.SINGLE_SOURCE_LEAD {{ background: #f6ead0; color: var(--ochre); border-color: #d7a64f; }}
.HYPOTHESIS {{ background: var(--inset); color: var(--muted); border-color: var(--line); }}
.CONTRADICTED {{ background: #f6e0dc; color: var(--crimson); border-color: #c96e6b; }}
.COLLECTION_FAILURE {{ background: #f2e2dc; color: var(--crimson); border-color: var(--line); }}
.AI_INFERRED {{ background: #e2ecef; color: var(--slate); border-color: #7ca5ae; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 16px; }}
.card {{
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px;
}}
.card b {{
  display: block;
  font-size: 24px;
  color: var(--ink);
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
  margin-bottom: 4px;
}}
.card span {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
table {{
  width: 100%;
  border-collapse: collapse;
  margin: 8px 0 24px;
  font-size: 12.5px;
  background: var(--surface);
  border: 1px solid var(--line);
}}
th, td {{
  text-align: left;
  padding: 8px 12px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}}
th {{
  background: var(--inset);
  color: var(--ink);
  font-weight: 700;
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}}
code {{
  background: var(--inset);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 1px 6px;
  font-size: 12px;
  color: var(--ink);
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
  word-break: break-all;
}}
.claim {{ margin: 6px 0 6px 16px; padding-left: 8px; border-left: 2px solid var(--line); }}
.artifact {{ color: var(--muted); font-size: 11px; }}
ul {{ margin: 8px 0; padding-left: 24px; }}
li {{ margin: 4px 0; }}
.muted {{ color: var(--muted); }}
.snippet {{
  background: var(--inset);
  border-left: 3px solid var(--accent);
  padding: 8px 12px;
  margin: 4px 0;
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 11.5px;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--ink-body);
}}
.ai-panel {{
  background: var(--surface);
  border: 1px solid #7ca5ae;
  border-left: 4px solid var(--slate);
  border-radius: 8px;
  padding: 16px;
  margin: 16px 0;
}}
.ai-item {{
  padding: 12px 0;
  border-bottom: 1px solid var(--line);
}}
.ai-item:last-child {{ border-bottom: none; padding-bottom: 0; }}
footer {{
  margin-top: 40px;
  padding-top: 16px;
  border-top: 1px solid var(--line);
  color: var(--muted);
  font-size: 11px;
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}}
@media print {{
  @page {{ margin: 14mm; }}
  body {{ background: #ffffff; color: #282828; }}
  main {{ max-width: none; padding: 0; }}
  .doc-header, .card, table, .ai-panel {{ background: #ffffff; border-color: #bdae93; break-inside: avoid; }}
  th, .snippet, code {{ background: #f9f5d7; color: #282828; border-color: #bdae93; }}
  h2 {{ color: #282828; border-color: #bdae93; break-after: avoid; }}
  tr {{ break-inside: avoid; }}
  .badge {{ border-color: #665c54; color: #282828 !important; background: #f2e5bc !important; }}
  a {{ color: #282828; }}
}}
</style></head><body><main>
""".replace("{{", "{").replace("}}", "}").replace("__TARGET__", _h(target_id))
    parts.append(head)
    parts.append('<div class="doc-header">')
    parts.append('<div class="kicker">Evidence-Cited Intelligence Dossier</div>')
    parts.append(f"<h1>Intelligence Dossier — <code>{_h(target_id)}</code></h1>")
    parts.append(
        f'<div class="meta">Generated {_h(generated_at)} · status '
        f'<b>{_h(investigation.get("status"))}</b> · stop reason '
        f'<code>{_h(investigation.get("stop_reason"))}</code> · '
        f'{_h(investigation.get("iterations"))} iterations · '
        f'{_h(investigation.get("tool_calls"))} tool calls</div></div>')

    # Summary cards.
    counters = [
        ("Entities", summary.get("entity_count", 0)),
        ("Claims", summary.get("claim_count", 0)),
        ("Relationships", summary.get("relationship_count", 0)),
        ("Evidence artifacts", summary.get("artifact_count", 0)),
        ("Contradictions", summary.get("contradiction_count", 0)),
    ]
    parts.append('<h2>1. Executive Summary</h2><div class="grid">')
    for label, value in counters:
        parts.append(f'<div class="card"><b>{_h(value)}</b><span>{_h(label)}</span></div>')
    parts.append("</div>")
    parts.append("<h3>Claim status distribution</h3><table><tr><th>Status</th><th>Claims</th></tr>")
    statuses = summary.get("claim_statuses") or {}
    for status in ("CONFIRMED", "CORROBORATED", "SINGLE_SOURCE_LEAD", "HYPOTHESIS",
                   "CONTRADICTED", "COLLECTION_FAILURE"):
        parts.append(f'<tr><td><span class="badge {status}">{status}</span></td>'
                     f'<td>{_h(statuses.get(status, 0))}</td></tr>')
    parts.append("</table>")
    objectives = summary.get("objectives") or []
    if objectives:
        parts.append("<h3>Core objectives</h3><ul>")
        for objective in objectives:
            achieved = "✅" if objective.get("achieved") else "◻"
            parts.append(f"<li>{achieved} {_h(objective.get('description'))} — "
                         f"<code>{_h(objective.get('status'))}</code></li>")
        parts.append("</ul>")

    # Findings.
    parts.append("<h2>2. Findings (evidence-cited)</h2>")
    entities = dossier.get("entities") or []
    if not entities:
        parts.append('<p class="muted">No entities were collected.</p>')
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entity in entities:
        grouped.setdefault(str(entity.get("type")), []).append(entity)
    for entity_type, group in grouped.items():
        parts.append(f"<h3>{_h(entity_type.replace('_', ' ').title())} ({len(group)})</h3>")
        for entity in group[:100]:
            attributes = entity.get("attributes") or {}
            attr_text = ""
            if attributes:
                attr_text = " — " + ", ".join(
                    f"<code>{_h(k, 60)}={_h(v, 80)}</code>"
                    for k, v in list(attributes.items())[:6])
            parts.append(f"<div><b>{_h(entity.get('value'))}</b>"
                         f"{attr_text}</div>")
            for claim in (entity.get("claims") or [])[:40]:
                if claim.get("predicate") == "IDENTIFIED_AS":
                    continue
                obj = claim.get("object") or {}
                if isinstance(obj.get("entity"), dict):
                    object_text = (f"{_h(obj['entity'].get('type'))}:"
                                   f"{_h(obj['entity'].get('value'))}")
                elif "literal" in obj:
                    object_text = f"<code>{_h(obj.get('literal'), 120)}</code>"
                else:
                    object_text = _h(obj.get("entity_id", "?"))
                artifacts = ", ".join(
                    f"<code>{_h(a.get('artifact_id'))}</code>"
                    for a in (claim.get("evidence") or [])[:4])
                parts.append(
                    f'<div class="claim">↳ <code>{_h(claim.get("predicate"))}</code> '
                    f'→ {object_text} <span class="badge {_h(claim.get("status"))}">'
                    f'{_h(claim.get("status"))}</span> '
                    f'<span class="muted">conf {_h(claim.get("confidence"))} · '
                    f'sources {_h(", ".join(claim.get("independent_sources") or []))}</span> '
                    f'<span class="artifact">{artifacts}</span></div>')

    # Relationships.
    parts.append("<h2>3. Relationship Map</h2>")
    relationships = dossier.get("relationships") or []
    if not relationships:
        parts.append('<p class="muted">No relationship claims recorded.</p>')
    else:
        parts.append("<table><tr><th>Subject</th><th>Predicate</th><th>Object</th>"
                     "<th>Status</th><th>Conf.</th><th>Evidence</th></tr>")
        for relationship in relationships[:250]:
            subject = relationship.get("subject") or {}
            obj = relationship.get("object") or {}
            cites = ", ".join(f"<code>{_h(a)}</code>"
                              for a in (relationship.get("artifact_ids") or [])[:3])
            parts.append(
                f"<tr><td>{_h(subject.get('value'), 120)}</td>"
                f"<td><code>{_h(relationship.get('predicate'))}</code></td>"
                f"<td>{_h(obj.get('value'), 120)}</td>"
                f'<td><span class="badge {_h(relationship.get("status"))}">'
                f'{_h(relationship.get("status"))}</span></td>'
                f"<td>{_h(relationship.get('confidence'))}</td>"
                f"<td>{cites}</td></tr>")
        parts.append("</table>")

    # Contradictions.
    parts.append("<h2>4. Contradictions</h2>")
    contradictions = dossier.get("contradictions") or []
    if not contradictions:
        parts.append('<p class="muted">No functional contradictions detected.</p>')
    for contradiction in contradictions:
        subject = contradiction.get("subject") or {}
        parts.append(f"<h3><code>{_h(contradiction.get('contradiction_id'))}</code> — "
                     f"{_h(subject.get('value', subject.get('entity_id')))} · "
                     f"<code>{_h(contradiction.get('predicate'))}</code></h3>")
        for label in ("claim_a", "claim_b"):
            claim = contradiction.get(label) or {}
            obj = claim.get("object") or {}
            value = obj.get("literal")
            if value is None and isinstance(obj.get("entity"), dict):
                value = obj["entity"].get("value")
            cites = ", ".join(f"<code>{_h(a)}</code>"
                              for a in (claim.get("artifact_ids") or [])[:3])
            parts.append(
                f'<div class="claim">{_h(label)}: <code>{_h(value, 160)}</code> '
                f'<span class="badge CONTRADICTED">CONTRADICTED</span> '
                f'<span class="artifact">{cites}</span></div>')

    # Gaps.
    gaps = dossier.get("collection_gaps") or {}
    parts.append("<h2>5. Collection Gaps, Dead Ends &amp; Unverified Hypotheses</h2>")
    parts.append("<h3>Failed collections</h3>")
    if gaps.get("failed_runs"):
        parts.append("<table><tr><th>Tool</th><th>Entity</th><th>Status</th>"
                     "<th>Error code</th><th>Artifact</th></tr>")
        for run in gaps["failed_runs"]:
            parts.append(f"<tr><td>{_h(run.get('tool_id'))}</td>"
                         f"<td><code>{_h(run.get('entity_id'), 120)}</code></td>"
                         f"<td>{_h(run.get('status'))}</td>"
                         f"<td>{_h(run.get('error_code'))}</td>"
                         f"<td><code>{_h(run.get('artifact_id'))}</code></td></tr>")
        parts.append("</table>")
    else:
        parts.append('<p class="muted">None.</p>')
    parts.append("<h3>Empty results (dead ends)</h3>")
    if gaps.get("empty_runs"):
        parts.append("<ul>")
        for run in gaps["empty_runs"]:
            parts.append(f"<li>{_h(run.get('tool_id'))} on "
                         f"<code>{_h(run.get('entity_id'), 120)}</code> — EMPTY</li>")
        parts.append("</ul>")
    else:
        parts.append('<p class="muted">None.</p>')
    parts.append("<h3>Unresolved hypotheses</h3>")
    if gaps.get("unresolved_hypotheses"):
        parts.append("<ul>")
        for hypothesis in gaps["unresolved_hypotheses"]:
            parts.append(f"<li><b>{_h(hypothesis.get('status'))}</b> · "
                         f"{_h(hypothesis.get('type'))} — "
                         f"{_h(hypothesis.get('question'))}</li>")
        parts.append("</ul>")
    else:
        parts.append('<p class="muted">All hypotheses were answered or ruled out.</p>')
    parts.append("<h3>Unresolved contradictions</h3>")
    unresolved = gaps.get("unresolved_contradictions") or []
    parts.append("<ul>" + "".join(f"<li><code>{_h(c)}</code></li>"
                                  for c in unresolved) + "</ul>"
                 if unresolved else '<p class="muted">None.</p>')

    # Provenance.
    parts.append("<h2>6. Provenance Appendix — Immutable Evidence Artifacts</h2>")
    artifacts = dossier.get("provenance_artifacts") or []
    if not artifacts:
        parts.append('<p class="muted">No artifacts recorded.</p>')
    else:
        parts.append("<table><tr><th>Artifact</th><th>Tool</th><th>Params hash</th>"
                     "<th>Timestamp</th><th>SHA-256</th><th>Parser</th>"
                     "<th>Status</th><th>Snippet</th></tr>")
        for artifact in artifacts[:300]:
            parts.append(
                f"<tr><td><code>{_h(artifact.get('artifact_id'))}</code></td>"
                f"<td>{_h(artifact.get('source_tool'))}</td>"
                f"<td><code>{_h(str(artifact.get('invocation_params_hash'))[:16])}</code></td>"
                f"<td>{_h(artifact.get('timestamp_utc'))}</td>"
                f"<td><code>{_h(str(artifact.get('raw_output_sha256'))[:20])}…</code></td>"
                f"<td>{_h(artifact.get('parser_version'))}</td>"
                f"<td>{_h(artifact.get('epistemic_status'))}</td>"
                f'<td><div class="snippet">{_h(artifact.get("raw_evidence_snippet"), 300)}'
                f"</div></td></tr>")
        parts.append("</table>")

    parts.append(
        "<h2>7. Method &amp; Epistemic Model</h2>"
        "<ul>"
        "<li><b>CONFIRMED</b> — ≥2 independent tools agree, confidence ≥0.90, direct sources.</li>"
        "<li><b>CORROBORATED</b> — ≥2 independent tools agree (confidence ≥0.85).</li>"
        "<li><b>SINGLE_SOURCE_LEAD</b> — one source; confidence capped at 0.65. A lead, not a fact.</li>"
        "<li><b>HYPOTHESIS</b> — planner-generated, no artifact yet.</li>"
        "<li><b>CONTRADICTED</b> — functional claims disagree; confidence 0.30; both values shown.</li>"
        "<li><b>COLLECTION_FAILURE</b> — run failed; recorded as a collection gap.</li>"
        "</ul><p class=\"muted\">External OSINT text is treated as untrusted: control "
        "characters are stripped and snippets are truncated. This dossier is generated "
        "by AI OSINT Hub v2.</p>"
    )

    ai_insights = dossier.get("ai_insights") or []
    if ai_insights:
        parts.append(
            "<h2>8. AI-Assisted Reflection &amp; Hypotheses "
            "(AI_INFERRED — Requires Verification)</h2>"
            '<div class="ai-panel">'
            '<p class="muted" style="margin-top:0">Advisory AI synthesis over '
            "quarantined evidence. All items carry <code>AI_INFERRED</code> provenance "
            "and require deterministic tool corroboration.</p>"
        )
        for insight in ai_insights:
            prov = insight.get("epistemic_provenance") or "AI_INFERRED"
            cites = ", ".join(
                f"<code>{_h(aid)}</code>"
                for aid in (insight.get("cited_artifact_ids") or [])[:12]
                if aid
            )
            parts.append('<div class="ai-item">')
            parts.append(
                f'<div><span class="badge AI_INFERRED">{_h(prov, 40)}</span> '
                f'<code>{_h(insight.get("kind") or "reflection", 60)}</code> '
                f'<span class="meta">{_h(insight.get("provider") or "unknown", 60)}/'
                f'{_h(insight.get("model") or "unknown", 80)} · '
                f'iter {_h(insight.get("iteration", 0))} · '
                f'{_h(insight.get("created_at") or "", 64)}</span></div>'
            )
            parts.append(
                f'<p style="margin:8px 0 4px">{_h(insight.get("summary") or "", 2000)}</p>'
            )
            if cites:
                parts.append(f'<div class="artifact">Cited artifacts: {cites}</div>')
            parts.append("</div>")
        parts.append("</div>")

    parts.append(f"<footer>{_h(DOSSIER_VERSION)} · generated {_h(generated_at)}</footer>")
    parts.append("</main></body></html>")
    return "".join(parts)


def write_report(store: ERKGStore, target_id: str, *, fmt: str = "md",
                 out_path: Optional[str] = None,
                 generated_at: Optional[str] = None) -> dict[str, Any]:
    """Build and optionally persist a dossier. Returns {format, content, path}."""
    dossier = build_dossier(store, target_id, generated_at=generated_at)
    if fmt == "json":
        content = render_json(dossier)
    elif fmt == "md":
        content = render_markdown(dossier)
    elif fmt == "html":
        content = render_html(dossier)
    else:
        raise ValueError(
            f"unsupported report format: {fmt!r} (expected 'md', 'json' or 'html')")
    path = None
    if out_path:
        from pathlib import Path

        destination = Path(out_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        path = str(destination.resolve())
    return {
        "target_id": target_id,
        "format": fmt,
        "content": content,
        "dossier": dossier,
        "path": path,
    }


__all__ = [
    "DOSSIER_VERSION",
    "build_dossier",
    "render_markdown",
    "render_json",
    "render_html",
    "write_report",
]
