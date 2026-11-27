"""FastAPI web workbench for the AI OSINT Hub (Phase 9).

A dependency-light server that exposes the
:class:`hub.service.InvestigationService` operations over REST + Server-Sent
Events and serves an embedded, dark-mode single-page workbench. No Node build
step is involved: the UI is one HTML document rendered by :func:`get_index`.

Endpoints
---------
GET  /                                    embedded SPA (Graph / Telemetry / Dossier)
GET  /api/tools                           capability health table
POST /api/doctor                          toolchain doctor (optional provisioning)
POST /api/investigations                  wait=True runs to a stop; else create + background run
GET  /api/investigations                  list known investigations
GET  /api/investigations/{id}             full ERKG payload for the workbench
GET  /api/investigations/{id}/stream      SSE snapshot/iteration/ledger/graph_delta/done
POST /api/investigations/{id}/step        run exactly one Plan/Execute/Normalize cycle
GET  /api/investigations/{id}/report      md | json | html evidence-cited dossier export

Security: external OSINT strings returned by this API are sanitized
(:func:`hub.security.quarantine.sanitize_untrusted`) and the browser only ever
inserts them with ``textContent`` — never ``innerHTML``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import inspect
import json
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from hub.erkg.graph import GraphView
from hub.investigation.engine import EngineError
from hub.models import EpistemicStatus, ScopeConfig
from hub.security.quarantine import sanitize_untrusted
from hub.service import InvestigationService

APP_TITLE = "AI OSINT Hub Intelligence Workbench"
APP_VERSION = "2.0.0"

STREAM_POLL_INTERVAL_SEC = 0.4
#: SSE comment heartbeat — 2 s keeps proxies/browsers from buffering/aborting.
STREAM_KEEPALIVE_SEC = 2.0
STREAM_MAX_SECONDS = 120.0
STREAM_DEADLINE_BUFFER_SEC = 30.0
TERMINAL_STATUSES = {"completed", "terminated", "failed"}
REPORT_FORMATS = {"md", "json", "html"}

_STATUS_ORDER = {
    EpistemicStatus.CONFIRMED: 0,
    EpistemicStatus.CORROBORATED: 1,
    EpistemicStatus.SINGLE_SOURCE_LEAD: 2,
    EpistemicStatus.HYPOTHESIS: 3,
    EpistemicStatus.CONTRADICTED: 4,
    EpistemicStatus.COLLECTION_FAILURE: 5,
}


# ════════════════════════════════════════════════════════════════════════
# Request models
# ════════════════════════════════════════════════════════════════════════

class InvestigateRequest(BaseModel):
    """Intake payload for a new investigation (free text + structured seeds)."""

    raw_input: str = ""
    name: Optional[str] = None
    usernames: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    phones: list[str] = Field(default_factory=list)
    org: Optional[str] = None
    location: Optional[str] = None
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    allow_domains: list[str] = Field(default_factory=list)
    allow_active_recon: bool = False
    max_iterations: int = Field(default=16, ge=1, le=500)
    max_tool_calls: int = Field(default=20, ge=1, le=1000)
    wall_clock_timeout_sec: int = Field(default=600, ge=5, le=86400)
    min_pivot_threshold: float = Field(default=0.12, ge=0.0, le=1.0)
    wait: bool = False


class StepRequest(BaseModel):
    """Optional explicit pivot selection for one engine step."""

    pivot_id: Optional[str] = None


class DoctorRequest(BaseModel):
    """Toolchain doctor options."""

    provision: bool = False


class CredentialsRequest(BaseModel):
    """API key submission for the Web UI API Keys drawer (never returned raw)."""

    github_token: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    censys_token: Optional[str] = None
    hunter_api_key: Optional[str] = None


class StepBatchRequest(BaseModel):
    """Bounded parallel pivot wave request."""

    max_pivots: int = Field(default=3, ge=1, le=8)


class AIConfigRequest(BaseModel):
    """AI & Vision configuration payload (keys are stored masked-only on read)."""

    model_config = ConfigDict(extra="allow")

    enabled: Optional[bool] = None
    preset: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    vision_model: Optional[str] = None
    embedding_model: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    ollama_host: Optional[str] = None
    lmstudio_base_url: Optional[str] = None
    gemini_api_key: Optional[str] = None
    deepseek_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    openai_base_url: Optional[str] = None
    num_ctx: Optional[int] = None
    temperature: Optional[float] = None
    keep_alive: Optional[str] = None
    vision_enabled: Optional[bool] = None
    reflection_enabled: Optional[bool] = None


class DemoRequest(BaseModel):
    """Optional parameters for seeding the synthetic demo case."""

    overwrite: bool = True


class ReflectRequest(BaseModel):
    """Optional provider override for case AI reflection."""

    provider_override: Optional[str] = None


class MediaAnalyzeRequest(BaseModel):
    """Media forensics & optional VLM extraction request."""

    url: str = Field(..., min_length=1, max_length=2048)
    use_vlm: bool = False
    target_id: Optional[str] = None


# ════════════════════════════════════════════════════════════════════════
# Small helpers (sanitization + serialization)
# ════════════════════════════════════════════════════════════════════════

def _text(value: Any, max_len: int = 2000) -> str:
    """Sanitize one untrusted external string to inert plain text."""
    if value is None:
        return ""
    try:
        return sanitize_untrusted(value, max_len=max_len)
    except Exception:  # noqa: BLE001 - display text must never crash a response
        return str(value)[:max_len]


def _value(value: Any, max_len: int = 500) -> Any:
    """Recursively sanitize JSON-ish values that can carry tool output."""
    if isinstance(value, str):
        return _text(value, max_len)
    if isinstance(value, list):
        return [_value(item, max_len) for item in value]
    if isinstance(value, dict):
        return {_text(key, max_len): _value(item, max_len)
                for key, item in value.items()}
    return value


def _seed_dict(request: InvestigateRequest) -> Optional[dict[str, Any]]:
    """Build the structured-seed mapping accepted by the service layer."""
    seeds: dict[str, Any] = {
        "name": request.name,
        "usernames": list(request.usernames),
        "emails": list(request.emails),
        "domains": list(request.domains),
        "phones": list(request.phones),
        "organizations": [request.org] if request.org else [],
        "locations": [request.location] if request.location else [],
        "urls": list(request.urls),
        "ips": list(request.ips),
    }
    cleaned = {key: value for key, value in seeds.items()
               if value not in (None, "", [])}
    return cleaned or None


def _scope_dict(request: InvestigateRequest) -> Optional[dict[str, Any]]:
    """Derive a code-enforced ScopeConfig override from intake controls."""
    scope: dict[str, Any] = {}
    if request.allow_domains:
        scope["allow_domains"] = [domain.strip() for domain in request.allow_domains
                                  if domain.strip()]
    if request.allow_active_recon:
        scope["allow_active_recon"] = True
    return scope or None


def _budget_overrides(request: InvestigateRequest) -> dict[str, Any]:
    return {
        "max_iterations": request.max_iterations,
        "max_tool_calls": request.max_tool_calls,
        "wall_clock_timeout_sec": request.wall_clock_timeout_sec,
        "min_pivot_threshold": request.min_pivot_threshold,
    }


def _call(func, *args: Any, **kwargs: Any) -> Any:
    """Call ``func`` keeping forward-compatible optional kwargs only if accepted."""
    try:
        parameters = inspect.signature(func).parameters
    except (TypeError, ValueError):  # pragma: no cover - builtins only
        return func(*args, **kwargs)
    if any(parameter.kind is inspect.Parameter.VAR_KEYWORD
           for parameter in parameters.values()):
        return func(*args, **kwargs)
    supported = {key: value for key, value in kwargs.items() if key in parameters}
    return func(*args, **supported)


async def _call_maybe_async(func, *args: Any, **kwargs: Any) -> Any:
    """Invoke sync or async function keeping supported kwargs only."""
    result = _call(func, *args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


def _import_ai_layer() -> Any:
    """Lazily import hub.ai so web server starts cleanly if AI package is absent."""
    try:
        from hub import ai as ai_layer

        return ai_layer
    except ImportError:
        return None


def _fallback_analytics(service: InvestigationService, target_id: str,
                        source_id: Optional[str] = None,
                        dest_id: Optional[str] = None) -> dict[str, Any]:
    """Lightweight deterministic graph analytics fallback if service.analytics is absent."""
    payload = build_investigation_payload(service, target_id)
    graph = payload.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    adj: dict[str, set[str]] = {n["id"]: set() for n in nodes}
    edge_lookup: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in edges:
        src, dst = edge.get("subject"), edge.get("object")
        if src in adj and dst in adj and src != dst:
            adj[src].add(dst)
            adj[dst].add(src)
            edge_lookup.setdefault((src, dst), edge)
            edge_lookup.setdefault((dst, src), edge)
    n_count = max(1, len(nodes) - 1)
    degree_centrality = {
        nid: round(len(neighbors) / n_count, 4) for nid, neighbors in adj.items()
    }
    visited: set[str] = set()
    clusters: list[dict[str, Any]] = []
    for idx, node in enumerate(nodes):
        nid = node["id"]
        if nid in visited:
            continue
        comp: list[str] = []
        queue = deque([nid])
        visited.add(nid)
        while queue:
            cur = queue.popleft()
            comp.append(cur)
            for nxt in sorted(adj.get(cur, ())):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        clusters.append({"cluster_id": f"c{len(clusters) + 1}", "node_ids": comp, "size": len(comp)})

    shortest: Optional[dict[str, Any]] = None
    if source_id and dest_id and source_id in adj and dest_id in adj:
        parent: dict[str, Optional[str]] = {source_id: None}
        q = deque([source_id])
        while q:
            cur = q.popleft()
            if cur == dest_id:
                break
            for nxt in sorted(adj.get(cur, ())):
                if nxt not in parent:
                    parent[nxt] = cur
                    q.append(nxt)
        if dest_id in parent:
            path_ids: list[str] = []
            cur_id: Optional[str] = dest_id
            while cur_id is not None:
                path_ids.append(cur_id)
                cur_id = parent[cur_id]
            path_ids.reverse()
            path_edges = []
            for a, b in zip(path_ids, path_ids[1:]):
                e = edge_lookup.get((a, b)) or {}
                path_edges.append({
                    "claim_id": e.get("id"),
                    "subject": a,
                    "object": b,
                    "predicate": e.get("predicate"),
                    "status": e.get("status"),
                    "artifact_ids": e.get("artifact_ids") or [],
                })
            shortest = {"found": True, "node_ids": path_ids, "edges": path_edges, "hops": len(path_edges)}
        else:
            shortest = {"found": False, "node_ids": [], "edges": [], "hops": 0}

    return {
        "status": "ok",
        "target_id": target_id,
        "centrality": {"degree": degree_centrality, "betweenness": {}},
        "clusters": clusters,
        "bridges": [],
        "phash_correlations": [],
        "shortest_path": shortest,
    }


def _fallback_timeline(service: InvestigationService, target_id: str) -> dict[str, Any]:
    """Chronological timeline fallback when service.timeline is absent."""
    payload = build_investigation_payload(service, target_id)
    events: list[dict[str, Any]] = []
    inv = payload.get("investigation") or {}
    if inv.get("created_at"):
        events.append({
            "timestamp_utc": inv["created_at"],
            "kind": "investigation_created",
            "title": f"Investigation initialized ({target_id})",
            "detail": inv.get("raw_input", ""),
        })
    for aid, art in (payload.get("artifacts") or {}).items():
        events.append({
            "timestamp_utc": art.get("timestamp_utc", ""),
            "kind": "artifact",
            "title": f"{art.get('source_tool', 'tool')} artifact",
            "artifact_id": aid,
            "status": art.get("epistemic_status"),
            "detail": art.get("raw_evidence_snippet", "")[:160],
        })
    for entry in payload.get("ledger") or []:
        events.append({
            "timestamp_utc": entry.get("run_at", ""),
            "kind": "ledger",
            "title": f"{entry.get('tool_id', 'tool')} ({entry.get('status', '')})",
            "entity_id": entry.get("entity_id"),
            "artifact_id": entry.get("artifact_id"),
            "detail": entry.get("error_message") or f"{entry.get('duration_ms', 0)}ms",
        })
    for ins in payload.get("ai_insights") or []:
        events.append({
            "timestamp_utc": ins.get("created_at", ""),
            "kind": "ai_insight",
            "title": f"AI {ins.get('kind', 'reflection')} ({ins.get('epistemic_provenance', 'AI_INFERRED')})",
            "detail": ins.get("summary", "")[:200],
        })
    events.sort(key=lambda item: str(item.get("timestamp_utc") or ""))
    return {"status": "ok", "target_id": target_id, "events": events}


def _fallback_diff(service: InvestigationService, id_a: str, id_b: str) -> dict[str, Any]:
    """Two-case entity/status diff fallback when service.diff is absent."""
    a = build_investigation_payload(service, id_a)
    b = build_investigation_payload(service, id_b)
    a_map = {(e["type"], e["value"]): e for e in a.get("entities") or []}
    b_map = {(e["type"], e["value"]): e for e in b.get("entities") or []}
    added = [b_map[k] for k in sorted(set(b_map) - set(a_map))]
    removed = [a_map[k] for k in sorted(set(a_map) - set(b_map))]
    return {
        "status": "ok",
        "target_id_a": id_a,
        "target_id_b": id_b,
        "added_entities": added,
        "removed_entities": removed,
        "status_changes": [],
        "new_contradictions": [],
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "common_count": len(set(a_map) & set(b_map)),
        },
    }


def _error_payload(message: str) -> dict[str, Any]:
    return {"status": "error", "errors": [message]}


# ════════════════════════════════════════════════════════════════════════
# ERKG payload builders (exposed for tests / other transports)
# ════════════════════════════════════════════════════════════════════════

def _best_status(statuses: list[EpistemicStatus]) -> str:
    """Most epistemically strong status among a set of claims."""
    if not statuses:
        return EpistemicStatus.SINGLE_SOURCE_LEAD.value
    return min(statuses, key=lambda status: _STATUS_ORDER.get(status, 9)).value


def _claim_object_text(claim, entity_index: dict[str, Any]) -> str:
    if claim.object_id is not None:
        entity = entity_index.get(claim.object_id)
        if entity is not None:
            return f"{entity.type.value}:{entity.canonical_value}"
        return claim.object_id
    try:
        text = json.dumps(claim.object_literal, default=str, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        text = str(claim.object_literal)
    return _text(text, 200)


def _entity_payload(entity) -> dict[str, Any]:
    return {
        "entity_id": entity.entity_id,
        "type": entity.type.value,
        "value": _text(entity.canonical_value),
        "display_value": _text(entity.display_value, 500),
        "aliases": [_text(alias, 200) for alias in entity.aliases[:10]],
        "first_seen": entity.first_seen,
        "last_seen": entity.last_seen,
    }


def _claim_payload(claim) -> dict[str, Any]:
    payload = claim.model_dump(mode="json")
    payload["predicate"] = _text(claim.predicate, 200)
    if claim.object_literal is not None:
        payload["object_literal"] = _value(claim.object_literal, 300)
    return payload


def _artifact_payload(artifact) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "source_tool": _text(artifact.source_tool, 80),
        "timestamp_utc": artifact.timestamp_utc,
        "invocation_params_hash": artifact.invocation_params_hash,
        "raw_output_sha256": artifact.raw_output_sha256,
        "raw_evidence_snippet": _text(artifact.raw_evidence_snippet, 4000),
        "epistemic_status": artifact.epistemic_status.value,
        "confidence": round(float(artifact.confidence), 3),
        "parser_version": _text(artifact.parser_version, 40),
        "raw_output_path": artifact.raw_output_path,
        "stdout_bytes": artifact.stdout_bytes,
        "truncated": bool(artifact.truncated),
    }


def _ledger_payload(record) -> dict[str, Any]:
    return {
        "tool_id": _text(record.tool_id, 80),
        "entity_id": record.entity_id,
        "status": record.status.value,
        "error_code": record.error_code.value if record.error_code else None,
        "artifact_id": record.artifact_id,
        "run_at": record.run_at,
        "duration_ms": record.duration_ms,
        "error_message": _text(record.error_message, 500),
    }


def _hypothesis_payload(hypothesis) -> dict[str, Any]:
    return {
        "hypothesis_id": hypothesis.hypothesis_id,
        "type": hypothesis.hypothesis_type.value,
        "question": _text(hypothesis.question, 500),
        "status": hypothesis.status.value,
        "target_entity_id": hypothesis.target_entity_id,
        "proposed_tool_ids": [_text(tool, 80) for tool in hypothesis.proposed_tool_ids],
        "rationale": _text(hypothesis.rationale, 500),
        "created_at": hypothesis.created_at,
        "closing_note": _text(hypothesis.closing_note, 300),
    }


def _contradiction_payload(contradiction,
                           entity_index: dict[str, Any]) -> dict[str, Any]:
    subject = entity_index.get(contradiction.subject_id)
    return {
        "contradiction_id": contradiction.contradiction_id,
        "subject_id": contradiction.subject_id,
        "subject": (f"{subject.type.value}:{subject.canonical_value}"
                    if subject is not None else contradiction.subject_id),
        "predicate": _text(contradiction.predicate, 200),
        "claim_a": contradiction.claim_a,
        "claim_b": contradiction.claim_b,
        "created_at": contradiction.created_at,
        "resolved": bool(contradiction.resolved),
    }


def _investigation_payload(investigation) -> dict[str, Any]:
    payload = investigation.model_dump(mode="json")
    payload["raw_input"] = _text(investigation.raw_input, 2000)
    if payload.get("stop_reason"):
        payload["stop_reason"] = _text(investigation.stop_reason, 200)
    return payload


def _pivot_payload(pivot) -> dict[str, Any]:
    return {
        "pivot_id": pivot.pivot_id,
        "entity_id": pivot.entity_id,
        "tool_id": _text(pivot.tool_id, 80),
        "params": _value(pivot.params, 300),
        "score": round(float(pivot.score), 4),
        "rationale": _text(pivot.rationale, 500),
        "hypothesis_id": pivot.hypothesis_id,
        "score_breakdown": pivot.score_breakdown(),
    }


def build_workbench_graph(entities: list[Any], claims: list[Any],
                          entity_index: dict[str, Any]) -> dict[str, Any]:
    """Build the SVG graph contract: nodes carry claims, edges are claim edges."""
    claims_by_subject: dict[str, list[Any]] = {entity.entity_id: []
                                               for entity in entities}
    for claim in claims:
        claims_by_subject.setdefault(claim.subject_id, []).append(claim)

    nodes = []
    for entity in entities:
        subject_claims = claims_by_subject.get(entity.entity_id, [])
        status = _best_status([claim.status for claim in subject_claims])
        confidence = round(max((float(claim.confidence)
                                for claim in subject_claims), default=0.0), 3)
        evidence_count = sum(len(claim.artifact_ids) for claim in subject_claims)
        nodes.append({
            "id": entity.entity_id,
            "type": entity.type.value,
            "value": _text(entity.canonical_value, 300),
            "status": status,
            "confidence": confidence,
            "evidence_count": evidence_count,
            # Unverified planner permutations are hidden by default in the UI.
            "is_hypothesis": status == EpistemicStatus.HYPOTHESIS.value,
            "claims": [{
                "claim_id": claim.claim_id,
                "predicate": _text(claim.predicate, 200),
                "object": _claim_object_text(claim, entity_index),
                "status": claim.status.value,
                "confidence": round(float(claim.confidence), 3),
                "artifact_ids": list(claim.artifact_ids),
            } for claim in subject_claims],
        })

    edges = []
    for claim in claims:
        if claim.object_id is None:
            continue
        if claim.subject_id not in entity_index or claim.object_id not in entity_index:
            continue
        edges.append({
            "id": claim.claim_id,
            "subject": claim.subject_id,
            "predicate": _text(claim.predicate, 200),
            "object": claim.object_id,
            "status": claim.status.value,
            "confidence": round(float(claim.confidence), 3),
            "hypothesis": claim.status == EpistemicStatus.HYPOTHESIS,
            "artifact_ids": list(claim.artifact_ids),
        })
    return {"nodes": nodes, "edges": edges}


def build_investigation_payload(service: InvestigationService,
                                target_id: str) -> dict[str, Any]:
    """Assemble the workbench payload for one investigation.

    Raises ``LookupError`` when the investigation is unknown; every other store
    failure is left to the caller so the API can answer with a clean error dict.
    """
    engine = service.engine()
    try:
        store = engine.open_store(target_id)
    except EngineError as exc:
        raise LookupError(str(exc)) from exc
    try:
        investigation = store.get_investigation(target_id)
        if investigation is None:
            raise LookupError(f"investigation not found: {target_id}")
        graph_view = GraphView(store, target_id, investigation.seed_entity_ids)
        entities = list(graph_view.entities.values())
        claims = list(graph_view.claims)
        entity_index = graph_view.entities
        artifacts = [_artifact_payload(artifact)
                     for artifact in store.list_artifacts(target_id)]
        ai_insights: list[dict[str, Any]] = []
        if hasattr(store, "list_ai_insights"):
            try:
                ai_insights = _value(store.list_ai_insights(target_id) or [], 1500)
            except Exception:  # noqa: BLE001 - optional AI insights
                ai_insights = []
        payload: dict[str, Any] = {
            "target_id": target_id,
            "investigation": _investigation_payload(investigation),
            "stats": store.stats(target_id),
            "graph_summary": graph_view.summary(),
            "entities": [_entity_payload(entity) for entity in entities],
            "claims": [_claim_payload(claim) for claim in claims],
            "contradictions": [_contradiction_payload(contradiction, entity_index)
                               for contradiction in store.list_contradictions(target_id)],
            "hypotheses": [_hypothesis_payload(hypothesis)
                           for hypothesis in store.list_hypotheses(target_id)],
            "ledger": [_ledger_payload(record)
                       for record in store.list_ledger(target_id)],
            "graph": build_workbench_graph(entities, claims, entity_index),
            "artifacts": {artifact["artifact_id"]: artifact
                          for artifact in artifacts},
            "ai_insights": ai_insights,
        }
    finally:
        store.close()

    try:
        preview = engine.preview(target_id)
        payload["pivots"] = [_pivot_payload(pivot)
                             for pivot in preview.get("next_pivots", [])]
        payload["objectives"] = preview.get("objectives", [])
    except Exception:  # noqa: BLE001 - pivots are advisory for the UI
        payload["pivots"] = []
        payload["objectives"] = []
    return payload


# ════════════════════════════════════════════════════════════════════════
# Server-Sent Events
# ════════════════════════════════════════════════════════════════════════

def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"


def _probe_stream_state(service: InvestigationService,
                        target_id: str) -> Optional[dict[str, Any]]:
    """Cheap read model polled by the SSE generator (direct store access)."""
    try:
        store = service.engine().open_store(target_id)
    except EngineError:
        return None
    try:
        investigation = store.get_investigation(target_id)
        if investigation is None:
            return None
        stats = store.stats(target_id)
        ledger = [_ledger_payload(record) for record in store.list_ledger(target_id)]
        return {
            "investigation": _investigation_payload(investigation),
            "stats": stats,
            "ledger": ledger,
            "counts": {
                "entities": stats.get("entities", 0),
                "claims": stats.get("claims", 0),
                "artifacts": stats.get("artifacts", 0),
            },
        }
    finally:
        store.close()


async def iter_investigation_events(
        service: InvestigationService, target_id: str, *,
        poll_interval: float = STREAM_POLL_INTERVAL_SEC,
        max_seconds: float = STREAM_MAX_SECONDS,
        keepalive_interval: float = STREAM_KEEPALIVE_SEC,
) -> AsyncIterator[str]:
    """Yield SSE frames until the investigation stops, errors or times out."""
    started = time.monotonic()
    last_keepalive = started
    previous: Optional[tuple[int, dict[str, int], int]] = None

    while True:
        elapsed = time.monotonic() - started
        state = _probe_stream_state(service, target_id)
        if state is None:
            yield _sse("error", {"target_id": target_id,
                                 "error": f"investigation not found: {target_id}"})
            return
        investigation = state["investigation"]
        stats = state["stats"]
        ledger = state["ledger"]
        counts = state["counts"]
        iteration = int(investigation.get("iteration_count", 0))
        status = str(investigation.get("status", ""))

        if previous is None:
            yield _sse("snapshot", {
                "target_id": target_id,
                "investigation": investigation,
                "stats": stats,
                "graph_summary": {
                    "nodes": counts["entities"],
                    "claims": counts["claims"],
                    "artifacts": counts["artifacts"],
                    "ledger_entries": len(ledger),
                },
            })
        else:
            previous_iteration, previous_counts, previous_ledger = previous
            if iteration != previous_iteration:
                yield _sse("iteration", {
                    "target_id": target_id,
                    "iteration": iteration,
                    "status": status,
                    "stats": stats,
                })
            if len(ledger) > previous_ledger:
                yield _sse("ledger", {
                    "target_id": target_id,
                    "entries": ledger[previous_ledger:],
                    "total": len(ledger),
                })
            if counts != previous_counts:
                yield _sse("graph_delta", {
                    "target_id": target_id,
                    "counts": counts,
                    "previous": previous_counts,
                    "delta": {key: counts[key] - previous_counts.get(key, 0)
                              for key in counts},
                })

        if status in TERMINAL_STATUSES:
            yield _sse("done", {
                "target_id": target_id,
                "status": status,
                "stop_reason": investigation.get("stop_reason"),
                "iterations": iteration,
                "tool_calls": investigation.get("tool_calls", 0),
                "stats": stats,
                "ledger": [{"tool_id": entry["tool_id"],
                            "status": entry["status"]} for entry in ledger],
            })
            return
        if elapsed >= max_seconds:
            yield _sse("timeout", {
                "target_id": target_id,
                "seconds": round(elapsed, 1),
                "note": "stream deadline reached; investigation may still be active",
            })
            return
        if time.monotonic() - last_keepalive >= keepalive_interval:
            last_keepalive = time.monotonic()
            yield ": keepalive\n\n"

        previous = (iteration, counts, len(ledger))
        await asyncio.sleep(poll_interval)


# ════════════════════════════════════════════════════════════════════════
# Background execution
# ════════════════════════════════════════════════════════════════════════

def _resume_sync(service: InvestigationService, target_id: str) -> Any:
    """Run the engine loop from committed state (called in a worker thread)."""
    return service.resume(target_id)


def _mark_background_failure(service: InvestigationService, target_id: str,
                             exc: BaseException) -> None:
    """Make a crashed background run observable instead of silently ACTIVE."""
    try:
        from hub.models import RunStatus

        store = service.engine().open_store(target_id)
        try:
            store.finish_investigation(
                target_id, RunStatus.FAILED,
                f"background_error: {type(exc).__name__}: {exc}"[:500])
        finally:
            store.close()
    except Exception:  # noqa: BLE001 - best effort only
        pass


async def _run_investigation(service: InvestigationService,
                             target_id: str) -> None:
    """Background task: resume the autonomous loop without blocking the event loop."""
    try:
        result = await asyncio.to_thread(_resume_sync, service, target_id)
        if isinstance(result, dict) and result.get("status") == "error":
            raise RuntimeError("; ".join(str(error) for error in
                                         result.get("errors", ["resume failed"])))
    except Exception as exc:  # noqa: BLE001 - must never leave the run ACTIVE forever
        _mark_background_failure(service, target_id, exc)


# ════════════════════════════════════════════════════════════════════════
# App factory
# ════════════════════════════════════════════════════════════════════════

def create_app(service: Optional[InvestigationService] = None) -> FastAPI:
    """Build the FastAPI application around one service instance."""
    app = FastAPI(title=APP_TITLE, version=APP_VERSION,
                  description="AI OSINT Hub REST + SSE workbench API")
    app.state.service = service or InvestigationService()
    app.state.tasks = set()
    app.state.background_errors = {}
    try:
        from hub.credentials import load_credentials

        load_credentials(force=True, sync_config=True)
    except Exception:  # noqa: BLE001 - credential loading must not block the UI
        pass

    svc: InvestigationService = app.state.service

    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ── UI ─────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def get_index() -> HTMLResponse:
        return HTMLResponse(content=WORKBENCH_HTML)

    # ── capability / toolchain endpoints ───────────────────────────

    @app.get("/api/tools")
    def get_tools(refresh: bool = False) -> Any:
        try:
            result = svc.tools(refresh=refresh)
        except Exception as exc:  # noqa: BLE001 - health checks must not 500 the UI
            return JSONResponse(_error_payload(
                f"tools check failed: {type(exc).__name__}: {exc}"), status_code=500)
        return JSONResponse(jsonable_encoder({
            "status": "ok",
            "tools": result.get("tools", []),
            "available": result.get("available", 0),
            "total": result.get("total", 0),
            "checked_at": result.get("checked_at"),
        }))

    @app.post("/api/doctor")
    def run_doctor(payload: Optional[DoctorRequest] = Body(default=None)) -> Any:
        provision = bool(payload.provision) if payload is not None else False
        try:
            result = svc.doctor(provision=provision)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(_error_payload(
                f"doctor failed: {type(exc).__name__}: {exc}"), status_code=500)
        return JSONResponse(jsonable_encoder(result))

    # ── credentials (API Keys drawer) ──────────────────────────────

    @app.get("/api/credentials")
    def get_credentials() -> Any:
        try:
            result = svc.credentials()
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(_error_payload(
                f"credentials read failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(result))

    @app.post("/api/credentials")
    def post_credentials(payload: CredentialsRequest) -> Any:
        data = {key: value for key, value in payload.model_dump().items()
                if value is not None and str(value).strip()}
        if not data:
            raise HTTPException(status_code=400,
                                detail="no credential values supplied")
        try:
            result = svc.set_credentials(data)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(_error_payload(
                f"credential save failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(result))

    # ── investigations: start / list ───────────────────────────────

    @app.post("/api/investigations")
    async def post_investigation(request: InvestigateRequest) -> Any:
        raw_input = (request.raw_input or "").strip()
        seeds = _seed_dict(request)
        scope = _scope_dict(request)
        overrides = _budget_overrides(request)
        if scope:
            overrides["scope"] = scope

        if request.wait:
            kwargs = {**overrides,
                      "include_report": True,
                      "report_format": "md",
                      "structured_seeds": seeds}
            try:
                result = await asyncio.to_thread(
                    _call, svc.investigate, raw_input, **kwargs)
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(
                    status_code=500,
                    detail=f"investigation failed: {type(exc).__name__}: {exc}")
            if not isinstance(result, dict) or result.get("status") == "error":
                raise HTTPException(
                    status_code=400,
                    detail=(result.get("errors") if isinstance(result, dict) else None)
                    or ["investigation rejected"])
            return JSONResponse(jsonable_encoder(result))

        create_kwargs: dict[str, Any] = {"overrides": overrides,
                                         "structured_seeds": seeds}
        try:
            created = await asyncio.to_thread(
                _call, svc.create, raw_input, **create_kwargs)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=500,
                detail=f"failed to create investigation: {type(exc).__name__}: {exc}")
        target_id = (created or {}).get("target_id") if isinstance(created, dict) else None
        if not target_id:
            raise HTTPException(
                status_code=400,
                detail=(created.get("errors") if isinstance(created, dict) else None)
                or ["failed to initialize investigation"])
        task = asyncio.create_task(_run_investigation(svc, target_id))
        app.state.tasks.add(task)
        task.add_done_callback(app.state.tasks.discard)
        return JSONResponse({
            "status": "started",
            "target_id": target_id,
            "state_path": created.get("state_path"),
            "stats": created.get("stats"),
            "candidate_count": created.get("candidate_count"),
        })

    @app.get("/api/investigations")
    def list_investigations() -> Any:
        try:
            result = svc.list_investigations()
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                {**_error_payload(f"list failed: {type(exc).__name__}: {exc}"),
                 "count": 0, "investigations": []},
                status_code=500)
        return JSONResponse(jsonable_encoder(result))

    # ── investigations: state / stream / step / report ─────────────

    @app.get("/api/investigations/{target_id}")
    def get_investigation(target_id: str) -> Any:
        try:
            payload = build_investigation_payload(svc, target_id)
        except LookupError:
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        except Exception as exc:  # noqa: BLE001 - never crash on store errors
            return JSONResponse(
                _error_payload(f"failed to read investigation: "
                               f"{type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(payload))

    @app.get("/api/investigations/{target_id}/stream")
    def stream_investigation(target_id: str) -> StreamingResponse:
        if not _investigation_exists(svc, target_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        return StreamingResponse(
            iter_investigation_events(
                svc, target_id,
                max_seconds=_stream_deadline_seconds(svc, target_id)),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/investigations/{target_id}/step")
    def step_investigation(target_id: str,
                           payload: Optional[StepRequest] = Body(default=None)) -> Any:
        pivot_id = payload.pivot_id if payload is not None else None
        try:
            result = svc.step(target_id, pivot_id=pivot_id)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"step failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if isinstance(result, dict) and result.get("status") == "error":
            message = "; ".join(str(error) for error in result.get("errors", []))
            if "not found" in message:
                raise HTTPException(status_code=404,
                                    detail=f"investigation not found: {target_id}")
            return JSONResponse(jsonable_encoder(result), status_code=400)
        return JSONResponse(jsonable_encoder(result))

    @app.get("/api/investigations/{target_id}/report")
    def get_report(target_id: str, format: str = "md") -> Any:
        report_format = (format or "md").strip().lower()
        if report_format not in REPORT_FORMATS:
            raise HTTPException(status_code=400,
                                detail=f"unsupported report format: {format!r}")
        try:
            result = svc.report(target_id, fmt=report_format)
        except EngineError:
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"report failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if not isinstance(result, dict) or result.get("status") == "error":
            message = "; ".join(str(error) for error in
                                (result.get("errors", []) if isinstance(result, dict)
                                 else ["report failed"]))
            if "not found" in message:
                raise HTTPException(status_code=404,
                                    detail=f"investigation not found: {target_id}")
            return JSONResponse(_error_payload(message), status_code=500)

        content = result.get("content") or ""
        if report_format == "html":
            return HTMLResponse(content=_ensure_html_document(content),
                                headers={"Content-Security-Policy":
                                         "default-src 'none'; style-src 'unsafe-inline'"})
        if report_format == "json":
            try:
                parsed = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                parsed = result.get("dossier") or {
                    "target_id": target_id, "content": content}
            return JSONResponse(jsonable_encoder(parsed))
        return PlainTextResponse(content=content, media_type="text/markdown")

    # ── graph analytics / timeline / diff / parallel pivots ────────

    @app.get("/api/investigations/{target_id}/analytics")
    async def get_analytics(target_id: str,
                            source_id: Optional[str] = None,
                            dest_id: Optional[str] = None) -> Any:
        if not _investigation_exists(svc, target_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        try:
            if hasattr(svc, "analytics"):
                result = await _call_maybe_async(
                    svc.analytics, target_id,
                    source_id=source_id, dest_id=dest_id)
            else:
                result = _fallback_analytics(
                    svc, target_id, source_id=source_id, dest_id=dest_id)
        except LookupError:
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"analytics failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if isinstance(result, dict) and result.get("status") == "error":
            message = "; ".join(str(err) for err in result.get("errors", []))
            if "not found" in message.lower():
                raise HTTPException(status_code=404, detail=message)
            return JSONResponse(jsonable_encoder(result), status_code=400)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    @app.get("/api/investigations/{target_id}/timeline")
    async def get_timeline(target_id: str) -> Any:
        if not _investigation_exists(svc, target_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        try:
            if hasattr(svc, "timeline"):
                result = await _call_maybe_async(svc.timeline, target_id)
            else:
                result = _fallback_timeline(svc, target_id)
        except LookupError:
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"timeline failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if isinstance(result, dict) and result.get("status") == "error":
            message = "; ".join(str(err) for err in result.get("errors", []))
            if "not found" in message.lower():
                raise HTTPException(status_code=404, detail=message)
            return JSONResponse(jsonable_encoder(result), status_code=400)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    @app.get("/api/investigations/{target_id}/diff/{other_id}")
    async def get_diff(target_id: str, other_id: str) -> Any:
        if not _investigation_exists(svc, target_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        if not _investigation_exists(svc, other_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {other_id}")
        try:
            if hasattr(svc, "diff"):
                result = await _call_maybe_async(svc.diff, target_id, other_id)
            else:
                result = _fallback_diff(svc, target_id, other_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"diff failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if isinstance(result, dict) and result.get("status") == "error":
            message = "; ".join(str(err) for err in result.get("errors", []))
            if "not found" in message.lower():
                raise HTTPException(status_code=404, detail=message)
            return JSONResponse(jsonable_encoder(result), status_code=400)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    @app.post("/api/investigations/{target_id}/step-batch")
    async def step_batch_investigation(
            target_id: str,
            payload: Optional[StepBatchRequest] = Body(default=None)) -> Any:
        if not _investigation_exists(svc, target_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        max_pivots = payload.max_pivots if payload is not None else 3
        try:
            if hasattr(svc, "step_batch"):
                result = await asyncio.to_thread(
                    _call, svc.step_batch, target_id, max_pivots=max_pivots)
                if inspect.isawaitable(result):
                    result = await result
            else:
                result = await asyncio.to_thread(svc.step, target_id)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"step-batch failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if isinstance(result, dict) and result.get("status") == "error":
            message = "; ".join(str(err) for err in result.get("errors", []))
            if "not found" in message.lower():
                raise HTTPException(status_code=404, detail=message)
            return JSONResponse(jsonable_encoder(result), status_code=400)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    # ── AI & Vision Lab endpoints ──────────────────────────────────

    @app.get("/api/ai/status")
    async def get_ai_status(probe_local: bool = False) -> Any:
        ai_layer = _import_ai_layer()
        if ai_layer is None or not hasattr(ai_layer, "get_ai_status"):
            return JSONResponse({
                "status": "unavailable",
                "enabled": False,
                "provider": "disabled",
                "available": False,
                "providers": {},
            })
        try:
            result = await _call_maybe_async(
                ai_layer.get_ai_status, probe_local=probe_local)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"ai status failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    @app.post("/api/ai/config")
    async def post_ai_config(payload: AIConfigRequest) -> Any:
        ai_layer = _import_ai_layer()
        if ai_layer is None or not hasattr(ai_layer, "update_ai_config"):
            return JSONResponse(
                {"status": "unavailable", "errors": ["AI subsystem not available"]},
                status_code=503)
        data = payload.model_dump(exclude_none=True)
        prov = str(data.get("provider") or "").strip().lower()
        if data.get("model"):
            model_field = {
                "ollama": "ollama_model",
                "lmstudio": "lmstudio_model",
                "gemini": "gemini_model",
                "deepseek": "deepseek_model",
                "openai_compat": "openai_model",
            }.get(prov or "ollama")
            if model_field and model_field not in data:
                data[model_field] = data.pop("model")
        if data.get("vision_model") and "ollama_vision_model" not in data:
            data["ollama_vision_model"] = data.pop("vision_model")
        if data.get("base_url"):
            url_field = {
                "ollama": "ollama_host",
                "lmstudio": "lmstudio_base_url",
                "gemini": "gemini_base_url",
                "deepseek": "deepseek_base_url",
                "openai_compat": "openai_base_url",
            }.get(prov or "ollama")
            if url_field and url_field not in data:
                data[url_field] = data.pop("base_url")
        if data.get("api_key"):
            key_field = {
                "gemini": "gemini_api_key",
                "deepseek": "deepseek_api_key",
                "openai_compat": "openai_api_key",
            }.get(prov)
            if key_field and key_field not in data:
                data[key_field] = data.pop("api_key")
        try:
            result = await _call_maybe_async(ai_layer.update_ai_config, data)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"ai config failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    @app.post("/api/investigations/{target_id}/reflect")
    async def post_reflect(target_id: str,
                           payload: Optional[ReflectRequest] = Body(default=None)) -> Any:
        if not _investigation_exists(svc, target_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        ai_layer = _import_ai_layer()
        if ai_layer is None or not hasattr(ai_layer, "run_case_reflection"):
            return JSONResponse(
                {"status": "unavailable", "target_id": target_id,
                 "errors": ["AI reflection subsystem not available"]},
                status_code=503)
        provider_override = payload.provider_override if payload is not None else None
        store = svc.engine().open_store(target_id)
        try:
            result = await _call_maybe_async(
                ai_layer.run_case_reflection, store, target_id,
                provider_override=provider_override)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"reflection failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        finally:
            store.close()
        return JSONResponse(jsonable_encoder(_value(result, 2000)))

    @app.post("/api/media/analyze")
    async def post_media_analyze(payload: MediaAnalyzeRequest) -> Any:
        url = (payload.url or "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="url is required")
        ai_layer = _import_ai_layer()
        if ai_layer is None or not hasattr(ai_layer, "analyze_media_url"):
            return JSONResponse(
                {"status": "unavailable",
                 "errors": ["Vision & media forensics subsystem not available"]},
                status_code=503)
        scope = ScopeConfig()
        if payload.target_id:
            if not _investigation_exists(svc, payload.target_id):
                raise HTTPException(status_code=404,
                                    detail=f"investigation not found: {payload.target_id}")
            store = svc.engine().open_store(payload.target_id)
            try:
                inv = store.get_investigation(payload.target_id)
                if inv is not None:
                    scope = inv.config.scope
            finally:
                store.close()
        try:
            result = await _call_maybe_async(
                ai_layer.analyze_media_url, url,
                use_vlm=payload.use_vlm, scope=scope)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"media analysis failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(_value(result, 2000)))

    # ── Demo Case / Portable Bundles / MCP Setup ───────────────────

    @app.post("/api/demo")
    async def post_demo(payload: Optional[DemoRequest] = Body(default=None)) -> Any:
        overwrite = bool(payload.overwrite) if payload is not None else True
        try:
            if hasattr(svc, "seed_demo"):
                result = await asyncio.to_thread(
                    _call, svc.seed_demo, overwrite=overwrite)
            else:
                from hub.demo import seed_demo_case

                inv_dir = svc.engine().state_root()
                result = await asyncio.to_thread(
                    seed_demo_case, None,
                    overwrite=overwrite, investigations_dir=inv_dir)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"demo seed failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    @app.get("/api/investigations/{target_id}/bundle")
    async def get_investigation_bundle(target_id: str,
                                       redact_pii: bool = False) -> Any:
        if not _investigation_exists(svc, target_id):
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        try:
            if hasattr(svc, "export_bundle"):
                exported = await asyncio.to_thread(
                    _call, svc.export_bundle, target_id,
                    redact_pii=redact_pii)
            else:
                try:
                    from hub.bundle import export_case_bundle
                except ImportError:
                    return JSONResponse(
                        {"status": "unavailable",
                         "errors": ["Portable bundle subsystem not available"]},
                        status_code=503)
                inv_dir = svc.engine().state_root()
                exported = await asyncio.to_thread(
                    _call, export_case_bundle, inv_dir, target_id,
                    redact_pii=redact_pii, investigations_dir=inv_dir)
        except LookupError:
            raise HTTPException(status_code=404,
                                detail=f"investigation not found: {target_id}")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"bundle export failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if not isinstance(exported, tuple) or len(exported) != 2:
            return JSONResponse(
                _error_payload("bundle export returned unexpected payload"),
                status_code=500)
        zip_bytes, manifest = exported
        safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", target_id).strip("._") or "case"
        filename = f"{safe_id}.osintcase.zip"
        return Response(
            content=bytes(zip_bytes),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Bundle-Target-Id": safe_id,
                "X-Bundle-Redacted": "true" if (manifest or {}).get("redacted", redact_pii) else "false",
            },
        )

    @app.post("/api/bundles/import")
    async def post_import_bundle(
        request: Request,
        overwrite: bool = False,
        target_id: Optional[str] = None,
    ) -> Any:
        max_bytes = 50 * 1024 * 1024
        content_type = (request.headers.get("content-type") or "").lower()
        new_target_id: Optional[str] = target_id
        effective_overwrite = bool(overwrite)

        if "application/json" in content_type:
            try:
                body_bytes = await request.body()
                if len(body_bytes) > 75 * 1024 * 1024:
                    raise HTTPException(status_code=400, detail="bundle payload exceeds size limit")
                data = json.loads(body_bytes.decode("utf-8"))
            except HTTPException:
                raise
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}")
            if not isinstance(data, dict):
                raise HTTPException(status_code=400, detail="JSON body must be an object")
            b64 = data.get("data_base64")
            if not isinstance(b64, str) or not b64.strip():
                raise HTTPException(status_code=400, detail="data_base64 is required")
            # Strip optional data URL prefix if present
            b64_clean = b64.strip()
            if "," in b64_clean and b64_clean.lower().startswith("data:"):
                b64_clean = b64_clean.split(",", 1)[1].strip()
            try:
                zip_bytes = base64.b64decode(b64_clean, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise HTTPException(status_code=400, detail=f"invalid base64 bundle data: {exc}")
            if "overwrite" in data and data["overwrite"] is not None:
                effective_overwrite = bool(data["overwrite"])
            if data.get("new_target_id"):
                new_target_id = str(data["new_target_id"])
            elif data.get("target_id"):
                new_target_id = str(data["target_id"])
        else:
            zip_bytes = await request.body()

        if not zip_bytes:
            raise HTTPException(status_code=400, detail="empty bundle payload")
        if len(zip_bytes) > max_bytes:
            raise HTTPException(status_code=400, detail="bundle exceeds 50 MiB limit")

        try:
            if hasattr(svc, "import_bundle"):
                result = await asyncio.to_thread(
                    _call, svc.import_bundle, zip_bytes,
                    overwrite=effective_overwrite, new_target_id=new_target_id)
            else:
                try:
                    from hub.bundle import import_case_bundle
                except ImportError:
                    return JSONResponse(
                        {"status": "unavailable",
                         "errors": ["Portable bundle subsystem not available"]},
                        status_code=503)
                inv_dir = svc.engine().state_root()
                result = await asyncio.to_thread(
                    _call, import_case_bundle, inv_dir, zip_bytes,
                    overwrite=effective_overwrite, new_target_id=new_target_id,
                    investigations_dir=inv_dir)
        except FileExistsError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"bundle import failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        return JSONResponse(jsonable_encoder(_value(result, 1000)))

    @app.get("/api/mcp-config")
    def get_mcp_config(client: str = "antigravity") -> Any:
        try:
            if hasattr(svc, "mcp_config"):
                result = _call(svc.mcp_config, client)
            else:
                result = _fallback_mcp_config(client)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                _error_payload(f"mcp-config failed: {type(exc).__name__}: {exc}"),
                status_code=500)
        if isinstance(result, dict) and result.get("status") == "error":
            return JSONResponse(jsonable_encoder(result), status_code=400)
        return JSONResponse(jsonable_encoder(result))

    return app


def _fallback_mcp_config(client: str = "antigravity") -> dict[str, Any]:
    """Generate a ready-to-paste MCP client configuration snippet."""
    key = (client or "antigravity").strip().lower()
    paths = {
        "antigravity": "~/.gemini/config/mcp_config.json",
        "claude": "~/Library/Application Support/Claude/claude_desktop_config.json (macOS) | %APPDATA%\\Claude\\claude_desktop_config.json (Windows)",
        "cursor": "~/.cursor/mcp.json",
        "vscode": ".vscode/mcp.json",
    }
    if key not in paths:
        raise ValueError(
            f"Unsupported MCP client {client!r}. Expected one of: {', '.join(sorted(paths))}"
        )
    root_key = "servers" if key == "vscode" else "mcpServers"
    server_entry: dict[str, Any] = {
        "command": sys.executable or "python",
        "args": ["-m", "hub.mcp_server"],
    }
    if key == "vscode":
        server_entry = {"type": "stdio", **server_entry}
    snippet = {root_key: {"ai-osint-hub": server_entry}}
    return {
        "status": "ok",
        "client": key,
        "config_path_hint": paths[key],
        "config_json": json.dumps(snippet, indent=2),
        "snippet_json": json.dumps(snippet, indent=2),
        "snippet": snippet,
    }


def _stream_deadline_seconds(service: InvestigationService,
                             target_id: str) -> float:
    """SSE deadline = investigation wall-clock timeout + 30 s buffer."""
    try:
        state = _probe_stream_state(service, target_id)
        if state:
            investigation = state["investigation"]
            config = investigation.get("config") or {}
            budgets = config.get("budgets") or {}
            wall = (budgets.get("wall_clock_timeout_sec")
                    or investigation.get("wall_clock_timeout_sec"))
            if wall:
                return max(60.0, float(wall) + STREAM_DEADLINE_BUFFER_SEC)
    except Exception:  # noqa: BLE001 - fall back to the conservative default
        pass
    return STREAM_MAX_SECONDS


def _investigation_exists(service: InvestigationService, target_id: str) -> bool:
    try:
        store = service.engine().open_store(target_id)
    except EngineError:
        return False
    except Exception:  # noqa: BLE001 - treat unreadable state as absent
        return False
    try:
        return store.get_investigation(target_id) is not None
    finally:
        store.close()


def _ensure_html_document(content: str) -> str:
    """Keep the reporting HTML as-is; wrap a fragment into a Gruvbox Light document."""
    text = content or ""
    if text.lstrip().lower().startswith("<!doctype") or "<html" in text.lower():
        return text
    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"color-scheme\" content=\"light\">"
        "<title>Intelligence Dossier</title>"
        "<style>body{background:#fbf1c7;color:#3c3836;font:14px/1.55 sans-serif;"
        "padding:32px}pre{white-space:pre-wrap;word-break:break-word;"
        "background:#f2e5bc;border:1px solid #d5c4a1;padding:16px;border-radius:6px}</style>"
        f"</head><body><pre>{_text(text, 200_000)}</pre></body></html>"
    )


# ════════════════════════════════════════════════════════════════════════
# Embedded single-page workbench (Gruvbox Material Light + offline Cytoscape)
# ════════════════════════════════════════════════════════════════════════

WORKBENCH_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>AI OSINT Hub Intelligence Workbench</title>
<!-- offline; replaces https://cdn.tailwindcss.com -->
<style>
:root {
  color-scheme: light;
  --bg: #fbf1c7;
  --panel: #f9f5d7;
  --panel2: #f2e5bc;
  --line: #d5c4a1;
  --text: #282828;
  --text-body: #3c3836;
  --muted: #665c54;
  --accent: #af3a03;
  --accent-hover: #b5381e;
  --green: #427b58;
  --olive: #79740e;
  --ochre: #b57614;
  --crimson: #9d0006;
  --slate: #076678;
}
[data-theme="dark"] {
  color-scheme: dark;
  --dark-legacy-bg: #0b1020;
  --bg: #1d2021;
  --panel: #282828;
  --panel2: #32302f;
  --line: #504945;
  --text: #fbf1c7;
  --text-body: #ebdbb2;
  --muted: #a89984;
  --accent: #fe8019;
  --accent-hover: #d65d0e;
  --green: #8ec07c;
  --olive: #b8bb26;
  --ochre: #fabd2f;
  --crimson: #fb4934;
  --slate: #83a598;
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text-body);
  font: 13.5px/1.5 "Inter", "Segoe UI", system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif;
}
.mono, code, pre, #artifact-sha, #artifact-confidence, #target-label, #stats-line,
.telemetry-list, .timeline-ts, .pivot-score {
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}
#workbench { display: flex; flex-direction: column; height: 100vh; min-height: 0; }
header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--panel2);
  flex-wrap: wrap;
}
header h1 {
  font-size: 15px;
  font-weight: 700;
  margin: 0;
  letter-spacing: -0.01em;
  color: var(--text);
}
header .pill {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 2px 8px;
  border-radius: 4px;
  border: 1px solid var(--line);
  background: var(--panel);
  color: var(--slate);
}
header .muted { color: var(--muted); font-size: 12px; }
main {
  flex: 1;
  min-height: 0;
  display: grid;
  grid-template-columns: 344px minmax(0, 1fr) 360px;
  gap: 16px;
  padding: 16px;
  max-width: 3440px;
  width: 100%;
  margin: 0 auto;
}
#workbench.rail-left-collapsed main { grid-template-columns: 0px minmax(0, 1fr) 360px; }
#workbench.rail-right-collapsed main { grid-template-columns: 344px minmax(0, 1fr) 0px; }
#workbench.rail-left-collapsed.rail-right-collapsed main { grid-template-columns: 0px minmax(0, 1fr) 0px; }
#workbench.rail-left-collapsed .intake-panel,
#workbench.rail-right-collapsed .inspector-panel {
  border-width: 0;
  padding: 0;
  overflow: hidden;
  visibility: hidden;
}
@media (max-width: 1360px) {
  main {
    grid-template-columns: 300px minmax(0, 1fr) 316px;
    gap: 12px;
    padding: 12px;
  }
  #workbench.rail-left-collapsed main { grid-template-columns: 0px minmax(0, 1fr) 316px; }
  #workbench.rail-right-collapsed main { grid-template-columns: 300px minmax(0, 1fr) 0px; }
}
@media (max-width: 1080px) {
  main,
  #workbench.rail-left-collapsed main,
  #workbench.rail-right-collapsed main,
  #workbench.rail-left-collapsed.rail-right-collapsed main {
    grid-template-columns: 1fr;
    overflow: auto;
  }
  #workbench.rail-left-collapsed .intake-panel,
  #workbench.rail-right-collapsed .inspector-panel {
    display: none;
  }
}
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  min-height: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.panel > h2 {
  margin: 0;
  padding: 8px 16px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  background: var(--panel2);
  border-bottom: 1px solid var(--line);
}
.panel-body { padding: 16px; overflow: auto; min-height: 0; }
label {
  display: block;
  font-size: 11px;
  font-weight: 600;
  color: var(--muted);
  margin: 8px 0 4px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
input, textarea, select {
  width: 100%;
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 6px 8px;
  font: inherit;
  font-size: 13px;
}
input:focus, textarea:focus, select:focus {
  outline: 2px solid var(--accent);
  outline-offset: -1px;
  border-color: var(--accent);
}
textarea { min-height: 80px; resize: vertical; }
button {
  background: var(--accent);
  color: #fbf1c7;
  border: 1px solid var(--accent);
  border-radius: 4px;
  padding: 6px 12px;
  font: inherit;
  font-size: 12.5px;
  font-weight: 600;
  cursor: pointer;
}
button:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
button.secondary {
  background: var(--panel2);
  border-color: var(--line);
  color: var(--text);
}
button.secondary:hover { background: var(--bg); border-color: var(--muted); }
button.compact { padding: 4px 8px; font-size: 11.5px; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.spacer { flex: 1; }
.muted { color: var(--muted); }
.tabs {
  display: flex;
  gap: 4px;
  padding: 8px 16px;
  background: var(--panel2);
  border-bottom: 1px solid var(--line);
  flex-wrap: wrap;
}
.tab {
  background: transparent;
  border-color: transparent;
  color: var(--muted);
  padding: 6px 12px;
  border-radius: 4px;
}
.tab.active {
  background: var(--panel);
  color: var(--text);
  border-color: var(--line);
  border-bottom: 2px solid var(--accent);
}
.tab-panel { display: none; flex: 1; min-height: 0; }
.tab-panel.active { display: flex; flex-direction: column; }
#graph-wrap {
  position: relative;
  flex: 1;
  min-height: 360px;
  padding: 8px;
  background: var(--bg);
}
#cy-graph {
  width: 100%;
  height: 100%;
  min-height: 344px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
}
#graph {
  width: 100%;
  height: 100%;
  min-height: 344px;
  display: block;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
}
.graph-hidden {
  position: absolute !important;
  left: -99999px !important;
  width: 960px !important;
  height: 620px !important;
  pointer-events: none;
}
#graph text { font-size: 11px; fill: var(--text-body); pointer-events: none; }
#graph .edge-line { stroke: var(--line); stroke-width: 1.5; cursor: pointer; }
#graph .edge-line:hover { stroke: var(--accent); stroke-width: 2.4; }
#graph .edge-line.path-highlight { stroke: var(--accent); stroke-width: 3.2; }
#graph .edge-label { font-size: 9.5px; fill: var(--muted); }
#graph .node-circle { stroke: var(--bg); stroke-width: 2; cursor: pointer; }
#graph .node-circle:hover { stroke: var(--text); stroke-width: 3; }
#graph .node-label { font-size: 10.5px; fill: var(--text); }
#graph .empty { font-size: 13px; fill: var(--muted); }
.dossier-pre {
  margin: 0;
  padding: 16px;
  background: var(--panel2);
  border: 1px solid var(--line);
  border-radius: 6px;
  white-space: pre-wrap;
  word-break: break-word;
  font: 12px/1.6 ui-monospace, Consolas, "Cascadia Mono", monospace;
  font-variant-numeric: tabular-nums;
  color: var(--text);
  min-height: 320px;
}
.telemetry-section { margin-bottom: 24px; }
.telemetry-section h3 {
  margin: 0 0 8px;
  font-size: 11.5px;
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  border-bottom: 1px solid var(--line);
  padding-bottom: 4px;
}
.telemetry-list { list-style: none; margin: 0; padding: 0; }
.telemetry-list li {
  padding: 8px;
  margin: 4px 0;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 4px;
  font-size: 12px;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: 0.03em;
  border: 1px solid var(--line);
  color: var(--text-body);
  background: var(--panel2);
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-variant-numeric: tabular-nums;
}
.badge.CONFIRMED { background: #e8eed8; color: var(--green); border-color: #8ea67c; }
.badge.CORROBORATED { background: #e8eed8; color: var(--olive); border-color: #a39e4b; }
.badge.SINGLE_SOURCE_LEAD { background: #f6ead0; color: var(--ochre); border-color: #d7a64f; }
.badge.HYPOTHESIS { background: var(--panel2); color: var(--muted); border-color: var(--line); }
.badge.CONTRADICTED { background: #f6e0dc; color: var(--crimson); border-color: #c96e6b; }
.badge.COLLECTION_FAILURE { background: #f2e2dc; color: var(--crimson); border-color: var(--line); }
.badge.AI_INFERRED { background: #e2ecef; color: var(--slate); border-color: #7ca5ae; }
[data-theme="dark"] .badge.CONFIRMED { background: #1d2c21; border-color: #427b58; }
[data-theme="dark"] .badge.CORROBORATED { background: #262919; border-color: #79740e; }
[data-theme="dark"] .badge.SINGLE_SOURCE_LEAD { background: #332612; border-color: #b57614; }
[data-theme="dark"] .badge.CONTRADICTED { background: #361717; border-color: #9d0006; }
[data-theme="dark"] .badge.AI_INFERRED { background: #17272c; border-color: #076678; }
#inspector dl { margin: 8px 0 0; }
#inspector dt {
  font-size: 10.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  margin-top: 8px;
}
#inspector dd { margin: 4px 0 0; font-size: 12.5px; word-break: break-word; }
#artifact-snippet {
  background: var(--panel2);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 11.5px;
  max-height: 192px;
  overflow: auto;
  margin: 0;
  color: var(--text);
}
.claim-line {
  font-size: 12px;
  padding: 6px 8px;
  margin: 4px 0;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 4px;
}
#ui-message { min-height: 16px; color: var(--crimson); font-size: 12px; margin: 8px 0 0; }
.dl-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  padding: 8px 16px;
  background: var(--panel2);
  border-bottom: 1px solid var(--line);
}
a.dl-link {
  display: inline-block;
  text-decoration: none;
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  border: 1px solid var(--line);
  background: var(--panel);
  border-radius: 4px;
  padding: 6px 12px;
}
a.dl-link:hover { border-color: var(--accent); color: var(--accent); }
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(40, 40, 40, 0.55);
  z-index: 60;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
}
.modal-backdrop[hidden] { display: none !important; }
.modal-card {
  width: min(560px, 96vw);
  max-height: 90vh;
  overflow: auto;
  background: var(--panel);
  border: 1px solid var(--line);
  border-top: 3px solid var(--accent);
  border-radius: 8px;
  padding: 24px;
}
.modal-card h2 { margin: 0 0 8px; font-size: 16px; color: var(--text); }
.modal-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 16px; }
.modal-grid .full { grid-column: 1 / -1; }
.cred-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-body);
}
.cred-badge {
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: 0.03em;
}
.cred-badge.ok { color: var(--green); border-color: var(--green); background: #e8eed8; }
.cred-badge.miss { color: var(--ochre); border-color: var(--ochre); background: #f6ead0; }
.cred-badge.info { color: var(--slate); border-color: var(--slate); background: #e2ecef; }
#graph-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  padding: 8px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--panel2);
}
#graph-toolbar button { padding: 4px 8px; font-size: 11.5px; }
#node-search { flex: 1 1 150px; min-width: 120px; margin: 0; padding: 4px 8px; font-size: 12px; }
#cluster-filter { width: auto; min-width: 110px; margin: 0; padding: 4px 8px; font-size: 11.5px; }
#type-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  padding: 8px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--panel);
}
.graph-toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11.5px;
  color: var(--text-body);
  margin: 0;
  text-transform: none;
  letter-spacing: 0;
  cursor: pointer;
}
.graph-toggle input { width: auto; margin: 0; }
.filter-pill {
  border: 1px solid var(--line);
  background: var(--panel2);
  color: var(--text-body);
  border-radius: 4px;
  padding: 2px 8px;
  font-size: 11px;
  cursor: pointer;
}
.filter-pill.active { border-color: var(--accent); color: #fbf1c7; background: var(--accent); }
.filter-pill .count { opacity: 0.8; margin-left: 4px; }
.node-dim { opacity: 0.18; }
.node-match .node-circle { stroke: var(--accent); stroke-width: 4; }
#ui-message.error { color: var(--crimson); font-weight: 600; }
.pill.completed { color: var(--green); border-color: var(--green); background: #e8eed8; }
.rail-card {
  margin-top: 16px;
  padding: 8px 12px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
}
.rail-card summary {
  cursor: pointer;
  font-size: 11.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text);
}
.tool-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  border-bottom: 1px solid var(--line);
  font-size: 11.5px;
}
.tool-row:last-child { border-bottom: none; }
.ai-box {
  background: var(--bg);
  border: 1px solid var(--line);
  border-left: 3px solid var(--slate);
  border-radius: 6px;
  padding: 16px;
  margin-bottom: 16px;
}
.quarantine-alert {
  background: #f6e0dc;
  border: 1px solid var(--crimson);
  color: var(--crimson);
  border-radius: 4px;
  padding: 8px;
  margin-top: 8px;
  font-size: 12px;
  font-weight: 600;
}
.first-run-overlay {
  position: absolute;
  inset: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 8;
  pointer-events: none;
}
.first-run-overlay[hidden] { display: none !important; }
.first-run-card {
  pointer-events: auto;
  width: min(640px, 100%);
  max-height: 100%;
  overflow: auto;
  background: var(--panel);
  border: 1px solid var(--line);
  border-top: 4px solid var(--accent);
  border-radius: 8px;
  padding: 24px;
}
.first-run-card h3 {
  margin: 0 0 8px;
  font-size: 17px;
  color: var(--text);
}
.checklist-card {
  margin-top: 16px;
  padding: 12px 16px;
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 6px;
}
.checklist-card[hidden] { display: none !important; }
.checklist-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  font-size: 12.5px;
  color: var(--text-body);
}
.checklist-item.done { color: var(--green); }
.preset-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-bottom: 8px;
}
.preset-pill {
  border: 1px solid var(--line);
  background: var(--panel2);
  color: var(--text-body);
  border-radius: 4px;
  padding: 4px 8px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
}
.preset-pill.active {
  background: var(--accent);
  border-color: var(--accent);
  color: #fbf1c7;
}
.seg-toggle {
  display: inline-flex;
  border: 1px solid var(--line);
  border-radius: 4px;
  overflow: hidden;
  background: var(--bg);
}
.seg-toggle button {
  background: transparent;
  color: var(--muted);
  border: none;
  border-radius: 0;
  padding: 4px 10px;
  font-size: 11.5px;
}
.seg-toggle button.active {
  background: var(--accent);
  color: #fbf1c7;
}
.dossier-rendered {
  max-width: 75ch;
  margin: 0 auto;
  padding: 8px 4px 32px;
  color: var(--text-body);
  line-height: 1.65;
}
.dossier-rendered[hidden], .dossier-pre[hidden] { display: none !important; }
.dossier-rendered h1 { font-size: 22px; color: var(--text); margin: 0 0 12px; border-bottom: 2px solid var(--accent); padding-bottom: 8px; }
.dossier-rendered h2 { font-size: 16.5px; color: var(--text); margin: 24px 0 10px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
.dossier-rendered h3 { font-size: 14px; color: var(--text); margin: 16px 0 8px; }
.dossier-rendered h4 { font-size: 13px; color: var(--muted); margin: 12px 0 6px; text-transform: uppercase; letter-spacing: 0.04em; }
.dossier-rendered p { margin: 8px 0; }
.dossier-rendered blockquote {
  margin: 12px 0;
  padding: 8px 12px;
  background: var(--panel2);
  border-left: 3px solid var(--accent);
  color: var(--text-body);
  border-radius: 0 4px 4px 0;
}
.dossier-rendered ul, .dossier-rendered ol { margin: 8px 0; padding-left: 22px; }
.dossier-rendered li { margin: 4px 0; }
.dossier-rendered table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0;
  font-size: 12px;
  background: var(--bg);
  border: 1px solid var(--line);
}
.dossier-rendered th, .dossier-rendered td {
  text-align: left;
  padding: 6px 10px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
.dossier-rendered th {
  background: var(--panel2);
  color: var(--text);
  font-weight: 700;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.dossier-rendered code {
  background: var(--panel2);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 1px 4px;
  font-size: 11.5px;
  color: var(--text);
}
.dossier-rendered pre {
  background: var(--panel2);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 12px;
  overflow: auto;
  font-size: 12px;
}
.dossier-rendered a { color: var(--slate); text-decoration: underline; }
.dossier-rendered hr { border: none; border-top: 1px solid var(--line); margin: 16px 0; }
.cmd-list {
  list-style: none;
  margin: 12px 0 0;
  padding: 0;
  max-height: 320px;
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--bg);
}
.cmd-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--line);
  cursor: pointer;
  font-size: 12.5px;
}
.cmd-item:last-child { border-bottom: none; }
.cmd-item.selected, .cmd-item:hover {
  background: var(--panel2);
  border-left: 3px solid var(--accent);
}
.pull-cmd-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 6px 8px;
  margin-top: 6px;
  background: var(--panel2);
  border: 1px solid var(--line);
  border-radius: 4px;
}
.kbd-hint {
  font-size: 10.5px;
  padding: 1px 6px;
  border: 1px solid var(--line);
  border-radius: 4px;
  background: var(--bg);
  color: var(--muted);
}
@media print {
  @page { margin: 14mm; size: auto; }
  body { background: #ffffff !important; color: #282828 !important; }
  #workbench { height: auto; display: block; }
  header, .intake-panel, .inspector-panel, .tabs, .dl-row,
  .modal-backdrop, .first-run-overlay { display: none !important; }
  main { display: block !important; padding: 0 !important; }
  .visualization-panel { border: none !important; background: #ffffff !important; }
  .tab-panel { display: none !important; }
  #tab-dossier { display: block !important; }
  .dossier-rendered { max-width: none; padding: 0; color: #282828 !important; }
  .dossier-rendered h1, .dossier-rendered h2, .dossier-rendered h3 { break-after: avoid; page-break-after: avoid; color: #282828 !important; }
  .dossier-rendered table, .dossier-rendered blockquote, .dossier-rendered pre { break-inside: avoid; page-break-inside: avoid; }
  .dossier-rendered th, .dossier-rendered code { background: #f2e5bc !important; color: #282828 !important; }
  .dossier-pre { background: #ffffff !important; color: #282828 !important; border: none !important; }
}
</style>
</head>
<body>
<div id="workbench">
  <header>
    <button id="toggle-left-rail" class="secondary compact" type="button" title="Toggle Left Rail">Rail</button>
    <h1>AI OSINT Hub Intelligence Workbench</h1>
    <span id="status-pill" class="pill" aria-live="polite">idle</span>
    <span id="target-label" class="muted"></span>
    <span class="spacer"></span>
    <span id="stats-line" class="muted"></span>
    <button id="open-cmd-palette" class="secondary compact" type="button" title="Command Palette (Ctrl+K / Cmd+K)">Cmd+K</button>
    <button id="open-mcp-modal" class="secondary compact" type="button" aria-haspopup="dialog" aria-controls="mcp-setup-modal">MCP Setup</button>
    <button id="toggle-theme" class="secondary compact" type="button" title="Toggle Light/Dark theme">Theme</button>
    <button id="open-api-keys" class="secondary compact" type="button"
            aria-haspopup="dialog" aria-controls="api-keys-modal">API Keys</button>
    <button id="toggle-right-rail" class="secondary compact" type="button" title="Toggle Inspector">Inspector</button>
  </header>
  <main>
    <section class="panel intake-panel" aria-label="Intake and Case Rail">
      <h2>Case &amp; Intake</h2>
      <div class="panel-body">
        <div class="rail-card" style="margin-top:0;margin-bottom:16px">
          <div class="row">
            <label for="case-select" style="margin:0;flex:1">Active Investigation</label>
            <button id="refresh-cases-btn" class="secondary compact" type="button">Refresh</button>
          </div>
          <select id="case-select" aria-label="Select investigation" style="margin-top:4px">
            <option value="">— current / new —</option>
          </select>
          <div class="row" style="margin-top:8px">
            <select id="diff-target-select" aria-label="Compare against case" style="flex:1">
              <option value="">Diff against case…</option>
            </select>
            <button id="run-diff-btn" class="secondary compact" type="button">Diff</button>
          </div>
          <div class="row" style="margin-top:8px">
            <button id="export-bundle-btn" class="secondary compact" type="button" title="Export portable .osintcase.zip">Export .osintcase.zip</button>
            <label class="graph-toggle" style="font-size:11px">
              <input id="export-redact-pii" type="checkbox"> Redact PII
            </label>
          </div>
          <div class="row" style="margin-top:6px">
            <button id="import-bundle-btn" class="secondary compact" type="button" title="Import .osintcase.zip bundle">Import .osintcase.zip</button>
            <label class="graph-toggle" style="font-size:11px">
              <input id="import-overwrite-bundle" type="checkbox"> Overwrite
            </label>
            <input id="bundle-file-input" type="file" accept=".zip,.osintcase.zip" hidden>
          </div>
        </div>

        <div id="intake-presets" class="preset-bar" role="group" aria-label="Guided intake presets">
          <button type="button" class="preset-pill active" data-preset="person">Person / Handle</button>
          <button type="button" class="preset-pill" data-preset="domain">Domain / Org</button>
          <button type="button" class="preset-pill" data-preset="media">Image / Media Forensics</button>
          <button type="button" class="preset-pill" data-preset="custom">Custom Clue</button>
        </div>
        <p id="intake-preset-hint" class="muted" style="font-size:11.5px;margin:0 0 8px">
          Preset: Person / Handle — provide a name, handle, or email to trace cross-platform identity.
        </p>

        <form id="intake" autocomplete="off">
          <label for="in-raw">Free-form intelligence</label>
          <textarea id="in-raw" placeholder="Paste OSINT notes, names, handles, emails, domains, phones, URLs, IPs…"></textarea>
          <label for="in-name">Full name</label>
          <input id="in-name" type="text" placeholder="Target display name">
          <div class="grid2">
            <div><label for="in-usernames">Usernames</label><input id="in-usernames" type="text" placeholder="comma or space separated"></div>
            <div><label for="in-emails">Emails</label><input id="in-emails" type="text" placeholder="comma separated"></div>
            <div><label for="in-domains">Domains</label><input id="in-domains" type="text" placeholder="comma separated"></div>
            <div><label for="in-phones">Phones</label><input id="in-phones" type="text" placeholder="comma separated"></div>
            <div><label for="in-org">Organization</label><input id="in-org" type="text" placeholder="name or comma-separated list"></div>
            <div><label for="in-location">Location</label><input id="in-location" type="text" placeholder="comma separated"></div>
            <div><label for="in-urls">URLs</label><input id="in-urls" type="text" placeholder="comma separated"></div>
            <div><label for="in-ips">IPs</label><input id="in-ips" type="text" placeholder="comma separated"></div>
          </div>
          <label for="in-allow-domains">Scope allow-domains (comma separated, optional)</label>
          <input id="in-allow-domains" type="text" placeholder="optional scope boundary">
          <div class="row" style="margin-top:8px">
            <label class="row" style="margin:0;text-transform:none;letter-spacing:0">
              <input id="in-active" type="checkbox" style="width:auto;margin-right:6px"> Allow active recon
            </label>
            <label class="row" style="margin:0;text-transform:none;letter-spacing:0">
              <input id="in-wait" type="checkbox" style="width:auto;margin-right:6px"> Wait for completion
            </label>
          </div>
          <details style="margin-top:8px">
            <summary class="muted" style="cursor:pointer;font-size:12px">Budgets &amp; thresholds</summary>
            <div class="grid2" style="margin-top:8px">
              <div><label for="in-max-iterations">Max iterations</label><input id="in-max-iterations" type="number" value="16" min="1" max="500"></div>
              <div><label for="in-max-tool-calls">Max tool calls</label><input id="in-max-tool-calls" type="number" value="20" min="1" max="1000"></div>
              <div><label for="in-timeout">Wall clock (s)</label><input id="in-timeout" type="number" value="600" min="5"></div>
              <div><label for="in-threshold">Min pivot score</label><input id="in-threshold" type="number" value="0.12" min="0" max="1" step="0.01"></div>
            </div>
          </details>
          <div class="row" style="margin-top:16px">
            <button id="run-investigation" type="submit">Start Investigation</button>
            <button id="run-pivot" class="secondary" type="button">Run Next Pivot</button>
            <button id="run-batch-pivots" class="secondary compact" type="button">Step Batch (3x)</button>
            <button id="clear-form" class="secondary compact" type="button">Clear Form</button>
          </div>
          <p id="ui-message" role="alert"></p>
        </form>

        <details id="tools-health-drawer" class="rail-card">
          <summary>32-Tool Health &amp; Scope Policy</summary>
          <div class="row" style="margin-top:8px">
            <span id="tools-summary-badge" class="badge">checking…</span>
            <span class="spacer"></span>
            <button id="refresh-tools-btn" class="secondary compact" type="button">Refresh</button>
            <button id="run-doctor-btn" class="secondary compact" type="button">Doctor</button>
          </div>
          <div id="scope-policy-summary" class="muted mono" style="font-size:11px;margin-top:8px">Default: passive-only, SSRF-guarded</div>
          <div id="tools-health-list" style="margin-top:8px;max-height:220px;overflow:auto"></div>
        </details>

        <details id="ai-config-drawer" class="rail-card">
          <summary>AI &amp; Vision Config</summary>
          <div style="margin-top:8px">
            <div class="row">
              <label class="row" style="margin:0;text-transform:none;letter-spacing:0">
                <input id="ai-enabled" type="checkbox" style="width:auto;margin-right:6px"> Enable AI Reflection / VLM
              </label>
              <span class="spacer"></span>
              <span id="ai-status-badge" class="badge AI_INFERRED">disabled</span>
            </div>
            <label for="ai-preset">Hardware Profile</label>
            <select id="ai-preset">
              <option value="disabled">disabled (zero-LLM core)</option>
              <option value="cpu_light">cpu_light (CPU-only compact)</option>
              <option value="vram_8gb">vram_8gb (8 GB VRAM + 32 GB RAM)</option>
              <option value="vram_16gb_plus">vram_16gb_plus (16 GB+ VRAM)</option>
              <option value="cloud_byok">cloud_byok (Cloud API BYOK)</option>
            </select>
            <label for="ai-provider">Provider</label>
            <select id="ai-provider">
              <option value="disabled">disabled</option>
              <option value="ollama">ollama (local)</option>
              <option value="lmstudio">lmstudio (local)</option>
              <option value="gemini">gemini</option>
              <option value="deepseek">deepseek</option>
              <option value="openai_compat">openai_compat</option>
            </select>
            <div class="grid2">
              <div><label for="ai-model">Text Model</label><input id="ai-model" type="text" placeholder="gemma4"></div>
              <div><label for="ai-vision-model">Vision Model</label><input id="ai-vision-model" type="text" placeholder="qwen2.5vl:7b"></div>
              <div><label for="ai-num-ctx">Context (num_ctx)</label><input id="ai-num-ctx" type="number" value="8192" min="512" max="131072"></div>
              <div><label for="ai-keep-alive">Keep Alive</label><input id="ai-keep-alive" type="text" value="2m" placeholder="90s"></div>
            </div>
            <label for="ai-base-url">Base URL (optional)</label>
            <input id="ai-base-url" type="text" placeholder="http://127.0.0.1:11434">
            <label for="ai-api-key">Provider API Key (write-only)</label>
            <input id="ai-api-key" type="password" autocomplete="off" spellcheck="false" placeholder="optional cloud key">
            <div class="row" style="margin-top:8px">
              <button id="save-ai-config" class="compact" type="button">Save AI Config</button>
              <button id="refresh-ai-status" class="secondary compact" type="button">Probe</button>
            </div>
            <p id="ai-config-message" class="muted" style="font-size:11.5px;margin:8px 0 0"></p>
          </div>
        </details>
      </div>
    </section>

    <section class="panel visualization-panel" aria-label="Visualization">
      <nav class="tabs" role="tablist">
        <button class="tab active" type="button" data-tab="graph">Graph</button>
        <button class="tab" type="button" data-tab="timeline">Timeline</button>
        <button class="tab" type="button" data-tab="telemetry">Telemetry &amp; Pivots</button>
        <button class="tab" type="button" data-tab="ai">AI &amp; Vision Lab</button>
        <button class="tab" type="button" data-tab="dossier">Dossier</button>
      </nav>
      <div id="tab-graph" class="tab-panel active">
        <div id="graph-toolbar" aria-label="Graph controls">
          <button id="zoom-in" type="button" class="secondary" title="Zoom in">Zoom +</button>
          <button id="zoom-out" type="button" class="secondary" title="Zoom out">Zoom −</button>
          <button id="zoom-reset" type="button" class="secondary" title="Reset view">Reset</button>
          <button id="toggle-graph-engine" type="button" class="secondary" title="Switch Cytoscape / SVG renderer">View: Auto</button>
          <input id="node-search" type="search" placeholder="Search nodes…"
                 aria-label="Search graph nodes">
          <select id="cluster-filter" aria-label="Filter by graph cluster">
            <option value="">All clusters</option>
          </select>
          <button id="clear-path-btn" type="button" class="secondary" title="Clear shortest-path highlight">Clear Path</button>
          <label class="graph-toggle" title="Show unverified planner hypotheses">
            <input id="show-hypotheses" type="checkbox">
            Show Hypotheses (<span id="hyp-count">0</span>)
          </label>
          <label class="graph-toggle" title="Show predicate labels on every edge">
            <input id="show-edge-labels" type="checkbox">
            Show Edge Labels
          </label>
        </div>
        <div id="type-filters" aria-label="Entity type filters"></div>
        <div id="graph-wrap">
          <div id="first-run-panel" class="first-run-overlay">
            <div class="first-run-card">
              <div class="row">
                <span class="badge AI_INFERRED">V2 WORKBENCH</span>
                <span class="muted mono" style="font-size:11px">Deterministic ERKG · Zero-LLM Default</span>
              </div>
              <h3 style="margin-top:8px">Start Your Investigation or Load the Synthetic Demo</h3>
              <p class="muted" style="margin:0 0 12px;font-size:12.5px">
                Every finding cites its immutable SHA-256 evidence artifact, detects contradictions automatically, and isolates untrusted external strings.
              </p>
              <div class="row">
                <button id="btn-load-demo" type="button">Load Interactive Demo Case</button>
                <button id="btn-import-bundle-empty" class="secondary" type="button">Import .osintcase.zip</button>
                <button id="btn-open-mcp-empty" class="secondary" type="button">10-Second MCP Setup</button>
              </div>
              <div id="quickstart-checklist" class="checklist-card">
                <div class="row" style="margin-bottom:6px">
                  <strong style="font-size:12px;color:var(--text)">Quick-Start Checklist</strong>
                  <span class="spacer"></span>
                  <button id="dismiss-quickstart" class="secondary compact" type="button">Dismiss</button>
                </div>
                <div class="checklist-item" data-step="1"><span class="mono">[ ]</span> 1. Load Interactive Demo Case or launch a new investigation</div>
                <div class="checklist-item" data-step="2"><span class="mono">[ ]</span> 2. Select any node in the graph to inspect its SHA-256 evidence artifact</div>
                <div class="checklist-item" data-step="3"><span class="mono">[ ]</span> 3. Press Ctrl/Cmd+K to jump between entities, pivots, and contradictions</div>
                <div class="checklist-item" data-step="4"><span class="mono">[ ]</span> 4. Export an evidence-cited Dossier (Markdown/HTML/PDF) or .osintcase.zip</div>
              </div>
            </div>
          </div>
          <div id="cy-graph" class="graph-hidden" aria-label="Interactive Cytoscape knowledge graph"></div>
          <svg id="graph" viewBox="0 0 960 620" preserveAspectRatio="xMidYMid meet"
               role="img" aria-label="Entity-resolved knowledge graph"></svg>
        </div>
      </div>

      <div id="tab-timeline" class="tab-panel">
        <div class="dl-row">
          <button id="refresh-timeline-btn" class="secondary compact" type="button">Refresh Timeline</button>
          <span id="timeline-summary" class="muted mono" style="font-size:12px"></span>
        </div>
        <div class="panel-body">
          <div class="telemetry-section">
            <h3>Chronological Investigation Timeline</h3>
            <ul id="timeline-list" class="telemetry-list">
              <li class="muted">Start or select an investigation to inspect timeline events.</li>
            </ul>
          </div>
          <div class="telemetry-section">
            <h3>Case Diff Comparison</h3>
            <div id="diff-results" class="muted" style="font-size:12px">Select a comparison case in the left rail and click Diff.</div>
          </div>
        </div>
      </div>

      <div id="tab-telemetry" class="tab-panel">
        <div class="panel-body" id="telemetry">
          <p class="muted">Start an investigation to see ledger, hypotheses, pivots, analytics and contradictions.</p>
        </div>
      </div>

      <div id="tab-ai" class="tab-panel">
        <div class="panel-body">
          <div id="ai-lab-profile-card" class="ai-box">
            <div class="row">
              <strong style="color:var(--text)">Hardware Profile &amp; Local Models</strong>
              <span id="ai-lab-badge" class="badge AI_INFERRED">disabled</span>
              <span class="spacer"></span>
              <button id="ai-lab-probe-btn" class="secondary compact" type="button">Detect Local Models</button>
            </div>
            <p class="muted" style="font-size:12px;margin:8px 0">
              AI is strictly opt-in (<code>disabled</code> by default). Pick a hardware profile tuned for your GPU/CPU or Cloud BYOK, and copy any missing <code>ollama pull</code> commands below.
            </p>
            <div class="row" style="margin-top:8px">
              <select id="ai-lab-preset" aria-label="AI Hardware Profile" style="max-width:320px">
                <option value="disabled">disabled — Zero-LLM Deterministic Core</option>
                <option value="cpu_light">cpu_light — CPU Light (no GPU)</option>
                <option value="vram_8gb">vram_8gb — 8 GB VRAM + 32 GB RAM</option>
                <option value="vram_16gb_plus">vram_16gb_plus — 16 GB+ VRAM Workstation</option>
                <option value="cloud_byok">cloud_byok — Cloud API BYOK</option>
              </select>
              <button id="ai-lab-apply-btn" class="compact" type="button">Apply Profile</button>
            </div>
            <div id="ai-models-status" class="muted mono" style="font-size:11.5px;margin-top:10px"></div>
            <div id="ai-pull-commands" style="margin-top:8px"></div>
          </div>
          <div class="ai-box">
            <div class="row">
              <strong style="color:var(--text)">AI Case Reflection (Quarantined)</strong>
              <span class="badge AI_INFERRED">AI_INFERRED</span>
              <span class="spacer"></span>
              <button id="run-reflect-btn" class="compact" type="button">Run Reflection</button>
            </div>
            <p class="muted" style="font-size:12px;margin:8px 0">
              AI reflections operate strictly over sanitized evidence packets and never auto-promote claims to CONFIRMED.
            </p>
            <div id="ai-insights-list"></div>
          </div>
          <div class="ai-box">
            <strong style="color:var(--text)">Vision &amp; Media Forensics Lab</strong>
            <p class="muted" style="font-size:12px;margin:8px 0">
              SSRF-guarded media download, SHA-256, EXIF/GPS, 64-bit dHash/pHash, OCR, visual prompt-injection detection, and optional quarantined VLM extraction.
            </p>
            <div class="row" style="margin-top:8px">
              <input id="media-url-input" type="url" placeholder="https://..." style="flex:1">
              <label class="graph-toggle">
                <input id="media-use-vlm" type="checkbox"> Use VLM
              </label>
              <button id="analyze-media-btn" class="compact" type="button">Analyze Media</button>
            </div>
            <pre id="media-results" class="dossier-pre" style="min-height:140px;margin-top:8px">No media analyzed yet.</pre>
          </div>
        </div>
      </div>

      <div id="tab-dossier" class="tab-panel">
        <div class="dl-row">
          <a id="download-md" class="dl-link" href="#" download>Download Markdown</a>
          <a id="download-json" class="dl-link" href="#" download>Download JSON</a>
          <a id="download-html" class="dl-link" href="#" download>Download HTML</a>
          <span class="spacer"></span>
          <div class="seg-toggle" role="group" aria-label="Dossier view mode">
            <button id="dossier-mode-rendered" class="active" type="button">Rendered</button>
            <button id="dossier-mode-raw" type="button">Raw</button>
          </div>
          <button id="dossier-print-btn" class="secondary compact" type="button">Print / Save PDF</button>
        </div>
        <div class="panel-body">
          <article id="dossier-rendered" class="dossier-rendered" aria-label="Rendered intelligence dossier">
            <p class="muted">No dossier yet. Load the Demo Case or start an investigation.</p>
          </article>
          <pre id="dossier-text" class="dossier-pre" hidden>No dossier yet.</pre>
        </div>
      </div>
    </section>

    <aside class="panel inspector-panel" aria-label="Artifact inspector">
      <h2>Artifact Inspector</h2>
      <div class="panel-body" id="inspector">
        <div class="row">
          <span id="epistemic-badge" class="badge">—</span>
          <span id="inspector-title" class="muted" style="font-size:12px">select a node or edge</span>
        </div>
        <div class="row" style="margin-top:8px">
          <button id="inspect-pivot-btn" class="compact" type="button" disabled>Pivot Entity</button>
          <button id="set-path-source-btn" class="secondary compact" type="button" disabled>Set Path Source</button>
          <button id="find-path-btn" class="secondary compact" type="button" disabled>Shortest Path</button>
        </div>
        <div id="path-status-line" class="muted mono" style="font-size:11px;margin-top:4px"></div>
        <dl>
          <dt>SHA-256</dt><dd id="artifact-sha">—</dd>
          <dt>Source tool</dt><dd id="artifact-tool">—</dd>
          <dt>Confidence</dt><dd id="artifact-confidence">—</dd>
          <dt>Evidence snippet</dt><dd><pre id="artifact-snippet">Select a graph node or edge to inspect its cited evidence artifact.</pre></dd>
        </dl>
        <div id="inspector-quarantine"></div>
        <div id="inspector-contradictions"></div>
        <div id="inspector-claims"></div>
      </div>
    </aside>
  </main>
  <div id="api-keys-modal" class="modal-backdrop" hidden role="dialog"
       aria-modal="true" aria-labelledby="api-keys-title">
    <div class="modal-card">
      <h2 id="api-keys-title">API Keys</h2>
      <p class="muted" style="margin:0 0 8px;font-size:12px">
        Stored locally in the credential vault and synced to theHarvester. Secrets are
        never shown again after saving.
      </p>
      <div class="modal-grid">
        <div class="full">
          <label for="key-github">GitHub Token</label>
          <input id="key-github" type="password" autocomplete="off" spellcheck="false"
                 placeholder="github_pat_…">
          <div class="cred-row"><span>GitHub</span><span id="cred-status-github" class="cred-badge info">—</span></div>
        </div>
        <div>
          <label for="key-virustotal">VirusTotal API Key</label>
          <input id="key-virustotal" type="password" autocomplete="off" spellcheck="false">
          <div class="cred-row"><span>VirusTotal</span><span id="cred-status-virustotal" class="cred-badge info">—</span></div>
        </div>
        <div>
          <label for="key-shodan">Shodan API Key</label>
          <input id="key-shodan" type="password" autocomplete="off" spellcheck="false">
          <div class="cred-row"><span>Shodan</span><span id="cred-status-shodan" class="cred-badge info">—</span></div>
        </div>
        <div>
          <label for="key-censys-id">Censys API ID</label>
          <input id="key-censys-id" type="password" autocomplete="off" spellcheck="false">
        </div>
        <div>
          <label for="key-censys-secret">Censys API Secret</label>
          <input id="key-censys-secret" type="password" autocomplete="off" spellcheck="false">
        </div>
        <div class="full">
          <div class="cred-row"><span>Censys (ID + Secret, or PAT)</span><span id="cred-status-censys" class="cred-badge info">—</span></div>
        </div>
        <div class="full">
          <label for="key-hunter">Hunter.io API Key</label>
          <input id="key-hunter" type="password" autocomplete="off" spellcheck="false">
          <div class="cred-row"><span>Hunter.io</span><span id="cred-status-hunter" class="cred-badge info">—</span></div>
        </div>
      </div>
      <div class="row" style="margin-top:16px">
        <button id="save-api-keys" type="button">Save &amp; Sync Keys</button>
        <button id="close-api-keys" class="secondary" type="button">Close</button>
      </div>
      <p id="api-keys-message" role="alert" style="font-size:12px"></p>
    </div>
  </div>
  <div id="scope-auth-modal" class="modal-backdrop" hidden role="dialog"
       aria-modal="true" aria-labelledby="scope-auth-title">
    <div class="modal-card">
      <h2 id="scope-auth-title">Scope &amp; Authorization Acknowledgment</h2>
      <p style="margin:8px 0;font-size:13px">
        Enabling <strong>Allow Active Recon</strong> permits direct network probes (e.g., port scanning, HTTP fingerprinting, directory enumeration) against target hosts.
      </p>
      <ul style="margin:8px 0;padding-left:20px;font-size:12.5px">
        <li>Verify that all target domains/IPs are listed in <code>Scope allow-domains</code> or explicitly authorized.</li>
        <li>Confirm you hold written authorization to perform active reconnaissance against these targets.</li>
        <li>Intrusive credential attacks remain strictly blocked by default.</li>
      </ul>
      <div class="row" style="margin-top:16px">
        <button id="confirm-scope-auth" type="button">I Confirm Authorization</button>
        <button id="cancel-scope-auth" class="secondary" type="button">Cancel</button>
      </div>
    </div>
  </div>
  <div id="cmd-palette-modal" class="modal-backdrop" hidden role="dialog"
       aria-modal="true" aria-labelledby="cmd-palette-title">
    <div class="modal-card">
      <div class="row" style="margin-bottom:8px">
        <h2 id="cmd-palette-title" style="margin:0">Command Palette</h2>
        <span class="spacer"></span>
        <span class="kbd-hint mono">↑↓ · Enter · Esc</span>
      </div>
      <input id="cmd-palette-input" type="search" autocomplete="off"
             placeholder="Jump to entity, switch tab, load demo, export bundle, toggle theme…">
      <ul id="cmd-palette-results" class="cmd-list" role="listbox"></ul>
      <div class="row" style="margin-top:12px">
        <span class="spacer"></span>
        <button id="close-cmd-palette" class="secondary compact" type="button">Close</button>
      </div>
    </div>
  </div>
  <div id="mcp-setup-modal" class="modal-backdrop" hidden role="dialog"
       aria-modal="true" aria-labelledby="mcp-setup-title">
    <div class="modal-card">
      <h2 id="mcp-setup-title">10-Second MCP Setup</h2>
      <p class="muted" style="margin:0 0 12px;font-size:12px">
        Connect AI OSINT Hub to your AI IDE or desktop agent via stdio MCP.
      </p>
      <div id="mcp-client-tabs" class="preset-bar" role="group" aria-label="MCP Client">
        <button type="button" class="preset-pill active" data-mcp-client="antigravity">Antigravity</button>
        <button type="button" class="preset-pill" data-mcp-client="claude">Claude Desktop</button>
        <button type="button" class="preset-pill" data-mcp-client="cursor">Cursor</button>
        <button type="button" class="preset-pill" data-mcp-client="vscode">VS Code</button>
      </div>
      <div class="muted mono" style="font-size:11.5px;margin-bottom:6px">
        Config path: <span id="mcp-config-path">—</span>
      </div>
      <pre id="mcp-config-pre" class="dossier-pre" style="min-height:140px"></pre>
      <div class="row" style="margin-top:12px">
        <button id="copy-mcp-config-btn" type="button">Copy JSON Config</button>
        <button id="close-mcp-setup" class="secondary" type="button">Close</button>
        <span id="mcp-copy-status" class="muted" style="font-size:12px"></span>
      </div>
    </div>
  </div>
</div>
<script>
(function () {
  "use strict";
  var state = {
    targetId: null,
    source: null,
    payload: null,
    analytics: null,
    cy: null,
    pathSourceId: null,
    selectedNode: null,
    graphView: {
      x: 0, y: 0, scale: 1, hidden: {}, search: "",
      cluster: "",
      renderer: "auto",
      shortestPathNodes: {},
      shortestPathEdges: {},
      showHypotheses: false,   // guessed permutations hidden by default
      showEdgeLabels: false    // permanent edge text off by default
    }
  };
  var TYPE_COLORS = {
    person: "#af3a03", username: "#076678", email: "#427b58", domain: "#b57614",
    subdomain: "#d65d0e", ip: "#458588", asn: "#689d6a", organization: "#9d0006",
    phone: "#076678", repository: "#665c54", social_profile: "#427b58",
    breach_record: "#9d0006", crypto_address: "#b57614", service: "#79740e",
    credential: "#cc241d", hash: "#7c6f64", port: "#d79921", location: "#689d6a",
    url: "#458588"
  };
  var TYPE_SHAPES = {
    person: "diamond", organization: "round-rectangle", domain: "hexagon",
    subdomain: "round-hexagon", ip: "rectangle", asn: "barrel",
    email: "ellipse", username: "ellipse", phone: "tag",
    hash: "cut-rectangle", service: "round-triangle", url: "vee",
    location: "pentagon", breach_record: "octagon", credential: "star"
  };
  var SVG_NS = "http://www.w3.org/2000/svg";

  function byId(id) { return document.getElementById(id); }
  function setText(id, text) {
    var node = byId(id);
    if (node) { node.textContent = (text === undefined || text === null) ? "" : String(text); }
  }
  function make(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }
  function svgNode(tag, cls) {
    var node = document.createElementNS(SVG_NS, tag);
    if (cls) { node.setAttribute("class", cls); }
    return node;
  }
  function readList(id) {
    var input = byId(id);
    if (!input) { return []; }
    return (input.value || "").split(/[\s,;]+/).filter(function (item) { return item; });
  }
  function setStatus(text, completed) {
    var node = byId("status-pill");
    if (!node) { return; }
    node.textContent = (text === undefined || text === null) ? "" : String(text);
    node.classList.toggle("completed",
      !!completed || node.textContent === "COMPLETED");
    var lowered = node.textContent.toLowerCase();
    if (lowered === "running" || lowered === "completed") {
      clearError();
    }
  }
  function isTransientNetworkError(err) {
    if (!err) { return false; }
    if (err.transient) { return true; }
    var message = String(err.message || err).toLowerCase();
    return message.indexOf("failed to fetch") !== -1
      || message.indexOf("networkerror") !== -1
      || message.indexOf("network error") !== -1
      || message.indexOf("load failed") !== -1;
  }
  function transientError(err) {
    var wrapped = new Error(String((err && err.message) || err || "network hiccup"));
    wrapped.transient = true;
    return wrapped;
  }
  function showError(err) {
    var node = byId("ui-message");
    if (!node) { return; }
    node.classList.add("error");
    node.textContent = (err && err.message) ? err.message : String(err);
  }
  function clearError() {
    var node = byId("ui-message");
    if (node) { node.classList.remove("error"); node.textContent = ""; }
  }
  function payloadStatus() {
    return (state.payload && state.payload.investigation)
      ? String(state.payload.investigation.status || "") : "";
  }
  function isTerminalStatus(status) {
    return status === "completed" || status === "terminated" || status === "failed";
  }
  function settleCompleted() {
    setStatus("COMPLETED", true);
    refreshState().then(function () {
      fetchDossier();
      fetchTimeline();
      updateDownloads();
      refreshCases();
    }).catch(function (err) { showError(err); });
  }
  function waitForCompletionAfterTimeout() {
    setStatus("waiting");
    var attempts = 0;
    function tick() {
      attempts += 1;
      refreshState().then(function () {
        var status = payloadStatus();
        if (isTerminalStatus(status)) {
          settleCompleted();
        } else if (attempts < 90) {
          window.setTimeout(tick, 1000);
        } else {
          setStatus("stream timeout");
        }
      }).catch(function () {
        if (attempts < 90) { window.setTimeout(tick, 1000); }
      });
    }
    tick();
  }

  function api(path, options) {
    return fetch(path, options || {}).catch(function (err) {
      if (isTransientNetworkError(err)) { throw transientError(err); }
      throw err;
    }).then(function (response) {
      return response.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : {}; } catch (err) { data = { raw: text }; }
        if (!response.ok) {
          throw new Error((data && (data.detail || data.errors)) || ("HTTP " + response.status));
        }
        return data;
      });
    });
  }

  function collectRequest() {
    return {
      raw_input: byId("in-raw").value,
      name: byId("in-name").value || null,
      usernames: readList("in-usernames"),
      emails: readList("in-emails"),
      domains: readList("in-domains"),
      phones: readList("in-phones"),
      org: byId("in-org").value || null,
      location: byId("in-location").value || null,
      urls: readList("in-urls"),
      ips: readList("in-ips"),
      allow_domains: readList("in-allow-domains"),
      allow_active_recon: byId("in-active").checked,
      max_iterations: Number(byId("in-max-iterations").value || 16),
      max_tool_calls: Number(byId("in-max-tool-calls").value || 20),
      wall_clock_timeout_sec: Number(byId("in-timeout").value || 600),
      min_pivot_threshold: Number(byId("in-threshold").value || 0.12),
      wait: byId("in-wait").checked
    };
  }

  function startInvestigation(event) {
    if (event) { event.preventDefault(); }
    clearError();
    setStatus("starting");
    api("/api/investigations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collectRequest())
    }).then(function (data) {
      if (!data || !data.target_id) { throw new Error("no target_id returned"); }
      state.targetId = data.target_id;
      state.pathSourceId = null;
      state.graphView.shortestPathNodes = {};
      state.graphView.shortestPathEdges = {};
      setText("target-label", data.target_id);
      setStatus(data.status === "started" ? "running" : String(data.status || ""));
      if (data.status === "started") { connectStream(); }
      updateDownloads();
      refreshCases();
      return refreshState();
    }).catch(function (err) { setStatus("error"); showError(err); });
  }

  function connectStream() {
    if (state.source) { state.source.close(); state.source = null; }
    if (!state.targetId) { return; }
    var source = new EventSource("/api/investigations/" + encodeURIComponent(state.targetId) + "/stream");
    state.source = source;
    ["snapshot", "iteration", "ledger", "graph_delta", "done", "timeout", "error"]
      .forEach(function (name) {
        source.addEventListener(name, function (event) {
          var data = {};
          try { data = JSON.parse(event.data); } catch (err) { data = {}; }
          if (name === "snapshot" || name === "iteration") {
            setStatus(data.investigation ? String(data.investigation.status) : "running");
          } else if (name === "done") {
            if (state.source) { state.source.close(); state.source = null; }
            settleCompleted();
            return;
          } else if (name === "timeout") {
            if (state.source) { state.source.close(); state.source = null; }
            waitForCompletionAfterTimeout();
            return;
          } else if (name === "error") {
            setStatus("stream error");
            if (state.source) { state.source.close(); state.source = null; }
          }
          refreshState();
        });
      });
    source.onerror = function () {
      if (state.source) { state.source.close(); state.source = null; }
      refreshState().then(function () {
        if (isTerminalStatus(payloadStatus())) {
          settleCompleted();
        } else if (byId("status-pill").textContent !== "COMPLETED") {
          setStatus("stream closed");
        }
      }).catch(function () {
        if (byId("status-pill").textContent !== "COMPLETED") {
          setStatus("stream closed");
        }
      });
    };
  }

  function summarize(payload) {
    var stats = payload.stats || {};
    return "entities " + (stats.entities || 0) + " · claims " + (stats.claims || 0) +
      " · artifacts " + (stats.artifacts || 0) + " · contradictions " + (stats.contradictions || 0);
  }

  function refreshState() {
    if (!state.targetId) { return Promise.resolve(); }
    return api("/api/investigations/" + encodeURIComponent(state.targetId)).then(function (payload) {
      state.payload = payload;
      renderGraph(payload);
      renderTelemetry(payload);
      renderAiInsights(payload);
      updateScopeSummary(payload);
      setText("stats-line", summarize(payload));
      fetchAnalytics();
      clearError();
    }).catch(function (err) {
      // Uvicorn may briefly reject fetches while a heavy subprocess/SSE poll is
      // running. During an active investigation, retry silently instead of
      // painting a red banner over a healthy run.
      if (isTransientNetworkError(err)) {
        if (state.targetId) {
          window.setTimeout(function () { refreshState(); }, 1200);
        }
        return;
      }
      showError(err);
    });
  }

  var INNER_RING_TYPES = {
    username: true, email: true, phone: true, organization: true, location: true
  };

  function applyGraphTransform() {
    var viewport = byId("graph-viewport");
    if (!viewport) { return; }
    var view = state.graphView;
    viewport.setAttribute("transform", "translate(" + view.x + "," + view.y +
      ") scale(" + view.scale + ")");
  }

  function renderTypeFilters(allNodes) {
    var container = byId("type-filters");
    if (!container) { return; }
    var counts = {};
    allNodes.forEach(function (node) {
      counts[node.type] = (counts[node.type] || 0) + 1;
    });
    container.textContent = "";
    Object.keys(counts).sort().forEach(function (type) {
      var active = !state.graphView.hidden[type];
      var pill = make("button", "filter-pill" + (active ? " active" : ""),
        String(type) + " ");
      pill.type = "button";
      pill.setAttribute("aria-pressed", active ? "true" : "false");
      var count = make("span", "count", String(counts[type]));
      pill.appendChild(count);
      pill.addEventListener("click", function () {
        if (state.graphView.hidden[type]) {
          delete state.graphView.hidden[type];
        } else {
          state.graphView.hidden[type] = true;
        }
        if (state.payload) { renderGraph(state.payload); }
      });
      container.appendChild(pill);
    });
  }

  function clusterNodeLookup() {
    var map = {};
    var clusters = (state.analytics && (state.analytics.clusters || state.analytics.communities)) || [];
    clusters.forEach(function (cluster, idx) {
      var cid = Array.isArray(cluster) ? ("c" + (idx + 1)) : String(cluster.cluster_id || ("c" + (idx + 1)));
      var members = Array.isArray(cluster) ? cluster : (cluster.node_ids || []);
      members.forEach(function (nid) {
        map[nid] = cid;
      });
    });
    return map;
  }

  function updateClusterSelect() {
    var sel = byId("cluster-filter");
    if (!sel) { return; }
    var prev = state.graphView.cluster || "";
    sel.textContent = "";
    var allOpt = make("option", "", "All clusters");
    allOpt.value = "";
    sel.appendChild(allOpt);
    var clusters = (state.analytics && (state.analytics.clusters || state.analytics.communities)) || [];
    clusters.forEach(function (cluster, idx) {
      var members = Array.isArray(cluster) ? cluster : (cluster.node_ids || []);
      var cid = Array.isArray(cluster) ? ("c" + (idx + 1)) : String(cluster.cluster_id || ("c" + (idx + 1)));
      var size = Array.isArray(cluster) ? members.length : (cluster.size || members.length);
      var opt = make("option", "", cid + " (" + size + ")");
      opt.value = cid;
      if (cid === prev) { opt.selected = true; }
      sel.appendChild(opt);
    });
  }

  function layoutGraph(nodes, edges) {
    var width = 960, height = 620, cx = width / 2, cy = height / 2;
    var positions = {}, targets = {};
    if (!nodes.length) { return positions; }
    var center = null;
    nodes.forEach(function (node) {
      if (!center && node.type === "person") { center = node; }
    });
    if (!center) { center = nodes[0]; }
    var centerId = center.id;
    var inner = [], outer = [];
    nodes.forEach(function (node) {
      if (node.id === centerId) { return; }
      if (INNER_RING_TYPES[node.type]) { inner.push(node); }
      else { outer.push(node); }
    });
    positions[centerId] = { x: cx, y: cy };
    targets[centerId] = { x: cx, y: cy, radius: 0, angle: 0 };
    function ring(list, baseRadius, phase) {
      var count = list.length;
      list.forEach(function (node, index) {
        var angle = phase + (2 * Math.PI * index) / Math.max(1, count);
        var layer = Math.floor(index / 18);
        var radius = baseRadius + layer * 44;
        var x = cx + radius * Math.cos(angle);
        var y = cy + radius * Math.sin(angle);
        positions[node.id] = { x: x, y: y };
        targets[node.id] = { x: x, y: y, radius: radius, angle: angle };
      });
    }
    ring(inner, 185, -Math.PI / 2);
    ring(outer, 330, -Math.PI / 2 + 0.30);
    var ids = nodes.map(function (node) { return node.id; })
      .filter(function (id) { return !!positions[id]; });
    var edgePairs = edges.filter(function (edge) {
      return positions[edge.subject] && positions[edge.object];
    });

    // Deterministic radial relaxation: every node is anchored to its assigned
    // concentric ring (radius + angle) with a strong radial spring; repulsion
    // and edge springs only perturb. Coordinates are NEVER rectangle-clamped,
    // so 150+ nodes can never line the canvas walls.
    var k_radial = 0.085, k_edge = 0.018, max_step = 8;
    for (var iteration = 0; iteration < 90; iteration += 1) {
      var displacement = {};
      ids.forEach(function (id) { displacement[id] = { x: 0, y: 0 }; });
      for (var i = 0; i < ids.length; i += 1) {
        for (var j = i + 1; j < ids.length; j += 1) {
          var a = positions[ids[i]], b = positions[ids[j]];
          var dx = a.x - b.x, dy = a.y - b.y;
          var dist2 = dx * dx + dy * dy;
          if (dist2 < 1) { dist2 = 1; }
          var dist = Math.sqrt(dist2);
          var repel = Math.min(32, 12000 / dist2);
          var ux = dx / dist, uy = dy / dist;
          displacement[ids[i]].x += ux * repel;
          displacement[ids[i]].y += uy * repel;
          displacement[ids[j]].x -= ux * repel;
          displacement[ids[j]].y -= uy * repel;
        }
      }
      edgePairs.forEach(function (edge) {
        var a = positions[edge.subject], b = positions[edge.object];
        var dx = b.x - a.x, dy = b.y - a.y;
        var dist = Math.sqrt(dx * dx + dy * dy) || 1;
        var spring = (dist - 155) * k_edge;
        var ux = dx / dist, uy = dy / dist;
        displacement[edge.subject].x += ux * spring;
        displacement[edge.subject].y += uy * spring;
        displacement[edge.object].x -= ux * spring;
        displacement[edge.object].y -= uy * spring;
      });
      ids.forEach(function (id) {
        if (id === centerId) { return; }
        var target = targets[id];
        // Strong radial spring toward the assigned ring target point.
        displacement[id].x += (target.x - positions[id].x) * k_radial;
        displacement[id].y += (target.y - positions[id].y) * k_radial;
        positions[id].x += Math.max(-max_step, Math.min(max_step, displacement[id].x));
        positions[id].y += Math.max(-max_step, Math.min(max_step, displacement[id].y));
      });
    }

    // Circular, aspect-preserving fit: scale all non-center nodes about (cx,cy)
    // by max_radius, never by independent x/y clamps.
    var maxRadius = 1;
    ids.forEach(function (id) {
      if (id === centerId) { return; }
      var dx = positions[id].x - cx, dy = positions[id].y - cy;
      maxRadius = Math.max(maxRadius, Math.sqrt(dx * dx + dy * dy));
    });
    var fitRadius = Math.min(width, height) / 2 - 42;
    var fitScale = Math.min(1, fitRadius / maxRadius);
    ids.forEach(function (id) {
      if (id === centerId) {
        positions[id].x = cx;
        positions[id].y = cy;
        return;
      }
      positions[id].x = cx + (positions[id].x - cx) * fitScale;
      positions[id].y = cy + (positions[id].y - cy) * fitScale;
    });
    return positions;
  }

  function renderGraph(payload) {
    var svg = byId("graph");
    if (!svg) { return; }
    while (svg.firstChild) { svg.removeChild(svg.firstChild); }
    var graph = payload.graph || { nodes: [], edges: [] };
    var nodes = graph.nodes || [];
    var edges = graph.edges || [];
    var firstRun = byId("first-run-panel");
    if (firstRun) { firstRun.hidden = nodes.length > 0; }
    renderTypeFilters(nodes);
    if (!nodes.length) {
      var empty = svgNode("text", "empty");
      empty.setAttribute("x", "28");
      empty.setAttribute("y", "44");
      empty.textContent = "No graph data yet — start an investigation.";
      svg.appendChild(empty);
      renderCytoscape([], [], {}, payload);
      return;
    }
    var hypothesisCount = nodes.filter(function (node) {
      return !!node.is_hypothesis;
    }).length;
    setText("hyp-count", String(hypothesisCount));
    var clusters = clusterNodeLookup();
    var clusterFilter = state.graphView.cluster || "";
    var visibleNodes = nodes.filter(function (node) {
      if (state.graphView.hidden[node.type]) { return false; }
      if (node.is_hypothesis && !state.graphView.showHypotheses) { return false; }
      if (clusterFilter && clusters[node.id] !== clusterFilter) { return false; }
      return true;
    });
    var visibleIds = {};
    visibleNodes.forEach(function (node) { visibleIds[node.id] = true; });
    var visibleEdges = edges.filter(function (edge) {
      return visibleIds[edge.subject] && visibleIds[edge.object];
    });
    var positions = layoutGraph(visibleNodes, visibleEdges);
    var viewport = svgNode("g");
    viewport.setAttribute("id", "graph-viewport");
    var search = String(state.graphView.search || "").toLowerCase();
    var nodeRadius = visibleNodes.length > 90 ? 11 : 15;
    var showEdgeLabels = !!state.graphView.showEdgeLabels;
    var pathEdges = state.graphView.shortestPathEdges || {};
    var pathNodes = state.graphView.shortestPathNodes || {};
    visibleEdges.forEach(function (edge) {
      var from = positions[edge.subject], to = positions[edge.object];
      if (!from || !to) { return; }
      var isPath = !!pathEdges[edge.id];
      var line = svgNode("line", "edge-line" + (isPath ? " path-highlight" : ""));
      line.setAttribute("x1", from.x); line.setAttribute("y1", from.y);
      line.setAttribute("x2", to.x); line.setAttribute("y2", to.y);
      line.addEventListener("click", function () { inspectClaim(edge, payload); });
      var tip = svgNode("title");
      tip.textContent = edge.predicate + " (" +
        Number(edge.confidence || 0).toFixed(2) + ")";
      line.appendChild(tip);
      viewport.appendChild(line);
      if (showEdgeLabels) {
        var label = svgNode("text", "edge-label");
        label.setAttribute("x", (from.x + to.x) / 2);
        label.setAttribute("y", (from.y + to.y) / 2 - 3);
        label.setAttribute("text-anchor", "middle");
        label.textContent = edge.predicate + " " +
          Number(edge.confidence || 0).toFixed(2);
        viewport.appendChild(label);
      }
    });
    visibleNodes.forEach(function (node) {
      var position = positions[node.id];
      if (!position) { return; }
      var group = svgNode("g", "node");
      if (search) {
        var haystack = (String(node.type) + " " + String(node.value)).toLowerCase();
        group.setAttribute("class", "node " +
          (haystack.indexOf(search) !== -1 ? "node-match" : "node-dim"));
      } else if (Object.keys(pathNodes).length) {
        group.setAttribute("class", "node " +
          (pathNodes[node.id] ? "node-match" : "node-dim"));
      }
      group.setAttribute("transform", "translate(" + position.x + "," + position.y + ")");
      var circle = svgNode("circle", "node-circle");
      circle.setAttribute("r", String(nodeRadius));
      circle.setAttribute("fill", TYPE_COLORS[node.type] || "#665c54");
      circle.addEventListener("click", function () { inspectEntity(node, payload); });
      var tip = svgNode("title");
      tip.textContent = node.type + ": " + node.value;
      circle.appendChild(tip);
      group.appendChild(circle);
      if (visibleNodes.length <= 150) {
        var typeLabel = svgNode("text", "node-label");
        typeLabel.setAttribute("text-anchor", "middle");
        typeLabel.setAttribute("y", String(nodeRadius + 14));
        typeLabel.textContent = String(node.type) + " · " +
          String(node.status || "").slice(0, 10);
        group.appendChild(typeLabel);
        var valueLabel = svgNode("text", "node-label");
        valueLabel.setAttribute("text-anchor", "middle");
        valueLabel.setAttribute("y", String(nodeRadius + 27));
        valueLabel.textContent = String(node.value || "").slice(0, 22);
        group.appendChild(valueLabel);
      }
      viewport.appendChild(group);
    });
    svg.appendChild(viewport);
    applyGraphTransform();
    renderCytoscape(visibleNodes, visibleEdges, positions, payload);
    clearError();
  }

  function syncGraphRendererVisibility() {
    var cyEl = byId("cy-graph");
    var svgEl = byId("graph");
    var toggleBtn = byId("toggle-graph-engine");
    if (!cyEl || !svgEl) { return; }
    var canCy = typeof window.cytoscape === "function";
    var useCy = (state.graphView.renderer === "cy" && canCy) ||
      (state.graphView.renderer === "auto" && canCy);
    cyEl.classList.toggle("graph-hidden", !useCy);
    svgEl.classList.toggle("graph-hidden", useCy);
    if (toggleBtn) {
      toggleBtn.textContent = useCy ? "View: Cytoscape" : "View: SVG";
    }
  }

  function renderCytoscape(visibleNodes, visibleEdges, positions, payload) {
    syncGraphRendererVisibility();
    var cyEl = byId("cy-graph");
    if (!cyEl || typeof window.cytoscape !== "function") { return; }
    var degreeMap = (state.analytics && (state.analytics.degree_centrality ||
      (state.analytics.centrality && state.analytics.centrality.degree))) || {};
    var search = String(state.graphView.search || "").toLowerCase();
    var pathNodes = state.graphView.shortestPathNodes || {};
    var pathEdges = state.graphView.shortestPathEdges || {};
    var hasPath = Object.keys(pathNodes).length > 0;
    var elements = [];
    var nodeMap = {};
    var edgeMap = {};
    visibleNodes.forEach(function (node) {
      nodeMap[node.id] = node;
      var deg = Number(degreeMap[node.id] || 0);
      var size = Math.round(28 + Math.min(28, deg * 44));
      var matchesSearch = search ?
        (String(node.type) + " " + String(node.value)).toLowerCase().indexOf(search) !== -1 : false;
      var classes = [];
      if (search) { classes.push(matchesSearch ? "matched" : "dimmed"); }
      else if (hasPath) { classes.push(pathNodes[node.id] ? "path-node" : "dimmed"); }
      if (node.is_hypothesis) { classes.push("hyp"); }
      elements.push({
        data: {
          id: node.id,
          label: String(node.value || "").slice(0, 22),
          type: node.type,
          status: node.status,
          color: TYPE_COLORS[node.type] || "#665c54",
          shape: TYPE_SHAPES[node.type] || "ellipse",
          size: size
        },
        position: positions[node.id] || { x: 480, y: 310 },
        classes: classes.join(" ")
      });
    });
    visibleEdges.forEach(function (edge) {
      edgeMap[edge.id] = edge;
      var conf = Number(edge.confidence || 0.3);
      var classes = [];
      if (pathEdges[edge.id]) { classes.push("path-edge"); }
      else if (hasPath) { classes.push("dimmed"); }
      if (edge.status === "CONTRADICTED") { classes.push("contradicted"); }
      elements.push({
        data: {
          id: edge.id,
          source: edge.subject,
          target: edge.object,
          label: state.graphView.showEdgeLabels ?
            (edge.predicate + " " + conf.toFixed(2)) : "",
          width: Math.max(1.2, Math.min(4.5, 1 + conf * 3.2))
        },
        classes: classes.join(" ")
      });
    });
    if (state.cy) {
      try { state.cy.destroy(); } catch (err) { /* ignore */ }
      state.cy = null;
    }
    var styleList = [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          "shape": "data(shape)",
          "width": "data(size)",
          "height": "data(size)",
          "label": "data(label)",
          "color": "#282828",
          "font-size": "10px",
          "font-family": "Inter, Segoe UI, sans-serif",
          "text-valign": "bottom",
          "text-margin-y": 5,
          "border-width": 2,
          "border-color": "#fbf1c7"
        }
      },
      {
        selector: "edge",
        style: {
          "width": "data(width)",
          "line-color": "#bdae93",
          "target-arrow-color": "#bdae93",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "label": "data(label)",
          "font-size": "9px",
          "color": "#665c54",
          "text-background-color": "#fbf1c7",
          "text-background-opacity": 0.9
        }
      },
      { selector: "node.hyp", style: { "border-style": "dashed", "border-color": "#b57614" } },
      { selector: "node.matched", style: { "border-width": 4, "border-color": "#af3a03" } },
      { selector: "node.path-node", style: { "border-width": 4, "border-color": "#af3a03" } },
      { selector: "edge.path-edge", style: { "line-color": "#af3a03", "target-arrow-color": "#af3a03", "width": 3.5 } },
      { selector: "edge.contradicted", style: { "line-color": "#9d0006", "target-arrow-color": "#9d0006", "line-style": "dashed" } },
      { selector: ".dimmed", style: { "opacity": 0.2 } }
    ];
    state.cy = window.cytoscape({
      container: cyEl,
      elements: elements,
      style: styleList,
      layout: { name: "preset" },
      minZoom: 0.25,
      maxZoom: 3.5,
      wheelSensitivity: 0.25
    });
    state.cy.on("tap", "node", function (evt) {
      var node = nodeMap[evt.target.id()];
      if (node && state.payload) { inspectEntity(node, state.payload); }
    });
    state.cy.on("tap", "edge", function (evt) {
      var edge = edgeMap[evt.target.id()];
      if (edge && state.payload) { inspectClaim(edge, state.payload); }
    });
    state.cy.fit(undefined, 28);
  }

  function zoomGraph(factor) {
    var view = state.graphView;
    view.scale = Math.max(0.3, Math.min(3.5, view.scale * factor));
    applyGraphTransform();
    if (state.cy) {
      state.cy.zoom(state.cy.zoom() * factor);
      state.cy.center();
    }
  }

  function resetGraphView() {
    state.graphView.x = 0;
    state.graphView.y = 0;
    state.graphView.scale = 1;
    applyGraphTransform();
    if (state.cy) { state.cy.fit(undefined, 28); }
  }

  function configureGraphInteraction() {
    var svg = byId("graph");
    if (!svg || svg.dataset.interactive === "1") { return; }
    svg.dataset.interactive = "1";
    svg.addEventListener("wheel", function (event) {
      event.preventDefault();
      zoomGraph(event.deltaY < 0 ? 1.12 : 0.89);
    }, { passive: false });
    var drag = null;
    svg.addEventListener("mousedown", function (event) {
      if (event.target && event.target.closest &&
          event.target.closest(".node")) { return; }
      drag = { x: event.clientX, y: event.clientY,
               startX: state.graphView.x, startY: state.graphView.y };
    });
    window.addEventListener("mousemove", function (event) {
      if (!drag) { return; }
      state.graphView.x = drag.startX + (event.clientX - drag.x);
      state.graphView.y = drag.startY + (event.clientY - drag.y);
      applyGraphTransform();
    });
    window.addEventListener("mouseup", function () { drag = null; });
  }

  function clearForm() {
    ["in-raw", "in-name", "in-usernames", "in-emails", "in-domains",
     "in-phones", "in-org", "in-location", "in-urls", "in-ips",
     "in-allow-domains"].forEach(function (id) {
      var node = byId(id);
      if (node) { node.value = ""; }
    });
    ["in-active", "in-wait"].forEach(function (id) {
      var node = byId(id);
      if (node) { node.checked = false; }
    });
    var defaults = { "in-max-iterations": "16", "in-max-tool-calls": "20",
                     "in-timeout": "600", "in-threshold": "0.12" };
    Object.keys(defaults).forEach(function (id) {
      var node = byId(id);
      if (node) { node.value = defaults[id]; }
    });
    ["show-hypotheses", "show-edge-labels"].forEach(function (id) {
      var node = byId(id);
      if (node) { node.checked = false; }
    });
    state.graphView.showHypotheses = false;
    state.graphView.showEdgeLabels = false;
    if (state.payload) { renderGraph(state.payload); }
    clearError();
    setStatus("idle");
  }

  function firstArtifact(claims, payload) {
    var artifacts = (payload && payload.artifacts) || {};
    for (var index = 0; index < claims.length; index += 1) {
      var ids = claims[index].artifact_ids || [];
      for (var inner = 0; inner < ids.length; inner += 1) {
        if (artifacts[ids[inner]]) { return artifacts[ids[inner]]; }
      }
    }
    return null;
  }

  function renderInspectorExtras(entityId, artifact, payload) {
    var qBox = byId("inspector-quarantine");
    if (qBox) {
      qBox.textContent = "";
      var snippet = artifact ? String(artifact.raw_evidence_snippet || "") : "";
      if (snippet.indexOf("INJECTION") !== -1 || snippet.indexOf("</untrusted") !== -1) {
        qBox.appendChild(make("div", "quarantine-alert",
          "Quarantine notice: untrusted OSINT snippet sanitized."));
      }
    }
    var cBox = byId("inspector-contradictions");
    if (cBox) {
      cBox.textContent = "";
      var contradictions = (payload && payload.contradictions) || [];
      var matched = entityId ? contradictions.filter(function (c) {
        return c.subject_id === entityId;
      }) : [];
      if (matched.length) {
        cBox.appendChild(make("div", "muted", "Contradictions (" + matched.length + ")"));
        matched.forEach(function (c) {
          var row = make("div", "claim-line");
          row.appendChild(make("span", "badge CONTRADICTED", "CONTRADICTED"));
          row.appendChild(make("span", "", " " + String(c.predicate || "")));
          cBox.appendChild(row);
        });
      }
    }
  }

  function renderInspector(title, badge, artifact, claims, entityId, payload) {
    setText("inspector-title", title);
    var badgeNode = byId("epistemic-badge");
    if (badgeNode) {
      badgeNode.className = "badge " + String(badge || "");
      badgeNode.textContent = badge || "—";
    }
    setText("artifact-sha", artifact ? artifact.raw_output_sha256 : "no cited artifact");
    setText("artifact-tool", artifact ? artifact.source_tool : "—");
    setText("artifact-confidence", artifact ? Number(artifact.confidence || 0).toFixed(3) : "—");
    setText("artifact-snippet", artifact ? artifact.raw_evidence_snippet : "No evidence artifact attached.");
    renderInspectorExtras(entityId, artifact, payload);
    var container = byId("inspector-claims");
    if (!container) { return; }
    while (container.firstChild) { container.removeChild(container.firstChild); }
    (claims || []).slice(0, 12).forEach(function (claim) {
      var line = make("div", "claim-line");
      line.appendChild(make("span", "", String(claim.predicate || "")));
      line.appendChild(make("span", "muted", " → " + String(claim.object || "")));
      var status = make("span", "badge " + String(claim.status || ""), claim.status || "");
      status.style.marginLeft = "6px";
      line.appendChild(status);
      line.appendChild(make("span", "muted",
        " " + Number(claim.confidence || 0).toFixed(2)));
      container.appendChild(line);
    });
  }

  function inspectEntity(node, payload) {
    state.selectedNode = node;
    var pivotBtn = byId("inspect-pivot-btn");
    var srcBtn = byId("set-path-source-btn");
    var dstBtn = byId("find-path-btn");
    if (pivotBtn) { pivotBtn.disabled = false; }
    if (srcBtn) { srcBtn.disabled = false; }
    if (dstBtn) { dstBtn.disabled = !state.pathSourceId || state.pathSourceId === node.id; }
    var claims = node.claims || [];
    renderInspector(node.type + ": " + node.value, node.status,
      firstArtifact(claims, payload), claims, node.id, payload);
    markChecklistStep(2);
  }

  function inspectClaim(edge, payload) {
    state.selectedNode = null;
    var pivotBtn = byId("inspect-pivot-btn");
    if (pivotBtn) { pivotBtn.disabled = true; }
    var claim = {
      predicate: edge.predicate,
      object: edge.object,
      status: edge.status,
      confidence: edge.confidence,
      artifact_ids: edge.artifact_ids || []
    };
    renderInspector("edge: " + edge.predicate, edge.status,
      firstArtifact([claim], payload), [claim], null, payload);
  }

  function renderTelemetry(payload) {
    var container = byId("telemetry");
    if (!container) { return; }
    while (container.firstChild) { container.removeChild(container.firstChild); }
    var ledger = payload.ledger || [];
    var hypotheses = payload.hypotheses || [];
    var contradictions = payload.contradictions || [];
    var pivots = payload.pivots || [];

    function section(title, rows, emptyText) {
      var box = make("section", "telemetry-section");
      box.appendChild(make("h3", "", title));
      if (!rows.length) {
        box.appendChild(make("p", "muted", emptyText));
        return box;
      }
      var list = make("ul", "telemetry-list");
      rows.forEach(function (row) { list.appendChild(row); });
      box.appendChild(list);
      return box;
    }

    container.appendChild(section("Queued Next Pivots", pivots.slice(0, 15).map(function (pivot) {
      var item = make("li", "row");
      var label = make("span", "", pivot.tool_id + " · score ");
      label.appendChild(make("span", "pivot-score", Number(pivot.score || 0).toFixed(3)));
      item.appendChild(label);
      item.appendChild(make("span", "muted", " — " + String(pivot.rationale || "").slice(0, 80)));
      item.appendChild(make("span", "spacer"));
      var btn = make("button", "secondary compact", "Execute");
      btn.type = "button";
      btn.addEventListener("click", function () { runSpecificPivot(pivot.pivot_id); });
      item.appendChild(btn);
      return item;
    }), "No pending ranked pivots."));

    container.appendChild(section("Execution ledger", ledger.slice(-40).map(function (entry) {
      var item = make("li");
      item.appendChild(make("b", "", entry.tool_id));
      item.appendChild(make("span", "muted", " · " + entry.status +
        " · " + entry.duration_ms + "ms"));
      if (entry.error_code) { item.appendChild(make("span", "", " · " + entry.error_code)); }
      return item;
    }), "No tool executions yet."));

    container.appendChild(section("Open / recent hypotheses", hypotheses.slice(-40).map(function (hypothesis) {
      var item = make("li");
      item.appendChild(make("span", "badge", hypothesis.status));
      item.appendChild(make("span", "", " " + hypothesis.type + " — " + hypothesis.question));
      return item;
    }), "No hypotheses yet."));

    container.appendChild(section("Contradictions", contradictions.map(function (contradiction) {
      var item = make("li");
      item.appendChild(make("span", "badge CONTRADICTED", "CONTRADICTED"));
      item.appendChild(make("span", "", " " + contradiction.predicate + " on " +
        contradiction.subject + (contradiction.resolved ? " (resolved)" : " (unresolved)")));
      return item;
    }), "No functional contradictions detected."));

    var analyticsBox = make("section", "telemetry-section");
    analyticsBox.appendChild(make("h3", "", "Graph Analytics Summary"));
    analyticsBox.id = "analytics-summary-box";
    analyticsBox.appendChild(make("p", "muted", "Analytics load automatically for active investigations."));
    container.appendChild(analyticsBox);
    renderAnalyticsSummary();
  }

  function renderAnalyticsSummary() {
    var box = byId("analytics-summary-box");
    if (!box || !state.analytics) { return; }
    while (box.children.length > 1) { box.removeChild(box.lastChild); }
    var a = state.analytics;
    var clusters = a.clusters || a.communities || [];
    var bridges = a.bridge_entities || a.bridges || [];
    var phashes = a.perceptual_hash_clusters || a.phash_correlations || [];
    var summary = make("p", "mono", "clusters: " + clusters.length +
      " · bridges: " + bridges.length + " · phash/favicon groups: " + phashes.length);
    box.appendChild(summary);
    var deg = a.degree_centrality || (a.centrality && a.centrality.degree) || {};
    var top = Object.keys(deg).sort(function (x, y) { return deg[y] - deg[x]; }).slice(0, 6);
    if (top.length) {
      var list = make("ul", "telemetry-list");
      top.forEach(function (nid) {
        var li = make("li");
        li.textContent = nid + " · degree centrality " + Number(deg[nid] || 0).toFixed(3);
        list.appendChild(li);
      });
      box.appendChild(list);
    }
  }

  function fetchAnalytics() {
    if (!state.targetId) { return Promise.resolve(); }
    return api("/api/investigations/" + encodeURIComponent(state.targetId) + "/analytics")
      .then(function (data) {
        state.analytics = data;
        updateClusterSelect();
        renderAnalyticsSummary();
        if (state.payload) { renderGraph(state.payload); }
      }).catch(function () { /* non-blocking advisory analytics */ });
  }

  function findShortestPath() {
    if (!state.targetId || !state.pathSourceId || !state.selectedNode) { return; }
    var destId = state.selectedNode.id;
    api("/api/investigations/" + encodeURIComponent(state.targetId) +
      "/analytics?source_id=" + encodeURIComponent(state.pathSourceId) +
      "&dest_id=" + encodeURIComponent(destId))
      .then(function (data) {
        var sp = data && data.shortest_path;
        state.graphView.shortestPathNodes = {};
        state.graphView.shortestPathEdges = {};
        if (sp && sp.found) {
          var pathIds = sp.path || sp.node_ids || [];
          pathIds.forEach(function (id) { state.graphView.shortestPathNodes[id] = true; });
          (sp.edges || []).forEach(function (e) { if (e.claim_id) { state.graphView.shortestPathEdges[e.claim_id] = true; } });
          var hops = (sp.length !== undefined && sp.length !== null) ? sp.length : (sp.hops || 0);
          setText("path-status-line", "Path found: " + hops + " hops");
        } else {
          setText("path-status-line", "No path between selected entities");
        }
        if (state.payload) { renderGraph(state.payload); }
      }).catch(function (err) { showError(err); });
  }

  function clearShortestPath() {
    state.pathSourceId = null;
    state.graphView.shortestPathNodes = {};
    state.graphView.shortestPathEdges = {};
    setText("path-status-line", "");
    var dstBtn = byId("find-path-btn");
    if (dstBtn) { dstBtn.disabled = true; }
    if (state.payload) { renderGraph(state.payload); }
  }

  function fetchTimeline() {
    if (!state.targetId) { return Promise.resolve(); }
    return api("/api/investigations/" + encodeURIComponent(state.targetId) + "/timeline")
      .then(function (data) {
        var list = byId("timeline-list");
        if (!list) { return; }
        list.textContent = "";
        var events = (data && data.events) || [];
        setText("timeline-summary", events.length + " event(s)");
        if (!events.length) {
          list.appendChild(make("li", "muted", "No timeline events recorded yet."));
          return;
        }
        events.forEach(function (ev) {
          var li = make("li");
          li.appendChild(make("span", "timeline-ts muted", String(ev.timestamp_utc || "") + " "));
          li.appendChild(make("span", "badge", String(ev.event_type || ev.kind || "event")));
          li.appendChild(make("strong", "", " " + String(ev.title || "")));
          if (ev.detail) {
            li.appendChild(make("div", "muted", String(ev.detail).slice(0, 180)));
          }
          list.appendChild(li);
        });
      }).catch(function () { /* ignore transient timeline errors */ });
  }

  function runCaseDiff() {
    var otherId = byId("diff-target-select") ? byId("diff-target-select").value : "";
    if (!state.targetId || !otherId) {
      setText("diff-results", "Select an active investigation and a comparison case first.");
      return;
    }
    activateTab("timeline");
    api("/api/investigations/" + encodeURIComponent(state.targetId) +
      "/diff/" + encodeURIComponent(otherId)).then(function (data) {
      var box = byId("diff-results");
      if (!box) { return; }
      box.textContent = "";
      var summary = data.summary || {};
      box.appendChild(make("div", "mono",
        "Compared " + state.targetId + " vs " + otherId + " — added: " +
        (summary.added_count || (data.added_entities || []).length) +
        " · removed: " + (summary.removed_count || (data.removed_entities || []).length) +
        " · status changes: " + (data.status_changes || []).length));
      var ul = make("ul", "telemetry-list");
      (data.added_entities || []).slice(0, 25).forEach(function (ent) {
        ul.appendChild(make("li", "", "+ " + ent.type + ": " + (ent.canonical_value || ent.value || "")));
      });
      (data.removed_entities || []).slice(0, 25).forEach(function (ent) {
        ul.appendChild(make("li", "", "- " + ent.type + ": " + (ent.canonical_value || ent.value || "")));
      });
      box.appendChild(ul);
    }).catch(function (err) { showError(err); });
  }

  function renderAiInsights(payload) {
    var list = byId("ai-insights-list");
    if (!list) { return; }
    list.textContent = "";
    var items = (payload && payload.ai_insights) || [];
    if (!items.length) {
      list.appendChild(make("p", "muted", "No AI reflections recorded for this case yet."));
      return;
    }
    items.forEach(function (ins) {
      var card = make("div", "claim-line");
      var head = make("div", "row");
      head.appendChild(make("span", "badge AI_INFERRED", ins.epistemic_provenance || "AI_INFERRED"));
      head.appendChild(make("span", "mono muted",
        " " + (ins.provider || "") + "/" + (ins.model || "") + " · " + (ins.kind || "reflection")));
      card.appendChild(head);
      card.appendChild(make("div", "", ins.summary || ""));
      list.appendChild(card);
    });
  }

  function copyTextToClipboard(text, statusEl) {
    var val = String(text || "");
    if (!val) { return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(val).then(function () {
        if (statusEl) { statusEl.textContent = "Copied!"; }
      }).catch(function () {
        if (statusEl) { statusEl.textContent = "Select and copy manually."; }
      });
      return;
    }
    var ta = document.createElement("textarea");
    ta.value = val;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      if (statusEl) { statusEl.textContent = "Copied!"; }
    } catch (err) {
      if (statusEl) { statusEl.textContent = "Copy unavailable."; }
    }
    document.body.removeChild(ta);
  }

  function renderAiLabStatus(data) {
    var preset = String(data.preset || (data.enabled ? (data.provider === "ollama" ? "vram_8gb" : "cloud_byok") : "disabled"));
    var labPreset = byId("ai-lab-preset");
    if (labPreset && preset) { labPreset.value = preset; }
    var railPreset = byId("ai-preset");
    if (railPreset && preset) { railPreset.value = preset; }
    var labBadge = byId("ai-lab-badge");
    if (labBadge) { labBadge.textContent = data.enabled ? (preset + " · " + String(data.provider || "")) : "disabled"; }

    var statusEl = byId("ai-models-status");
    if (statusEl) {
      var installed = data.installed_models || [];
      var missing = data.missing_models || [];
      var parts = [];
      parts.push("Installed: " + (installed.length ? installed.join(", ") : "none detected"));
      if (missing.length) { parts.push("Missing: " + missing.join(", ")); }
      statusEl.textContent = parts.join(" | ");
    }
    var pullBox = byId("ai-pull-commands");
    if (pullBox) {
      pullBox.textContent = "";
      var cmds = data.pull_commands || [];
      if (!cmds.length && data.models && data.provider === "ollama") {
        if (data.models.ollama) { cmds.push("ollama pull " + data.models.ollama); }
        if (data.models.ollama_vision) { cmds.push("ollama pull " + data.models.ollama_vision); }
      }
      cmds.forEach(function (cmd) {
        var row = make("div", "pull-cmd-row");
        row.appendChild(make("code", "mono", String(cmd)));
        var btn = make("button", "secondary compact", "Copy");
        btn.type = "button";
        btn.addEventListener("click", function () {
          copyTextToClipboard(cmd, btn);
          window.setTimeout(function () { btn.textContent = "Copy"; }, 1400);
        });
        row.appendChild(btn);
        pullBox.appendChild(row);
      });
    }
  }

  function refreshAiStatus(probe) {
    return api("/api/ai/status" + (probe ? "?probe_local=true" : "")).then(function (data) {
      var enabled = !!data.enabled;
      var provider = String(data.provider || "disabled");
      var badge = byId("ai-status-badge");
      if (badge) { badge.textContent = enabled ? provider : "disabled"; }
      var enEl = byId("ai-enabled");
      if (enEl) { enEl.checked = enabled; }
      var provEl = byId("ai-provider");
      if (provEl && provider) { provEl.value = provider; }
      var models = data.models || {};
      var endpoints = data.endpoints || {};
      var hw = data.hardware_profile || {};
      var modelVal = data.model || models[provider] || models.ollama || "";
      var visionVal = data.vision_model || models.ollama_vision || "";
      var baseVal = data.base_url || endpoints[provider] || "";
      var numCtxVal = data.num_ctx || hw.ollama_num_ctx || 8192;
      var keepAliveVal = data.keep_alive || hw.ollama_keep_alive || "2m";
      if (modelVal && byId("ai-model")) { byId("ai-model").value = modelVal; }
      if (visionVal && byId("ai-vision-model")) { byId("ai-vision-model").value = visionVal; }
      if (baseVal && byId("ai-base-url")) { byId("ai-base-url").value = baseVal; }
      if (byId("ai-num-ctx")) { byId("ai-num-ctx").value = String(numCtxVal); }
      if (byId("ai-keep-alive")) { byId("ai-keep-alive").value = String(keepAliveVal); }
      var reachable = !!(data.active || data.available);
      setText("ai-config-message", "AI status: " + (enabled ? provider : "disabled") +
        (reachable ? " (active)" : " (idle)"));
      renderAiLabStatus(data);
    }).catch(function () { /* ignore if ai subsystem absent */ });
  }

  function saveAiConfig(overrideBody) {
    var body = overrideBody || {
      enabled: byId("ai-enabled") ? !!byId("ai-enabled").checked : false,
      preset: byId("ai-preset") ? byId("ai-preset").value : undefined,
      provider: byId("ai-provider") ? byId("ai-provider").value : "disabled",
      model: byId("ai-model") ? byId("ai-model").value.trim() : "",
      vision_model: byId("ai-vision-model") ? byId("ai-vision-model").value.trim() : "",
      base_url: byId("ai-base-url") ? byId("ai-base-url").value.trim() : "",
      num_ctx: byId("ai-num-ctx") ? Number(byId("ai-num-ctx").value || 8192) : 8192,
      keep_alive: byId("ai-keep-alive") ? byId("ai-keep-alive").value.trim() : "2m"
    };
    var apiKey = (!overrideBody && byId("ai-api-key")) ? byId("ai-api-key").value.trim() : "";
    if (apiKey) { body.api_key = apiKey; }
    setText("ai-config-message", "Saving AI config…");
    api("/api/ai/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (data) {
      if (byId("ai-api-key")) { byId("ai-api-key").value = ""; }
      setText("ai-config-message", "Saved AI config (" + String(data.provider || body.provider || "updated") + ").");
      refreshAiStatus(false);
    }).catch(function (err) {
      setText("ai-config-message", String(err.message || err));
    });
  }

  function runCaseReflection() {
    if (!state.targetId) { showError(new Error("select or start an investigation first")); return; }
    api("/api/investigations/" + encodeURIComponent(state.targetId) + "/reflect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    }).then(function () {
      return refreshState();
    }).catch(function (err) { showError(err); });
  }

  function analyzeMedia() {
    var url = byId("media-url-input") ? byId("media-url-input").value.trim() : "";
    if (!url) { setText("media-results", "Enter an http(s) media URL first."); return; }
    var useVlm = byId("media-use-vlm") ? !!byId("media-use-vlm").checked : false;
    setText("media-results", "Analyzing media…");
    api("/api/media/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, use_vlm: useVlm, target_id: state.targetId || null })
    }).then(function (data) {
      setText("media-results", JSON.stringify(data, null, 2));
    }).catch(function (err) {
      setText("media-results", "Error: " + String(err.message || err));
    });
  }

  function updateScopeSummary(payload) {
    var el = byId("scope-policy-summary");
    if (!el || !payload || !payload.investigation) { return; }
    var cfg = payload.investigation.config || {};
    var scope = cfg.scope || {};
    var domains = (scope.allow_domains || []).join(", ") || "unrestricted";
    el.textContent = "Active recon: " + (scope.allow_active_recon ? "enabled" : "disabled") +
      " · allow_domains: " + domains;
  }

  function refreshToolsHealth() {
    api("/api/tools").then(function (data) {
      setText("tools-summary-badge", (data.available || 0) + "/" + (data.total || 0) + " ready");
      var list = byId("tools-health-list");
      if (!list) { return; }
      list.textContent = "";
      (data.tools || []).forEach(function (tool) {
        var row = make("div", "tool-row");
        row.appendChild(make("span", "mono", tool.tool_id || ""));
        var badgeCls = tool.available ? "badge CONFIRMED" : "badge COLLECTION_FAILURE";
        row.appendChild(make("span", badgeCls, tool.available ? "ready" : "missing"));
        list.appendChild(row);
      });
    }).catch(function () { /* ignore */ });
  }

  function runDoctorCheck() {
    setText("tools-summary-badge", "running doctor…");
    api("/api/doctor", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provision: false })
    }).then(function (data) {
      setText("tools-summary-badge", (data.available || 0) + "/" + (data.total || 0) + " ok");
      refreshToolsHealth();
    }).catch(function (err) { showError(err); });
  }

  function refreshCases() {
    return api("/api/investigations").then(function (data) {
      var items = (data && data.investigations) || [];
      ["case-select", "diff-target-select"].forEach(function (selId, idx) {
        var sel = byId(selId);
        if (!sel) { return; }
        var cur = idx === 0 ? (state.targetId || sel.value) : sel.value;
        sel.textContent = "";
        var def = make("option", "", idx === 0 ? "— current / new —" : "Diff against case…");
        def.value = "";
        sel.appendChild(def);
        items.forEach(function (item) {
          var opt = make("option", "", item.target_id + " (" + item.status + ")");
          opt.value = item.target_id;
          if (item.target_id === cur) { opt.selected = true; }
          sel.appendChild(opt);
        });
      });
    }).catch(function () { /* ignore */ });
  }

  function isSafeHref(rawUrl) {
    var cleaned = String(rawUrl || "").replace(/[\u0000-\u001f\u007f]/g, "").trim();
    if (!cleaned || !/^(https?:|mailto:)/i.test(cleaned)) {
      return null;
    }
    try {
      var parsed = new URL(cleaned);
      var proto = String(parsed.protocol || "").toLowerCase();
      if (proto === "http:" || proto === "https:" || proto === "mailto:") {
        return parsed.href;
      }
    } catch (err) {
      return null;
    }
    return null;
  }

  var EPISTEMIC_BADGES = {
    CONFIRMED: true, CORROBORATED: true, SINGLE_SOURCE_LEAD: true,
    HYPOTHESIS: true, CONTRADICTED: true, COLLECTION_FAILURE: true, AI_INFERRED: true
  };

  function appendInlineMarkdown(parent, text) {
    var src = String(text || "");
    var pos = 0;
    var tokenRe = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\)|(?<![A-Za-z0-9_])_[^_\s][^_]*?_(?![A-Za-z0-9_]))/g;
    var match;
    while ((match = tokenRe.exec(src)) !== null) {
      if (match.index > pos) {
        parent.appendChild(document.createTextNode(src.slice(pos, match.index)));
      }
      var tok = match[0];
      if (tok.charAt(0) === "`" && tok.charAt(tok.length - 1) === "`") {
        parent.appendChild(make("code", "", tok.slice(1, -1)));
      } else if (tok.slice(0, 2) === "**" && tok.slice(-2) === "**") {
        var innerBold = tok.slice(2, -2);
        if (EPISTEMIC_BADGES[innerBold]) {
          parent.appendChild(make("span", "badge " + innerBold, innerBold));
        } else {
          parent.appendChild(make("strong", "", innerBold));
        }
      } else if (tok.charAt(0) === "[" && tok.indexOf("](") !== -1) {
        var splitAt = tok.indexOf("](");
        var label = tok.slice(1, splitAt);
        var hrefRaw = tok.slice(splitAt + 2, -1);
        var safeHref = isSafeHref(hrefRaw);
        if (safeHref) {
          var anchor = document.createElement("a");
          anchor.setAttribute("href", safeHref);
          anchor.setAttribute("target", "_blank");
          anchor.setAttribute("rel", "noopener noreferrer");
          anchor.textContent = label;
          parent.appendChild(anchor);
        } else {
          parent.appendChild(document.createTextNode(label));
        }
      } else if (tok.charAt(0) === "_" && tok.charAt(tok.length - 1) === "_") {
        parent.appendChild(make("em", "", tok.slice(1, -1)));
      } else {
        parent.appendChild(document.createTextNode(tok));
      }
      pos = tokenRe.lastIndex;
    }
    if (pos < src.length) {
      parent.appendChild(document.createTextNode(src.slice(pos)));
    }
  }

  function splitTableCells(line) {
    var trimmed = line.trim();
    if (trimmed.charAt(0) === "|") { trimmed = trimmed.slice(1); }
    if (trimmed.charAt(trimmed.length - 1) === "|") { trimmed = trimmed.slice(0, -1); }
    return trimmed.split("|").map(function (c) { return c.trim(); });
  }

  function renderMarkdownSafe(mdText, container) {
    if (!container) { return; }
    while (container.firstChild) { container.removeChild(container.firstChild); }
    var lines = String(mdText || "").replace(/\r\n/g, "\n").split("\n");
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      var trimmed = line.trim();
      if (!trimmed) { i += 1; continue; }

      if (trimmed.slice(0, 3) === "```") {
        var codeLines = [];
        i += 1;
        while (i < lines.length && lines[i].trim().slice(0, 3) !== "```") {
          codeLines.push(lines[i]);
          i += 1;
        }
        i += 1;
        var pre = document.createElement("pre");
        pre.appendChild(make("code", "", codeLines.join("\n")));
        container.appendChild(pre);
        continue;
      }

      if (/^---+$/.test(trimmed)) {
        container.appendChild(document.createElement("hr"));
        i += 1;
        continue;
      }

      var hMatch = /^(#{1,4})\s+(.*)$/.exec(trimmed);
      if (hMatch) {
        var hEl = document.createElement("h" + hMatch[1].length);
        appendInlineMarkdown(hEl, hMatch[2]);
        container.appendChild(hEl);
        i += 1;
        continue;
      }

      if (trimmed.charAt(0) === ">") {
        var bq = document.createElement("blockquote");
        var bqLines = [];
        while (i < lines.length && lines[i].trim().charAt(0) === ">") {
          bqLines.push(lines[i].trim().replace(/^>\s?/, ""));
          i += 1;
        }
        appendInlineMarkdown(bq, bqLines.join(" "));
        container.appendChild(bq);
        continue;
      }

      if (trimmed.charAt(0) === "|" && i + 1 < lines.length && /^\s*\|?\s*[:\-| ]+\s*$/.test(lines[i + 1])) {
        var headers = splitTableCells(trimmed);
        i += 2;
        var table = document.createElement("table");
        var thead = document.createElement("thead");
        var htr = document.createElement("tr");
        headers.forEach(function (cell) {
          var th = document.createElement("th");
          appendInlineMarkdown(th, cell);
          htr.appendChild(th);
        });
        thead.appendChild(htr);
        table.appendChild(thead);
        var tbody = document.createElement("tbody");
        while (i < lines.length && lines[i].trim().charAt(0) === "|") {
          var rowCells = splitTableCells(lines[i]);
          var tr = document.createElement("tr");
          for (var c = 0; c < headers.length; c += 1) {
            var td = document.createElement("td");
            appendInlineMarkdown(td, rowCells[c] || "");
            tr.appendChild(td);
          }
          tbody.appendChild(tr);
          i += 1;
        }
        table.appendChild(tbody);
        container.appendChild(table);
        continue;
      }

      if (/^\s*[-*]\s+/.test(line)) {
        var ul = document.createElement("ul");
        while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
          var li = document.createElement("li");
          if (/^\s{2,}[-*]\s+/.test(lines[i])) {
            li.style.marginLeft = "16px";
          }
          appendInlineMarkdown(li, lines[i].replace(/^\s*[-*]\s+/, ""));
          ul.appendChild(li);
          i += 1;
        }
        container.appendChild(ul);
        continue;
      }

      if (/^\s*\d+\.\s+/.test(line)) {
        var ol = document.createElement("ol");
        while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
          var oli = document.createElement("li");
          appendInlineMarkdown(oli, lines[i].replace(/^\s*\d+\.\s+/, ""));
          ol.appendChild(oli);
          i += 1;
        }
        container.appendChild(ol);
        continue;
      }

      var para = document.createElement("p");
      var paraLines = [];
      while (
        i < lines.length && lines[i].trim() &&
        !/^(#{1,4})\s+/.test(lines[i].trim()) &&
        lines[i].trim().charAt(0) !== ">" &&
        lines[i].trim().charAt(0) !== "|" &&
        !/^\s*[-*]\s+/.test(lines[i]) &&
        !/^\s*\d+\.\s+/.test(lines[i]) &&
        lines[i].trim().slice(0, 3) !== "```"
      ) {
        paraLines.push(lines[i].trim());
        i += 1;
      }
      appendInlineMarkdown(para, paraLines.join(" "));
      container.appendChild(para);
    }
  }

  function setDossierMode(mode) {
    var rendered = byId("dossier-rendered");
    var raw = byId("dossier-text");
    var btnR = byId("dossier-mode-rendered");
    var btnRaw = byId("dossier-mode-raw");
    var isRaw = mode === "raw";
    if (rendered) { rendered.hidden = isRaw; }
    if (raw) { raw.hidden = !isRaw; }
    if (btnR) { btnR.classList.toggle("active", !isRaw); }
    if (btnRaw) { btnRaw.classList.toggle("active", isRaw); }
  }

  function fetchDossier() {
    if (!state.targetId) { return Promise.resolve(); }
    return fetch("/api/investigations/" + encodeURIComponent(state.targetId) + "/report?format=md")
      .catch(function (err) {
        if (isTransientNetworkError(err)) { throw transientError(err); }
        throw err;
      })
      .then(function (response) {
        return response.text().then(function (text) {
          if (!response.ok) {
            throw new Error(text || ("HTTP " + response.status));
          }
          return text;
        });
      })
      .then(function (text) {
        setText("dossier-text", text);
        renderMarkdownSafe(text, byId("dossier-rendered"));
        clearError();
      })
      .catch(function (err) {
        if (isTransientNetworkError(err)) { return; }
        showError(err);
      });
  }

  function updateDownloads() {
    ["md", "json", "html"].forEach(function (format) {
      var link = byId("download-" + format);
      if (!link) { return; }
      if (!state.targetId) { link.setAttribute("href", "#"); return; }
      link.setAttribute("href", "/api/investigations/" +
        encodeURIComponent(state.targetId) + "/report?format=" + format);
      link.setAttribute("download", "dossier-" + state.targetId + "." + format);
    });
  }

  function runSpecificPivot(pivotId) {
    if (!state.targetId) { showError(new Error("start an investigation first")); return; }
    clearError();
    setStatus("stepping");
    api("/api/investigations/" + encodeURIComponent(state.targetId) + "/step", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pivotId ? { pivot_id: pivotId } : {})
    }).then(function (data) {
      setStatus(data && data.status ? String(data.status) : "stepped");
      return refreshState();
    }).catch(function (err) { setStatus("error"); showError(err); });
  }

  function runNextPivot() {
    runSpecificPivot(null);
  }

  function runBatchPivots() {
    if (!state.targetId) { showError(new Error("start an investigation first")); return; }
    clearError();
    setStatus("stepping batch");
    api("/api/investigations/" + encodeURIComponent(state.targetId) + "/step-batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ max_pivots: 3 })
    }).then(function (data) {
      setStatus(data && data.status ? String(data.status) : "stepped");
      return refreshState();
    }).catch(function (err) { setStatus("error"); showError(err); });
  }

  function pivotSelectedEntity() {
    if (!state.selectedNode || !state.payload) { return; }
    var pivots = state.payload.pivots || [];
    var match = null;
    for (var i = 0; i < pivots.length; i += 1) {
      if (pivots[i].entity_id === state.selectedNode.id) { match = pivots[i]; break; }
    }
    runSpecificPivot(match ? match.pivot_id : null);
  }

  function renderCredentialStatuses(payload) {
    var providers = (payload && payload.providers) || {};
    Object.keys(providers).forEach(function (provider) {
      var badge = byId("cred-status-" + provider);
      if (!badge) { return; }
      var info = providers[provider] || {};
      var status = String(info.auth_status || "");
      var configured = !!info.configured;
      badge.textContent = (configured ? "Configured" : "Not Set") +
        (status ? " · " + status : "");
      badge.className = "cred-badge " + (configured ? "ok"
        : (status === "KEYLESS_LIMITED" ? "info" : "miss"));
    });
    var summary = (payload && payload.summary) || {};
    setText("api-keys-message", "Configured " + (summary.configured || 0) + "/" +
      (summary.total || 0) + " providers. Keys are masked and stored locally.");
  }

  function openApiKeys() {
    var modal = byId("api-keys-modal");
    if (!modal) { return; }
    modal.hidden = false;
    setText("api-keys-message", "Loading credential status…");
    api("/api/credentials")
      .then(renderCredentialStatuses)
      .catch(function (err) { setText("api-keys-message", String(err.message || err)); });
    var first = byId("key-github");
    if (first) { try { first.focus(); } catch (err) { /* ignore */ } }
  }

  function closeApiKeys() {
    var modal = byId("api-keys-modal");
    if (modal) { modal.hidden = true; }
  }

  function saveApiKeys() {
    var values = {
      github_token: byId("key-github") ? byId("key-github").value.trim() : "",
      virustotal_api_key: byId("key-virustotal") ? byId("key-virustotal").value.trim() : "",
      shodan_api_key: byId("key-shodan") ? byId("key-shodan").value.trim() : "",
      censys_api_id: byId("key-censys-id") ? byId("key-censys-id").value.trim() : "",
      censys_api_secret: byId("key-censys-secret") ? byId("key-censys-secret").value.trim() : "",
      hunter_api_key: byId("key-hunter") ? byId("key-hunter").value.trim() : ""
    };
    var body = {};
    Object.keys(values).forEach(function (key) {
      if (values[key]) { body[key] = values[key]; }
    });
    if (!Object.keys(body).length) {
      setText("api-keys-message", "Enter at least one API key to save.");
      return;
    }
    setText("api-keys-message", "Saving and syncing…");
    api("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (payload) {
      renderCredentialStatuses(payload);
      setText("api-keys-message", "Saved " + ((payload.saved || []).join(", ") || "keys") +
        "; TheHarvester config synced and tool auth statuses refreshed.");
      ["key-github", "key-virustotal", "key-shodan", "key-censys-id",
       "key-censys-secret", "key-hunter"].forEach(function (id) {
        var input = byId(id);
        if (input) { input.value = ""; }
      });
    }).catch(function (err) {
      setText("api-keys-message", String(err.message || err));
    });
  }

  var CHECKLIST_KEY = "ai_osint_quickstart_v2";
  var THEME_KEY = "ai_osint_theme";
  var resizeTimer = null;
  var cmdSelectedIdx = 0;
  var cmdFiltered = [];
  var activeMcpClient = "antigravity";

  function loadChecklistState() {
    try {
      var raw = window.localStorage ? window.localStorage.getItem(CHECKLIST_KEY) : null;
      return raw ? JSON.parse(raw) : { dismissed: false, steps: {} };
    } catch (err) {
      return { dismissed: false, steps: {} };
    }
  }

  function saveChecklistState(data) {
    try {
      if (window.localStorage) {
        window.localStorage.setItem(CHECKLIST_KEY, JSON.stringify(data));
      }
    } catch (err) { /* ignore storage restrictions */ }
  }

  function applyChecklistUI() {
    var box = byId("quickstart-checklist");
    if (!box) { return; }
    var st = loadChecklistState();
    box.hidden = !!st.dismissed;
    var items = box.querySelectorAll(".checklist-item");
    for (var i = 0; i < items.length; i += 1) {
      var stepId = items[i].getAttribute("data-step");
      var done = !!(st.steps && st.steps[stepId]);
      items[i].classList.toggle("done", done);
      var mark = items[i].firstElementChild;
      if (mark) { mark.textContent = done ? "[x]" : "[ ]"; }
    }
  }

  function markChecklistStep(stepNum) {
    var st = loadChecklistState();
    if (!st.steps) { st.steps = {}; }
    st.steps[String(stepNum)] = true;
    saveChecklistState(st);
    applyChecklistUI();
  }

  function dismissChecklist() {
    var st = loadChecklistState();
    st.dismissed = true;
    saveChecklistState(st);
    applyChecklistUI();
  }

  function scheduleCyResize() {
    if (resizeTimer) { window.clearTimeout(resizeTimer); }
    resizeTimer = window.setTimeout(function () {
      if (state.cy) {
        state.cy.resize();
        state.cy.fit(undefined, 36);
      }
    }, 150);
  }

  function toggleThemeMode() {
    var root = document.documentElement;
    var nextDark = root.getAttribute("data-theme") !== "dark";
    if (nextDark) { root.setAttribute("data-theme", "dark"); }
    else { root.removeAttribute("data-theme"); }
    try {
      if (window.localStorage) {
        window.localStorage.setItem(THEME_KEY, nextDark ? "dark" : "light");
      }
    } catch (err) { /* ignore */ }
  }

  function restoreThemeMode() {
    try {
      if (window.localStorage && window.localStorage.getItem(THEME_KEY) === "dark") {
        document.documentElement.setAttribute("data-theme", "dark");
      }
    } catch (err) { /* ignore */ }
  }

  function loadDemoCase() {
    clearError();
    setStatus("seeding demo");
    return api("/api/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ overwrite: true })
    }).then(function (data) {
      if (!data || !data.target_id) { throw new Error("demo returned no target_id"); }
      state.targetId = data.target_id;
      state.pathSourceId = null;
      state.graphView.shortestPathNodes = {};
      state.graphView.shortestPathEdges = {};
      setText("target-label", data.target_id);
      setStatus("COMPLETED", true);
      markChecklistStep(1);
      updateDownloads();
      return refreshCases().then(function () {
        return refreshState();
      }).then(function () {
        fetchTimeline();
        fetchDossier();
      });
    }).catch(function (err) {
      setStatus("error");
      showError(err);
    });
  }

  function exportCaseBundle() {
    if (!state.targetId) {
      showError(new Error("select or load an investigation first"));
      return;
    }
    var redactEl = byId("export-redact-pii");
    var redact = !!(redactEl && redactEl.checked);
    var url = "/api/investigations/" + encodeURIComponent(state.targetId) +
      "/bundle?redact_pii=" + (redact ? "true" : "false");
    var link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", state.targetId + ".osintcase.zip");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    markChecklistStep(4);
  }

  function arrayBufferToBase64(buffer) {
    var bytes = new Uint8Array(buffer);
    var chunks = [];
    var step = 0x8000;
    for (var i = 0; i < bytes.length; i += step) {
      chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + step)));
    }
    return window.btoa(chunks.join(""));
  }

  function importCaseBundleFile(file) {
    if (!file) { return; }
    clearError();
    setStatus("importing bundle");
    var reader = new FileReader();
    reader.onload = function () {
      var b64 = arrayBufferToBase64(reader.result);
      var overwriteEl = byId("import-overwrite-bundle");
      var overwrite = !!(overwriteEl && overwriteEl.checked);
      api("/api/bundles/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name || "case.osintcase.zip",
          data_base64: b64,
          overwrite: overwrite
        })
      }).then(function (data) {
        var tid = (data && (data.target_id || (data.manifest && data.manifest.target_id))) || null;
        if (!tid) { throw new Error("imported bundle did not return target_id"); }
        state.targetId = tid;
        setText("target-label", tid);
        setStatus("COMPLETED", true);
        markChecklistStep(1);
        updateDownloads();
        return refreshCases().then(function () { return refreshState(); }).then(function () {
          fetchTimeline();
          fetchDossier();
        });
      }).catch(function (err) {
        setStatus("error");
        showError(err);
      });
    };
    reader.onerror = function () {
      setStatus("error");
      showError(new Error("failed to read selected bundle file"));
    };
    reader.readAsArrayBuffer(file);
  }

  var PRESET_HINTS = {
    person: {
      hint: "Preset: Person / Handle — provide a name, handle, or email to trace cross-platform identity.",
      focus: "in-name"
    },
    domain: {
      hint: "Preset: Domain / Org — enter a target domain, organization, or IP for passive DNS, RDAP, CT & ASN mapping.",
      focus: "in-domains"
    },
    media: {
      hint: "Preset: Image / Media Forensics — paste an image URL below or launch the Vision & Media Forensics Lab.",
      focus: "in-urls"
    },
    custom: {
      hint: "Preset: Custom Clue — paste free-form OSINT notes, handles, phones, or mixed selectors.",
      focus: "in-raw"
    }
  };

  function setIntakePreset(presetKey) {
    var key = PRESET_HINTS[presetKey] ? presetKey : "person";
    var bar = byId("intake-presets");
    if (bar) {
      var btns = bar.querySelectorAll(".preset-pill");
      for (var i = 0; i < btns.length; i += 1) {
        btns[i].classList.toggle("active", btns[i].getAttribute("data-preset") === key);
      }
    }
    setText("intake-preset-hint", PRESET_HINTS[key].hint);
    var focusEl = byId(PRESET_HINTS[key].focus);
    if (focusEl) { try { focusEl.focus(); } catch (err) { /* ignore */ } }
  }

  function openScopeAuthModal() {
    var modal = byId("scope-auth-modal");
    if (modal) { modal.hidden = false; }
    var confirmBtn = byId("confirm-scope-auth");
    if (confirmBtn) { try { confirmBtn.focus(); } catch (err) { /* ignore */ } }
  }

  function closeScopeAuthModal(confirmed) {
    var modal = byId("scope-auth-modal");
    if (modal) { modal.hidden = true; }
    var activeBox = byId("in-active");
    if (activeBox) { activeBox.checked = !!confirmed; }
  }

  function fetchMcpConfig(client) {
    activeMcpClient = client || activeMcpClient || "antigravity";
    var tabs = byId("mcp-client-tabs");
    if (tabs) {
      var pills = tabs.querySelectorAll(".preset-pill");
      for (var i = 0; i < pills.length; i += 1) {
        pills[i].classList.toggle("active", pills[i].getAttribute("data-mcp-client") === activeMcpClient);
      }
    }
    setText("mcp-copy-status", "");
    setText("mcp-config-pre", "Loading MCP snippet…");
    return api("/api/mcp-config?client=" + encodeURIComponent(activeMcpClient)).then(function (data) {
      setText("mcp-config-path", data.config_path_hint || data.path || "—");
      var jsonText = data.snippet_json || data.config_json || JSON.stringify(data.snippet || data.config || data, null, 2);
      setText("mcp-config-pre", jsonText);
    }).catch(function (err) {
      setText("mcp-config-pre", "Error: " + String(err.message || err));
    });
  }

  function openMcpSetup() {
    var modal = byId("mcp-setup-modal");
    if (!modal) { return; }
    modal.hidden = false;
    fetchMcpConfig(activeMcpClient);
  }

  function closeMcpSetup() {
    var modal = byId("mcp-setup-modal");
    if (modal) { modal.hidden = true; }
  }

  function buildCommandItems() {
    var items = [
      { label: "Load Interactive Demo Case (Aurora Meridian)", category: "Action", run: function () { loadDemoCase(); } },
      { label: "Run Next Pivot", category: "Pivot", run: function () { runNextPivot(); } },
      { label: "Step Batch (3x Pivots)", category: "Pivot", run: function () { runBatchPivots(); } },
      { label: "Export Case Bundle (.osintcase.zip)", category: "Bundle", run: function () { exportCaseBundle(); } },
      { label: "Import Case Bundle (.osintcase.zip)", category: "Bundle", run: function () { var f = byId("bundle-file-input"); if (f) { f.click(); } } },
      { label: "Open 10-Second MCP Setup", category: "MCP", run: function () { openMcpSetup(); } },
      { label: "Open API Keys Vault", category: "Settings", run: function () { openApiKeys(); } },
      { label: "Toggle Light / Dark Theme", category: "View", run: function () { toggleThemeMode(); } },
      { label: "Print / Save Dossier PDF", category: "Dossier", run: function () { activateTab("dossier"); window.print(); } },
      { label: "Switch Tab: Graph", category: "Tab", run: function () { activateTab("graph"); } },
      { label: "Switch Tab: Timeline", category: "Tab", run: function () { activateTab("timeline"); } },
      { label: "Switch Tab: Telemetry & Pivots", category: "Tab", run: function () { activateTab("telemetry"); } },
      { label: "Switch Tab: AI & Vision Lab", category: "Tab", run: function () { activateTab("ai"); } },
      { label: "Switch Tab: Dossier", category: "Tab", run: function () { activateTab("dossier"); } }
    ];
    var nodes = (state.payload && state.payload.graph && state.payload.graph.nodes) || [];
    nodes.slice(0, 60).forEach(function (node) {
      items.push({
        label: "Jump to " + String(node.type) + ": " + String(node.value),
        category: String(node.status || "Entity"),
        run: function () {
          activateTab("graph");
          inspectEntity(node, state.payload);
          if (state.cy) {
            var el = state.cy.getElementById(node.id);
            if (el && el.length) {
              state.cy.animate({ center: { eles: el } }, { duration: 150 });
            }
          }
        }
      });
    });
    return items;
  }

  function renderCommandPaletteResults() {
    var list = byId("cmd-palette-results");
    var input = byId("cmd-palette-input");
    if (!list) { return; }
    var q = input ? String(input.value || "").trim().toLowerCase() : "";
    var all = buildCommandItems();
    cmdFiltered = all.filter(function (item) {
      return !q || item.label.toLowerCase().indexOf(q) !== -1 || item.category.toLowerCase().indexOf(q) !== -1;
    }).slice(0, 18);
    if (cmdSelectedIdx >= cmdFiltered.length) { cmdSelectedIdx = Math.max(0, cmdFiltered.length - 1); }
    list.textContent = "";
    if (!cmdFiltered.length) {
      list.appendChild(make("li", "cmd-item muted", "No matching commands or entities."));
      return;
    }
    cmdFiltered.forEach(function (item, idx) {
      var li = make("li", "cmd-item" + (idx === cmdSelectedIdx ? " selected" : ""));
      li.setAttribute("role", "option");
      li.appendChild(make("span", "", item.label));
      li.appendChild(make("span", "badge", item.category));
      li.addEventListener("click", function () {
        closeCommandPalette();
        markChecklistStep(3);
        item.run();
      });
      list.appendChild(li);
    });
  }

  function openCommandPalette() {
    var modal = byId("cmd-palette-modal");
    if (!modal) { return; }
    modal.hidden = false;
    cmdSelectedIdx = 0;
    var input = byId("cmd-palette-input");
    if (input) { input.value = ""; }
    renderCommandPaletteResults();
    if (input) { try { input.focus(); } catch (err) { /* ignore */ } }
  }

  function closeCommandPalette() {
    var modal = byId("cmd-palette-modal");
    if (modal) { modal.hidden = true; }
  }

  function activateTab(name) {
    var tabs = document.querySelectorAll(".tab");
    for (var index = 0; index < tabs.length; index += 1) {
      tabs[index].classList.toggle("active", tabs[index].getAttribute("data-tab") === name);
    }
    var panels = document.querySelectorAll(".tab-panel");
    for (var panelIndex = 0; panelIndex < panels.length; panelIndex += 1) {
      panels[panelIndex].classList.toggle("active",
        panels[panelIndex].id === "tab-" + name);
    }
    if (name === "dossier") { fetchDossier(); markChecklistStep(4); }
    if (name === "timeline") { fetchTimeline(); }
    if (name === "graph" && state.cy) { state.cy.resize(); state.cy.fit(undefined, 36); }
  }

  function wire() {
    restoreThemeMode();
    applyChecklistUI();
    byId("intake").addEventListener("submit", startInvestigation);
    byId("run-pivot").addEventListener("click", runNextPivot);
    var batchBtn = byId("run-batch-pivots");
    if (batchBtn) { batchBtn.addEventListener("click", runBatchPivots); }
    var clearButton = byId("clear-form");
    if (clearButton) { clearButton.addEventListener("click", clearForm); }
    var activeReconBox = byId("in-active");
    if (activeReconBox) {
      activeReconBox.addEventListener("change", function () {
        if (activeReconBox.checked) {
          activeReconBox.checked = false;
          openScopeAuthModal();
        }
      });
    }
    var confirmScopeBtn = byId("confirm-scope-auth");
    if (confirmScopeBtn) {
      confirmScopeBtn.addEventListener("click", function () { closeScopeAuthModal(true); });
    }
    var cancelScopeBtn = byId("cancel-scope-auth");
    if (cancelScopeBtn) {
      cancelScopeBtn.addEventListener("click", function () { closeScopeAuthModal(false); });
    }
    var scopeModal = byId("scope-auth-modal");
    if (scopeModal) {
      scopeModal.addEventListener("click", function (event) {
        if (event.target === scopeModal) { closeScopeAuthModal(false); }
      });
    }
    var presetBar = byId("intake-presets");
    if (presetBar) {
      presetBar.addEventListener("click", function (event) {
        var btn = event.target && event.target.closest ? event.target.closest("[data-preset]") : null;
        if (btn) { setIntakePreset(btn.getAttribute("data-preset")); }
      });
    }
    var zoomIn = byId("zoom-in");
    if (zoomIn) { zoomIn.addEventListener("click", function () { zoomGraph(1.18); }); }
    var zoomOut = byId("zoom-out");
    if (zoomOut) { zoomOut.addEventListener("click", function () { zoomGraph(0.85); }); }
    var zoomReset = byId("zoom-reset");
    if (zoomReset) { zoomReset.addEventListener("click", resetGraphView); }
    var toggleEngine = byId("toggle-graph-engine");
    if (toggleEngine) {
      toggleEngine.addEventListener("click", function () {
        var canCy = typeof window.cytoscape === "function";
        if (!canCy) { state.graphView.renderer = "svg"; }
        else {
          var currentlyCy = state.graphView.renderer !== "svg";
          state.graphView.renderer = currentlyCy ? "svg" : "cy";
        }
        syncGraphRendererVisibility();
        if (state.payload) { renderGraph(state.payload); }
      });
    }
    var clusterSel = byId("cluster-filter");
    if (clusterSel) {
      clusterSel.addEventListener("change", function () {
        state.graphView.cluster = clusterSel.value || "";
        if (state.payload) { renderGraph(state.payload); }
      });
    }
    var clearPathBtn = byId("clear-path-btn");
    if (clearPathBtn) { clearPathBtn.addEventListener("click", clearShortestPath); }
    var nodeSearch = byId("node-search");
    if (nodeSearch) {
      nodeSearch.addEventListener("input", function () {
        state.graphView.search = nodeSearch.value || "";
        if (state.payload) { renderGraph(state.payload); }
      });
    }
    var showHypotheses = byId("show-hypotheses");
    if (showHypotheses) {
      showHypotheses.addEventListener("change", function () {
        state.graphView.showHypotheses = !!showHypotheses.checked;
        if (state.payload) { renderGraph(state.payload); }
      });
    }
    var showEdgeLabels = byId("show-edge-labels");
    if (showEdgeLabels) {
      showEdgeLabels.addEventListener("change", function () {
        state.graphView.showEdgeLabels = !!showEdgeLabels.checked;
        if (state.payload) { renderGraph(state.payload); }
      });
    }
    configureGraphInteraction();
    var toggleLeft = byId("toggle-left-rail");
    if (toggleLeft) {
      toggleLeft.addEventListener("click", function () {
        byId("workbench").classList.toggle("rail-left-collapsed");
        scheduleCyResize();
      });
    }
    var toggleRight = byId("toggle-right-rail");
    if (toggleRight) {
      toggleRight.addEventListener("click", function () {
        byId("workbench").classList.toggle("rail-right-collapsed");
        scheduleCyResize();
      });
    }
    window.addEventListener("resize", scheduleCyResize);
    var toggleTheme = byId("toggle-theme");
    if (toggleTheme) { toggleTheme.addEventListener("click", toggleThemeMode); }

    var loadDemoBtn = byId("btn-load-demo");
    if (loadDemoBtn) { loadDemoBtn.addEventListener("click", loadDemoCase); }
    var dismissChecklistBtn = byId("dismiss-quickstart");
    if (dismissChecklistBtn) { dismissChecklistBtn.addEventListener("click", dismissChecklist); }
    var exportBundleBtn = byId("export-bundle-btn");
    if (exportBundleBtn) { exportBundleBtn.addEventListener("click", exportCaseBundle); }
    var bundleFileInput = byId("bundle-file-input");
    if (bundleFileInput) {
      bundleFileInput.addEventListener("change", function () {
        if (bundleFileInput.files && bundleFileInput.files[0]) {
          importCaseBundleFile(bundleFileInput.files[0]);
          bundleFileInput.value = "";
        }
      });
    }
    var importBundleBtn = byId("import-bundle-btn");
    if (importBundleBtn && bundleFileInput) {
      importBundleBtn.addEventListener("click", function () { bundleFileInput.click(); });
    }
    var importEmptyBtn = byId("btn-import-bundle-empty");
    if (importEmptyBtn && bundleFileInput) {
      importEmptyBtn.addEventListener("click", function () { bundleFileInput.click(); });
    }

    var openCmdBtn = byId("open-cmd-palette");
    if (openCmdBtn) { openCmdBtn.addEventListener("click", openCommandPalette); }
    var closeCmdBtn = byId("close-cmd-palette");
    if (closeCmdBtn) { closeCmdBtn.addEventListener("click", closeCommandPalette); }
    var cmdModal = byId("cmd-palette-modal");
    if (cmdModal) {
      cmdModal.addEventListener("click", function (event) {
        if (event.target === cmdModal) { closeCommandPalette(); }
      });
    }
    var cmdInput = byId("cmd-palette-input");
    if (cmdInput) {
      cmdInput.addEventListener("input", function () {
        cmdSelectedIdx = 0;
        renderCommandPaletteResults();
      });
      cmdInput.addEventListener("keydown", function (event) {
        if (event.key === "ArrowDown") {
          event.preventDefault();
          if (cmdFiltered.length) {
            cmdSelectedIdx = (cmdSelectedIdx + 1) % cmdFiltered.length;
            renderCommandPaletteResults();
          }
        } else if (event.key === "ArrowUp") {
          event.preventDefault();
          if (cmdFiltered.length) {
            cmdSelectedIdx = (cmdSelectedIdx - 1 + cmdFiltered.length) % cmdFiltered.length;
            renderCommandPaletteResults();
          }
        } else if (event.key === "Enter") {
          event.preventDefault();
          var chosen = cmdFiltered[cmdSelectedIdx];
          if (chosen) {
            closeCommandPalette();
            markChecklistStep(3);
            chosen.run();
          }
        }
      });
    }

    var openMcpBtn = byId("open-mcp-modal");
    if (openMcpBtn) { openMcpBtn.addEventListener("click", openMcpSetup); }
    var openMcpEmptyBtn = byId("btn-open-mcp-empty");
    if (openMcpEmptyBtn) { openMcpEmptyBtn.addEventListener("click", openMcpSetup); }
    var closeMcpBtn = byId("close-mcp-setup");
    if (closeMcpBtn) { closeMcpBtn.addEventListener("click", closeMcpSetup); }
    var mcpModal = byId("mcp-setup-modal");
    if (mcpModal) {
      mcpModal.addEventListener("click", function (event) {
        if (event.target === mcpModal) { closeMcpSetup(); }
      });
    }
    var mcpTabs = byId("mcp-client-tabs");
    if (mcpTabs) {
      mcpTabs.addEventListener("click", function (event) {
        var btn = event.target && event.target.closest ? event.target.closest("[data-mcp-client]") : null;
        if (btn) { fetchMcpConfig(btn.getAttribute("data-mcp-client")); }
      });
    }
    var copyMcpBtn = byId("copy-mcp-config-btn");
    if (copyMcpBtn) {
      copyMcpBtn.addEventListener("click", function () {
        var pre = byId("mcp-config-pre");
        copyTextToClipboard(pre ? pre.textContent : "", byId("mcp-copy-status"));
      });
    }

    document.addEventListener("keydown", function (event) {
      if ((event.ctrlKey || event.metaKey) && String(event.key || "").toLowerCase() === "k") {
        event.preventDefault();
        var cm = byId("cmd-palette-modal");
        if (cm && !cm.hidden) { closeCommandPalette(); }
        else { openCommandPalette(); }
      } else if (event.key === "Escape") {
        closeCommandPalette();
        closeMcpSetup();
        closeApiKeys();
        var sm = byId("scope-auth-modal");
        if (sm && !sm.hidden) { closeScopeAuthModal(false); }
      }
    });

    var dosModeR = byId("dossier-mode-rendered");
    if (dosModeR) { dosModeR.addEventListener("click", function () { setDossierMode("rendered"); }); }
    var dosModeRaw = byId("dossier-mode-raw");
    if (dosModeRaw) { dosModeRaw.addEventListener("click", function () { setDossierMode("raw"); }); }
    var dosPrint = byId("dossier-print-btn");
    if (dosPrint) { dosPrint.addEventListener("click", function () { window.print(); }); }

    var caseSelect = byId("case-select");
    if (caseSelect) {
      caseSelect.addEventListener("change", function () {
        if (!caseSelect.value) { return; }
        state.targetId = caseSelect.value;
        setText("target-label", state.targetId);
        updateDownloads();
        refreshState();
        fetchTimeline();
      });
    }
    var refreshCasesBtn = byId("refresh-cases-btn");
    if (refreshCasesBtn) { refreshCasesBtn.addEventListener("click", refreshCases); }
    var diffBtn = byId("run-diff-btn");
    if (diffBtn) { diffBtn.addEventListener("click", runCaseDiff); }
    var refreshTlBtn = byId("refresh-timeline-btn");
    if (refreshTlBtn) { refreshTlBtn.addEventListener("click", fetchTimeline); }
    var refreshToolsBtn = byId("refresh-tools-btn");
    if (refreshToolsBtn) { refreshToolsBtn.addEventListener("click", refreshToolsHealth); }
    var runDoctorBtn = byId("run-doctor-btn");
    if (runDoctorBtn) { runDoctorBtn.addEventListener("click", runDoctorCheck); }
    var saveAiBtn = byId("save-ai-config");
    if (saveAiBtn) { saveAiBtn.addEventListener("click", function () { saveAiConfig(null); }); }
    var probeAiBtn = byId("refresh-ai-status");
    if (probeAiBtn) { probeAiBtn.addEventListener("click", function () { refreshAiStatus(true); }); }
    var aiLabApplyBtn = byId("ai-lab-apply-btn");
    if (aiLabApplyBtn) {
      aiLabApplyBtn.addEventListener("click", function () {
        var sel = byId("ai-lab-preset");
        var preset = sel ? sel.value : "disabled";
        saveAiConfig({ preset: preset, enabled: preset !== "disabled" });
      });
    }
    var aiLabProbeBtn = byId("ai-lab-probe-btn");
    if (aiLabProbeBtn) { aiLabProbeBtn.addEventListener("click", function () { refreshAiStatus(true); }); }
    var aiRailPreset = byId("ai-preset");
    if (aiRailPreset) {
      aiRailPreset.addEventListener("change", function () {
        var preset = aiRailPreset.value;
        if (byId("ai-enabled")) { byId("ai-enabled").checked = preset !== "disabled"; }
      });
    }
    var reflectBtn = byId("run-reflect-btn");
    if (reflectBtn) { reflectBtn.addEventListener("click", runCaseReflection); }
    var mediaBtn = byId("analyze-media-btn");
    if (mediaBtn) { mediaBtn.addEventListener("click", analyzeMedia); }
    var inspectPivotBtn = byId("inspect-pivot-btn");
    if (inspectPivotBtn) { inspectPivotBtn.addEventListener("click", pivotSelectedEntity); }
    var setPathSrcBtn = byId("set-path-source-btn");
    if (setPathSrcBtn) {
      setPathSrcBtn.addEventListener("click", function () {
        if (!state.selectedNode) { return; }
        state.pathSourceId = state.selectedNode.id;
        setText("path-status-line", "Path source: " + state.selectedNode.value);
        var dstBtn = byId("find-path-btn");
        if (dstBtn) { dstBtn.disabled = true; }
      });
    }
    var findPathBtn = byId("find-path-btn");
    if (findPathBtn) { findPathBtn.addEventListener("click", findShortestPath); }
    var openKeys = byId("open-api-keys");
    if (openKeys) { openKeys.addEventListener("click", openApiKeys); }
    var closeKeys = byId("close-api-keys");
    if (closeKeys) { closeKeys.addEventListener("click", closeApiKeys); }
    var saveKeys = byId("save-api-keys");
    if (saveKeys) { saveKeys.addEventListener("click", saveApiKeys); }
    var modal = byId("api-keys-modal");
    if (modal) {
      modal.addEventListener("click", function (event) {
        if (event.target === modal) { closeApiKeys(); }
      });
    }
    var tabs = document.querySelectorAll(".tab");
    for (var index = 0; index < tabs.length; index += 1) {
      tabs[index].addEventListener("click", function (event) {
        activateTab(event.currentTarget.getAttribute("data-tab"));
      });
    }
    var cyScript = byId("cytoscape-vendor-script");
    if (cyScript) {
      cyScript.addEventListener("load", function () {
        if (state.payload) { renderGraph(state.payload); }
        else { syncGraphRendererVisibility(); }
      });
    }
    updateDownloads();
    refreshCases();
    refreshToolsHealth();
    refreshAiStatus(false);
    syncGraphRendererVisibility();
    setDossierMode("rendered");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
</script>
<script id="cytoscape-vendor-script" src="/static/vendor/cytoscape.min.js" defer></script>
</body>
</html>
"""


# Module-level app for ``uvicorn hub.web:app`` / ``python -m hub.cli serve``.
app = create_app()


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the workbench with uvicorn (imported lazily to keep imports fast)."""
    import uvicorn

    uvicorn.run(app, host=host, port=port)


__all__ = [
    "APP_TITLE",
    "WORKBENCH_HTML",
    "build_investigation_payload",
    "build_workbench_graph",
    "create_app",
    "iter_investigation_events",
    "run",
]
