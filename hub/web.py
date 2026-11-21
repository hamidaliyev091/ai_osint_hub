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
import inspect
import json
import time
from typing import Any, AsyncIterator, Optional

from fastapi import Body, FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from pydantic import BaseModel, Field

from hub.erkg.graph import GraphView
from hub.investigation.engine import EngineError
from hub.models import EpistemicStatus
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

    return app


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
    """Keep the reporting HTML as-is; wrap a fragment into a dark document."""
    text = content or ""
    if text.lstrip().lower().startswith("<!doctype") or "<html" in text.lower():
        return text
    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"color-scheme\" content=\"dark\">"
        "<title>Intelligence Dossier</title>"
        "<style>body{background:#0b1120;color:#e2e8f0;font:14px/1.5 sans-serif;"
        "padding:32px}pre{white-space:pre-wrap;word-break:break-word}</style>"
        f"</head><body><pre>{_text(text, 200_000)}</pre></body></html>"
    )


# ════════════════════════════════════════════════════════════════════════
# Embedded single-page workbench (Tailwind CDN + offline CSS fallback)
# ════════════════════════════════════════════════════════════════════════

WORKBENCH_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>AI OSINT Hub Intelligence Workbench</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
:root { color-scheme: dark; --bg:#0b1020; --panel:#111827; --panel2:#0f172a;
        --line:#1f2937; --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; }
* { box-sizing: border-box; }
html, body { height: 100%; }
body { margin:0; background:radial-gradient(1200px 700px at 20% -10%, #16213f 0%, var(--bg) 55%);
       color:var(--text); font:14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
#workbench { display:flex; flex-direction:column; height:100vh; min-height:0; }
header { display:flex; align-items:center; gap:12px; padding:12px 16px;
         border-bottom:1px solid var(--line); background:rgba(9,14,30,.85); backdrop-filter:blur(6px); }
header h1 { font-size:16px; margin:0; letter-spacing:.01em; color:#f8fafc; }
header .pill { font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.06em;
               padding:2px 9px; border-radius:999px; border:1px solid #334155; background:#0f172a; color:#93c5fd; }
header .muted { color:var(--muted); font-size:12px; }
main { flex:1; min-height:0; display:grid; grid-template-columns:320px minmax(0,1fr) 330px;
       gap:12px; padding:12px; }
@media (max-width:1150px) { main { grid-template-columns:1fr; overflow:auto; } }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:12px;
         min-height:0; display:flex; flex-direction:column; overflow:hidden; }
.panel > h2 { margin:0; padding:10px 12px; font-size:12px; text-transform:uppercase;
              letter-spacing:.08em; color:var(--muted); border-bottom:1px solid var(--line); }
.panel-body { padding:12px; overflow:auto; min-height:0; }
label { display:block; font-size:11px; color:var(--muted); margin:8px 0 3px; text-transform:uppercase;
        letter-spacing:.05em; }
input, textarea, select { width:100%; background:#0b1220; color:var(--text);
        border:1px solid #263243; border-radius:8px; padding:6px 8px; font:inherit; font-size:13px; }
input:focus, textarea:focus { outline:1px solid var(--accent); border-color:var(--accent); }
textarea { min-height:88px; resize:vertical; }
button { background:#1d4ed8; color:#eff6ff; border:1px solid #1d4ed8; border-radius:8px;
         padding:7px 12px; font:inherit; font-weight:600; cursor:pointer; }
button:hover { background:#2563eb; }
button.secondary { background:#0f172a; border-color:#334155; color:#cbd5e1; }
button.secondary:hover { background:#172036; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.spacer { flex:1; }
.muted { color:var(--muted); }
.tabs { display:flex; gap:6px; padding:8px 10px; border-bottom:1px solid var(--line); }
.tab { background:transparent; border-color:transparent; color:var(--muted); padding:5px 10px; }
.tab.active { background:#172036; color:#e2e8f0; border-color:#334155; }
.tab-panel { display:none; flex:1; min-height:0; }
.tab-panel.active { display:flex; flex-direction:column; }
#graph-wrap { flex:1; min-height:0; padding:6px; }
#graph { width:100%; height:100%; min-height:340px; display:block;
         background:radial-gradient(900px 500px at 50% 40%, #0d1730 0%, #0a0f1f 70%);
         border-radius:10px; }
#graph text { font-size:11px; fill:#cbd5e1; pointer-events:none; }
#graph .edge-line { stroke:#334155; stroke-width:1.4; cursor:pointer; }
#graph .edge-line:hover { stroke:#38bdf8; stroke-width:2.2; }
#graph .edge-label { font-size:9.5px; fill:#64748b; }
#graph .node-circle { stroke:#0b1020; stroke-width:2; cursor:pointer; }
#graph .node-circle:hover { stroke:#f8fafc; stroke-width:3; }
#graph .node-label { font-size:10.5px; fill:#e2e8f0; }
#graph .empty { font-size:13px; fill:#64748b; }
.dossier-pre { margin:0; padding:12px; background:#0b1220; border:1px solid var(--line);
       border-radius:10px; white-space:pre-wrap; word-break:break-word; font:12px/1.55 ui-monospace,
       Consolas, "Cascadia Mono", monospace; color:#cbd5e1; min-height:320px; }
.telemetry-section { margin-bottom:16px; }
.telemetry-section h3 { margin:0 0 6px; font-size:12px; color:#93c5fd;
       text-transform:uppercase; letter-spacing:.06em; }
.telemetry-list { list-style:none; margin:0; padding:0; }
.telemetry-list li { padding:5px 8px; margin:3px 0; background:var(--panel2);
       border:1px solid var(--line); border-radius:7px; font-size:12px; }
.badge { display:inline-block; padding:1px 7px; border-radius:999px; font-size:10.5px;
       font-weight:700; letter-spacing:.03em; border:1px solid #334155; color:#cbd5e1;
       background:#0f172a; }
.badge.CONFIRMED { background:#052e16; color:#4ade80; border-color:#166534; }
.badge.CORROBORATED { background:#052e2b; color:#2dd4bf; border-color:#115e59; }
.badge.SINGLE_SOURCE_LEAD { background:#3b2f0b; color:#fbbf24; border-color:#854d0e; }
.badge.HYPOTHESIS { background:#1e293b; color:#94a3b8; }
.badge.CONTRADICTED { background:#450a0a; color:#f87171; border-color:#7f1d1d; }
.badge.COLLECTION_FAILURE { background:#1f2937; color:#9ca3af; }
#inspector dl { margin:0; }
#inspector dt { font-size:10.5px; text-transform:uppercase; letter-spacing:.06em;
       color:var(--muted); margin-top:10px; }
#inspector dd { margin:2px 0 0; font-size:12.5px; word-break:break-word; }
#artifact-snippet { background:#0b1220; border:1px solid var(--line); border-radius:8px;
       padding:8px; white-space:pre-wrap; word-break:break-word; font-size:11.5px;
       max-height:190px; overflow:auto; margin:0; color:#cbd5e1; }
.claim-line { font-size:12px; padding:4px 6px; margin:3px 0; background:var(--panel2);
       border:1px solid var(--line); border-radius:6px; }
#ui-message { min-height:16px; color:#fca5a5; font-size:12px; }
.dl-row { display:flex; gap:8px; flex-wrap:wrap; padding:10px; border-bottom:1px solid var(--line); }
a.dl-link { display:inline-block; text-decoration:none; font-size:12px; font-weight:600;
       color:#bfdbfe; border:1px solid #334155; background:#0f172a; border-radius:8px;
       padding:6px 10px; }
a.dl-link:hover { border-color:#38bdf8; color:#f8fafc; }
.modal-backdrop { position:fixed; inset:0; background:rgba(2,6,23,.78); z-index:60;
  display:flex; align-items:center; justify-content:center; padding:20px; }
.modal-backdrop[hidden] { display:none !important; }
.modal-card { width:min(560px, 96vw); max-height:90vh; overflow:auto; background:#0f172a;
  border:1px solid #334155; border-radius:14px; padding:18px 20px;
  box-shadow:0 24px 80px rgba(0,0,0,.6); }
.modal-card h2 { margin:0 0 4px; font-size:17px; color:#f8fafc; }
.modal-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:12px; }
.modal-grid .full { grid-column:1 / -1; }
.cred-row { display:flex; align-items:center; justify-content:space-between; gap:10px;
  margin-top:6px; font-size:12px; color:#cbd5e1; }
.cred-badge { border:1px solid #334155; border-radius:999px; padding:1px 8px;
  font-size:10.5px; font-weight:700; letter-spacing:.03em; }
.cred-badge.ok { color:#4ade80; border-color:#166534; background:#052e16; }
.cred-badge.miss { color:#fbbf24; border-color:#854d0e; background:#3b2f0b; }
.cred-badge.info { color:#93c5fd; border-color:#1e40af; background:#0c1e3a; }
#graph-toolbar { display:flex; align-items:center; gap:6px; flex-wrap:wrap;
  padding:8px 10px; border-bottom:1px solid var(--line); background:var(--panel2); }
#graph-toolbar button { padding:4px 9px; font-size:11px; }
#node-search { flex:1 1 160px; min-width:120px; margin:0; padding:5px 8px; font-size:12px; }
#type-filters { display:flex; flex-wrap:wrap; gap:4px; padding:6px 10px;
  border-bottom:1px solid var(--line); }
.graph-toggle { display:inline-flex; align-items:center; gap:5px; font-size:11px;
  color:#cbd5e1; margin:0; text-transform:none; letter-spacing:0; cursor:pointer; }
.graph-toggle input { width:auto; margin:0; }
.filter-pill { border:1px solid #334155; background:#0f172a; color:#cbd5e1;
  border-radius:999px; padding:2px 8px; font-size:10.5px; cursor:pointer; }
.filter-pill.active { border-color:#38bdf8; color:#f8fafc; background:#0c4a6e; }
.filter-pill .count { opacity:.7; margin-left:3px; }
.node-dim { opacity:.18; }
.node-match .node-circle { stroke:#facc15; stroke-width:4; }
#ui-message.error { color:#fca5a5; font-weight:600; }
.pill.completed { color:#4ade80; border-color:#166534; background:#052e16; }
</style>
</head>
<body>
<div id="workbench">
  <header>
    <h1>AI OSINT Hub Intelligence Workbench</h1>
    <span id="status-pill" class="pill" aria-live="polite">idle</span>
    <span id="target-label" class="muted"></span>
    <span class="spacer"></span>
    <span id="stats-line" class="muted"></span>
    <button id="open-api-keys" class="secondary" type="button"
            aria-haspopup="dialog" aria-controls="api-keys-modal">API Keys</button>
  </header>
  <main>
    <section class="panel intake-panel" aria-label="Intake">
      <h2>Intake</h2>
      <div class="panel-body">
        <form id="intake" autocomplete="off">
          <label for="in-raw">Free-form intelligence</label>
          <textarea id="in-raw" placeholder="Paste any OSINT notes, names, handles, emails, domains, phones, URLs, IPs…"></textarea>
          <label for="in-name">Full name</label>
          <input id="in-name" type="text" placeholder="e.g. John Smith">
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
          <details style="margin-top:10px">
            <summary class="muted" style="cursor:pointer;font-size:12px">Budgets &amp; thresholds</summary>
            <div class="grid2" style="margin-top:6px">
              <div><label for="in-max-iterations">Max iterations</label><input id="in-max-iterations" type="number" value="16" min="1" max="500"></div>
              <div><label for="in-max-tool-calls">Max tool calls</label><input id="in-max-tool-calls" type="number" value="20" min="1" max="1000"></div>
              <div><label for="in-timeout">Wall clock (s)</label><input id="in-timeout" type="number" value="600" min="5"></div>
              <div><label for="in-threshold">Min pivot score</label><input id="in-threshold" type="number" value="0.12" min="0" max="1" step="0.01"></div>
            </div>
          </details>
          <div class="row" style="margin-top:12px">
            <button id="run-investigation" type="submit">Start Investigation</button>
            <button id="run-pivot" class="secondary" type="button">Run Next Pivot</button>
            <button id="clear-form" class="secondary" type="button">Clear Form</button>
          </div>
          <p id="ui-message" role="alert"></p>
        </form>
      </div>
    </section>

    <section class="panel visualization-panel" aria-label="Visualization">
      <nav class="tabs" role="tablist">
        <button class="tab active" type="button" data-tab="graph">Graph</button>
        <button class="tab" type="button" data-tab="telemetry">Telemetry</button>
        <button class="tab" type="button" data-tab="dossier">Dossier</button>
      </nav>
      <div id="tab-graph" class="tab-panel active">
        <div id="graph-toolbar" aria-label="Graph controls">
          <button id="zoom-in" type="button" class="secondary" title="Zoom in">Zoom +</button>
          <button id="zoom-out" type="button" class="secondary" title="Zoom out">Zoom −</button>
          <button id="zoom-reset" type="button" class="secondary" title="Reset view">Reset</button>
          <input id="node-search" type="search" placeholder="Search nodes…"
                 aria-label="Search graph nodes">
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
          <svg id="graph" viewBox="0 0 960 620" preserveAspectRatio="xMidYMid meet"
               role="img" aria-label="Entity-resolved knowledge graph"></svg>
        </div>
      </div>
      <div id="tab-telemetry" class="tab-panel">
        <div class="panel-body" id="telemetry">
          <p class="muted">Start an investigation to see ledger, hypotheses and contradictions.</p>
        </div>
      </div>
      <div id="tab-dossier" class="tab-panel">
        <div class="dl-row">
          <a id="download-md" class="dl-link" href="#" download>Download Markdown</a>
          <a id="download-json" class="dl-link" href="#" download>Download JSON</a>
          <a id="download-html" class="dl-link" href="#" download>Download HTML</a>
        </div>
        <div class="panel-body">
          <pre id="dossier-text" class="dossier-pre">No dossier yet.</pre>
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
        <dl>
          <dt>SHA-256</dt><dd id="artifact-sha">—</dd>
          <dt>Source tool</dt><dd id="artifact-tool">—</dd>
          <dt>Confidence</dt><dd id="artifact-confidence">—</dd>
          <dt>Evidence snippet</dt><dd><pre id="artifact-snippet">Select a graph node or edge to inspect its cited evidence artifact.</pre></dd>
        </dl>
        <div id="inspector-claims"></div>
      </div>
    </aside>
  </main>
  <div id="api-keys-modal" class="modal-backdrop" hidden role="dialog"
       aria-modal="true" aria-labelledby="api-keys-title">
    <div class="modal-card">
      <h2 id="api-keys-title">API Keys</h2>
      <p class="muted" style="margin:0 0 6px;font-size:12px">
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
      <div class="row" style="margin-top:14px">
        <button id="save-api-keys" type="button">Save &amp; Sync Keys</button>
        <button id="close-api-keys" class="secondary" type="button">Close</button>
      </div>
      <p id="api-keys-message" role="alert" style="font-size:12px"></p>
    </div>
  </div>
</div>
<script>
(function () {
  "use strict";
  var state = {
    targetId: null, source: null, payload: null,
    graphView: {
      x: 0, y: 0, scale: 1, hidden: {}, search: "",
      showHypotheses: false,   // guessed permutations hidden by default
      showEdgeLabels: false    // permanent edge text off by default
    }
  };
  var TYPE_COLORS = {
    person: "#f472b6", username: "#60a5fa", email: "#34d399", domain: "#fbbf24",
    subdomain: "#f59e0b", ip: "#a78bfa", asn: "#8b5cf6", organization: "#f87171",
    phone: "#22d3ee", repository: "#94a3b8", social_profile: "#38bdf8",
    breach_record: "#ef4444", crypto_address: "#e879f9", service: "#4ade80",
    credential: "#fb7185", hash: "#cbd5e1", port: "#facc15", location: "#2dd4bf",
    url: "#93c5fd"
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
      updateDownloads();
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
      setText("target-label", data.target_id);
      setStatus(data.status === "started" ? "running" : String(data.status || ""));
      if (data.status === "started") { connectStream(); }
      updateDownloads();
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
      setText("stats-line", summarize(payload));
      clearError();
    }).catch(function (err) {
      // Uvicorn may briefly reject fetches while a heavy subprocess/SSE poll is
      // running. During an active investigation, retry silently instead of
      // painting a red "Failed to fetch" banner over a healthy run.
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
    renderTypeFilters(nodes);
    if (!nodes.length) {
      var empty = svgNode("text", "empty");
      empty.setAttribute("x", "28");
      empty.setAttribute("y", "44");
      empty.textContent = "No graph data yet — start an investigation.";
      svg.appendChild(empty);
      return;
    }
    var hypothesisCount = nodes.filter(function (node) {
      return !!node.is_hypothesis;
    }).length;
    setText("hyp-count", String(hypothesisCount));
    var visibleNodes = nodes.filter(function (node) {
      if (state.graphView.hidden[node.type]) { return false; }
      if (node.is_hypothesis && !state.graphView.showHypotheses) { return false; }
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
    visibleEdges.forEach(function (edge) {
      var from = positions[edge.subject], to = positions[edge.object];
      if (!from || !to) { return; }
      var line = svgNode("line", "edge-line");
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
      }
      group.setAttribute("transform", "translate(" + position.x + "," + position.y + ")");
      var circle = svgNode("circle", "node-circle");
      circle.setAttribute("r", String(nodeRadius));
      circle.setAttribute("fill", TYPE_COLORS[node.type] || "#94a3b8");
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
    clearError();
  }

  function zoomGraph(factor) {
    var view = state.graphView;
    view.scale = Math.max(0.3, Math.min(3.5, view.scale * factor));
    applyGraphTransform();
  }

  function resetGraphView() {
    state.graphView.x = 0;
    state.graphView.y = 0;
    state.graphView.scale = 1;
    applyGraphTransform();
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

  function renderInspector(title, badge, artifact, claims) {
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
    var claims = node.claims || [];
    renderInspector(node.type + ": " + node.value, node.status,
      firstArtifact(claims, payload), claims);
  }

  function inspectClaim(edge, payload) {
    var claim = {
      predicate: edge.predicate,
      object: edge.object,
      status: edge.status,
      confidence: edge.confidence,
      artifact_ids: edge.artifact_ids || []
    };
    renderInspector("edge: " + edge.predicate, edge.status,
      firstArtifact([claim], payload), [claim]);
  }

  function renderTelemetry(payload) {
    var container = byId("telemetry");
    if (!container) { return; }
    while (container.firstChild) { container.removeChild(container.firstChild); }
    var ledger = payload.ledger || [];
    var hypotheses = payload.hypotheses || [];
    var contradictions = payload.contradictions || [];

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

  function runNextPivot() {
    if (!state.targetId) { showError(new Error("start an investigation first")); return; }
    clearError();
    setStatus("stepping");
    api("/api/investigations/" + encodeURIComponent(state.targetId) + "/step", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    }).then(function (data) {
      setStatus(data && data.status ? String(data.status) : "stepped");
      return refreshState();
    }).catch(function (err) { setStatus("error"); showError(err); });
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
    if (name === "dossier") { fetchDossier(); }
  }

  function wire() {
    byId("intake").addEventListener("submit", startInvestigation);
    byId("run-pivot").addEventListener("click", runNextPivot);
    var clearButton = byId("clear-form");
    if (clearButton) { clearButton.addEventListener("click", clearForm); }
    var zoomIn = byId("zoom-in");
    if (zoomIn) { zoomIn.addEventListener("click", function () { zoomGraph(1.18); }); }
    var zoomOut = byId("zoom-out");
    if (zoomOut) { zoomOut.addEventListener("click", function () { zoomGraph(0.85); }); }
    var zoomReset = byId("zoom-reset");
    if (zoomReset) { zoomReset.addEventListener("click", resetGraphView); }
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
    updateDownloads();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
</script>
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
