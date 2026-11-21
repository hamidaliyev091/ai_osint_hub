"""Legacy compatibility entry point: ``python -m hub.orchestrate``.

The v1 orchestrator (JSON-per-file state, POSIX-only fcntl locking, ad-hoc
candidate scoring) was replaced by the ERKG + pivot engine in v2. This module is
a thin, cross-platform shim so existing scripts keep working:

  python -m hub.orchestrate --init   '{"raw_input":"...","constraints":{}}'
  python -m hub.orchestrate --status '{"target_id":"..."}'
  python -m hub.orchestrate --step   '{"target_id":"...","selected_action_id":"act_000"}'
  python -m hub.orchestrate --report '{"target_id":"..."}'

New integrations should use ``python -m hub.cli`` or the MCP server instead.
Legacy ``act_NNN`` ids are mapped onto the current deterministic pivot ids.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

from hub.service import InvestigationService, _pivots_to_legacy_actions


def _service() -> InvestigationService:
    return InvestigationService()


def cmd_init(raw_input: str, constraints: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Create an investigation and return ranked legacy-shaped candidate actions."""
    return _service().create(raw_input, constraints=constraints or {})


def cmd_status(target_id: str) -> dict[str, Any]:
    """Return current state, stats and legacy-shaped candidate actions."""
    return _service().status(target_id)


def cmd_step(target_id: str, selected_action_id: Optional[str] = None,
             action: Optional[dict[str, Any]] = None,
             constraints: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Execute one step using legacy act_NNN ids or a raw {tool, params} action."""
    service = _service()
    pivot_id: Optional[str] = None
    if selected_action_id:
        if selected_action_id.startswith("piv_"):
            pivot_id = selected_action_id
        else:
            preview = service.status(target_id)
            if preview.get("status") == "error":
                return preview
            for candidate in preview.get("candidate_actions", []):
                if candidate["action_id"] == selected_action_id:
                    pivot_id = candidate["pivot_id"]
                    break
            if pivot_id is None:
                return {"status": "error",
                        "errors": [f"invalid action_id '{selected_action_id}'. "
                                   f"Current ids: "
                                   f"{[c['action_id'] for c in preview.get('candidate_actions', [])]}"]}
    elif action:
        preview = service.status(target_id)
        if preview.get("status") == "error":
            return preview
        tool = action.get("tool")
        params = action.get("params") or {}
        for candidate in preview.get("candidate_actions", []):
            if candidate["tool"] == tool and candidate["params"] == params:
                pivot_id = candidate["pivot_id"]
                break
        if pivot_id is None:
            return {"status": "error",
                    "errors": [f"raw action {tool}:{params} is not in the current "
                               f"candidate list"]}
    else:
        return {"status": "error", "errors": ["No selected_action_id or action provided"]}

    result = service.step(target_id, pivot_id=pivot_id)
    if result.get("status") == "error":
        return result
    record = result.get("record") or {}
    execution = result.get("execution") or {}
    legacy = {
        "turn": result.get("iteration"),
        "status": "completed" if not result.get("stopped") else "stopped",
        "action_taken": result.get("action"),
        "execution_status": execution.get("status", "unknown"),
        "new_entities_count": len(record.get("new_entity_ids", [])),
        "new_claims": record.get("new_claims", 0),
        "parse_errors": (execution.get("warnings") or [])[:5],
        "duration_ms": execution.get("duration_ms", 0),
        "candidate_actions": _pivots_to_legacy_actions(result.get("next_pivots", [])),
        "candidate_count": len(result.get("next_pivots", [])),
        "stop_reason": result.get("stop_reason"),
        "objectives": result.get("objectives"),
        "graph_summary": result.get("graph_summary"),
        "execution": execution,
        "next_pivots": result.get("next_pivots"),
        "reflection": result.get("reflection"),
    }
    return legacy


def cmd_report(target_id: str) -> dict[str, Any]:
    """Generate the evidence-cited dossier in legacy {report_md, ...} shape."""
    result = _service().report(target_id, fmt="md")
    if result.get("status") == "error":
        return result
    return {
        "status": "complete",
        "target_id": target_id,
        "report_md": result.get("content", ""),
        "report_path": result.get("path"),
        "summary": result.get("summary"),
    }


def main(argv: Optional[list[str]] = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    parser = argparse.ArgumentParser(prog="orchestrate (legacy shim)")
    parser.add_argument("--init", type=str, default=None,
                        help='JSON {"raw_input": "...", "constraints": {}}')
    parser.add_argument("--step", type=str, default=None,
                        help='JSON {"target_id": "...", "selected_action_id": "act_000"}')
    parser.add_argument("--status", type=str, default=None,
                        help='JSON {"target_id": "..."}')
    parser.add_argument("--report", type=str, default=None,
                        help='JSON {"target_id": "..."}')
    args = parser.parse_args(argv)

    if args.init:
        data = json.loads(args.init)
        result = cmd_init(data["raw_input"], data.get("constraints", {}))
    elif args.step:
        data = json.loads(args.step)
        result = cmd_step(
            data["target_id"],
            selected_action_id=data.get("selected_action_id"),
            action=data.get("action"),
            constraints=data.get("constraints", {}),
        )
    elif args.status:
        data = json.loads(args.status)
        result = cmd_status(data["target_id"])
    elif args.report:
        data = json.loads(args.report)
        result = cmd_report(data["target_id"])
    else:
        print(json.dumps({"status": "error", "errors": ["No command specified"]}))
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
