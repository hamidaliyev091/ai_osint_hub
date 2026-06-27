#!/usr/bin/env python3
"""MCP server for AI OSINT Hub — exposes orchestrator commands as MCP tools.

Listens on a Unix domain socket (~/.ai_osint_hub/mcp.sock) via SSE transport.
Routes to the same orchestrator functions that the CLI uses.
Backward compatible: CLI entry points still work independently.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.fastmcp import FastMCP
from hub.orchestrate import cmd_init, cmd_step, cmd_status, cmd_report

# ── Socket path ──────────────────────────────────────────
SOCKET_PATH = os.path.expanduser("~/.ai_osint_hub/mcp.sock")
SOCKET_DIR = os.path.dirname(SOCKET_PATH)
os.makedirs(SOCKET_DIR, exist_ok=True)

# ── FastMCP server ───────────────────────────────────────
mcp = FastMCP(
    name="AI OSINT Hub",
    instructions="Autonomous OSINT investigation orchestrator — 9 tools, exposure graph mapping, credential recovery",
)


# ── MCP Tools ────────────────────────────────────────────

@mcp.tool()
def osint_init(raw_input: str, max_depth: int = 5, time_budget_minutes: int = 30) -> dict:
    """Initialize a new OSINT investigation from raw intelligence.

    Provide any identifying information: name, email, username, phone, domain,
    or free-form text describing the target. The system parses the input,
    generates investigative hypotheses, and returns ranked candidate actions.

    Args:
        raw_input: Free-form target description (name, email, username, domain, etc.)
        max_depth: Maximum investigation turns (default 5)
        time_budget_minutes: Wall-clock time limit in minutes (default 30)

    Returns:
        Investigation state with target_id, parsed entities, generated hypotheses,
        candidate actions ranked by score, and graph summary.
    """
    constraints = {"max_depth": max_depth, "time_budget_minutes": time_budget_minutes}
    return cmd_init(raw_input, constraints)


@mcp.tool()
def osint_step(target_id: str, selected_action_id: str, max_depth: int = 5) -> dict:
    """Execute one selected action in an active investigation.

    Call osint_status first to get the current candidate list, pick the
    highest-priority action_id, then call osint_step with it. The orchestrator
    validates the action_id against stored state, executes the tool, parses
    output, updates the exposure graph, and returns new candidates.

    Args:
        target_id: Investigation ID from osint_init
        selected_action_id: Action ID from the candidate list (e.g., "act_000")
        max_depth: Override max depth for this step (default 5)

    Returns:
        Turn result with execution_status, new_entities_count, parse_errors,
        updated candidates, hard_stops, soft_stops, and stop_recommendation.
    """
    constraints = {"max_depth": max_depth}
    return cmd_step(target_id, selected_action_id=selected_action_id, constraints=constraints)


@mcp.tool()
def osint_status(target_id: str) -> dict:
    """Get current investigation state for resume or inspection.

    Use this after a crash, timeout, or to inspect progress mid-investigation.
    Returns the full candidate list with scores, last 3 turns, and graph summary.

    Args:
        target_id: Investigation ID from osint_init

    Returns:
        Current state with investigation metadata, graph summary, candidate
        actions, completeness score, and last 3 turn summaries.
    """
    return cmd_status(target_id)


@mcp.tool()
def osint_report(target_id: str) -> dict:
    """Generate final investigation report in Markdown.

    Call this after the investigation reaches a hard stop or you decide to
    terminate. Returns a structured report with discovered entities by type,
    relationships, breach exposures, and security recommendations.

    Args:
        target_id: Investigation ID from osint_init

    Returns:
        Final report with report_md (Markdown), graph_summary, and status.
    """
    return cmd_report(target_id)


# ── Main ────────────────────────────────────────────────

def main():
    """Run the MCP server on a Unix domain socket."""
    import uvicorn

    # Remove stale socket
    if os.path.exists(SOCKET_PATH):
        try:
            os.unlink(SOCKET_PATH)
        except OSError:
            pass

    print(f"MCP server starting on {SOCKET_PATH}", file=sys.stderr)

    app = mcp.sse_app()
    config = uvicorn.Config(app, uds=SOCKET_PATH, log_level="warning")
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
