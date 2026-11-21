"""Managed python wrappers for upstream OSINT tools that cannot run natively.

Each wrapper is a REAL tool: it performs live public-network queries with
``httpx`` and prints output in the format the corresponding deterministic parser
expects. Nothing here is mocked; a wrapper is only installed by
``python -m hub.cli doctor --provision`` when the real upstream package cannot
run on the available interpreter.

``WRAPPER_TOOLS`` is the registry consumed by the provisioner; add a module and
entry here to make a new wrapper available as a last-resort managed launcher.
"""

from __future__ import annotations

from typing import Any

WRAPPER_TOOLS: dict[str, dict[str, Any]] = {}


def register(tool_id: str, *, module: str, display_name: str = "",
             smoke_args: list[str] | None = None) -> None:
    WRAPPER_TOOLS[tool_id.strip().lower()] = {
        "module": module,
        "display_name": display_name or f"{tool_id} managed wrapper",
        "smoke_args": smoke_args or ["--help"],
    }


def wrapper_spec(tool_id: str) -> dict[str, Any]:
    key = tool_id.strip().lower()
    if key not in WRAPPER_TOOLS:
        raise KeyError(f"no managed wrapper implemented for {tool_id!r}")
    return WRAPPER_TOOLS[key]


__all__ = ["WRAPPER_TOOLS", "register", "wrapper_spec"]
