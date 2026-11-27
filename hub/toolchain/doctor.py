"""Toolchain provisioning + doctor (``python -m hub.cli doctor --provision``).

The doctor proves each registered capability is *actually executable* on this
host, not merely declared:

* resolves the tool through the full locator chain (managed bins → PATH → WSL2
  bridge → managed python wrapper);
* runs a real ``--version`` / ``--help`` smoke command with a timeout and
  captures exit code + output;
* reports the resolver and absolute location for every tool.

``--provision`` first ensures the managed layout (``~/.ai_osint_hub/bin`` and
the repo ``.venv`` script dirs), installs missing python OSINT CLIs into the
managed venv, installs WSL-side binaries when the bridge is present, downloads
the official phoneinfoga release on Windows, and finally creates shell-free
managed wrapper launchers for anything whose upstream package cannot run on the
available interpreters. It is idempotent: healthy tools are never reinstalled.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from hub.tools import capabilities, locator
from hub.tools.locator import install_hint
from hub.tools.runtime import scrub_environment

SMOKE_TIMEOUT_SEC = 60
SMOKE_OUTPUT_LIMIT = 220

#: Tool-specific smoke invocations (a real subprocess runs for binaries).
SMOKE_ARGS: dict[str, list[str]] = {
    "holehe": ["--help"],
    "maigret": ["--version"],
    "h8mail": ["--help"],
    "theharvester": ["--help"],
    "sherlock": ["--version"],
    "ghunt": ["--help"],
    "snscrape": ["--version"],
    "phoneinfoga": ["help"],
    "whatweb": ["--version"],
    "hashcat": ["--version"],
    "hydra": ["-h"],
    "nmap": ["--version"],
    "amass": ["--version"],
    "gobuster": ["version"],
    "dns_lookup": [],
    "http_headers": [],
    "tls_cert": [],
}

_BUILTIN_TOOLS = {"dns_lookup", "http_headers", "tls_cert"}


@dataclass
class ToolCheck:
    """Doctor result for one capability."""

    tool_id: str
    available: bool
    resolver: str = ""
    location: str = ""
    smoke_ok: bool = False
    smoke_exit_code: Optional[int] = None
    smoke_output: str = ""
    detail: str = ""
    auth_status: str = "NOT_REQUIRED"
    auth_detail: str = ""
    install_hint: str = ""
    policy_blocked: bool = False
    ui_status: str = "ready"

    @property
    def auth_ready(self) -> bool:
        return self.auth_status not in {"MISSING_KEY", "PARTIAL",
                                        "OPTIONAL_UNCONFIGURED"}

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "available": self.available,
            "resolver": self.resolver,
            "location": self.location,
            "smoke_ok": self.smoke_ok,
            "smoke_exit_code": self.smoke_exit_code,
            "smoke_output": self.smoke_output,
            "detail": self.detail,
            "auth_status": self.auth_status,
            "auth_detail": self.auth_detail,
            "auth_ready": self.auth_ready,
            "install_hint": self.install_hint,
            "policy_blocked": self.policy_blocked,
            "ui_status": self.ui_status,
            "ok": bool(self.available and self.smoke_ok),
        }


def _shorten(text: str, limit: int = SMOKE_OUTPUT_LIMIT) -> str:
    text = (text or "").replace("\x1b", "").strip()
    text = " ".join(text.split())
    return text[:limit]


def smoke_tool(resolved: locator.ResolvedTool, tool_id: str, *,
               timeout: int = SMOKE_TIMEOUT_SEC) -> tuple[bool, Optional[int], str]:
    """Run a real ``--version``/``--help`` smoke command for a resolved tool."""
    args = SMOKE_ARGS.get(tool_id.lower(), ["--help"])
    if not resolved.available:
        return False, None, ""
    command = resolved.command(args)
    capability = capabilities.get_tool(tool_id)
    environment = locator.enrich_child_env(scrub_environment(), resolved)
    if capability is not None:
        environment.update(capabilities.invocation_env(capability))
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    environment.setdefault("PYTHONUTF8", "1")
    try:
        process = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=environment,
        )
    except subprocess.TimeoutExpired:
        return False, None, f"smoke check timed out after {timeout}s"
    except (OSError, ValueError) as exc:
        return False, None, f"smoke spawn failed: {type(exc).__name__}: {exc}"
    output = _shorten((process.stdout or "") + " " + (process.stderr or ""))
    # Many CLI tools exit 1/2 for --help while still printing valid usage text;
    # a traceback or a completely silent nonzero exit does not count as healthy.
    lower = output.lower()
    looks_valid = any(marker in lower for marker in (
        "usage", "version", "options", "help", "commands", "examples", "syntax",
        tool_id.lower(),
    ))
    # Some legitimate CLIs exit non-zero for --help (e.g. hydra exits 255 after
    # printing usage). Anything that produced recognisable CLI text and no Python
    # traceback is considered executable.
    ok = process.returncode == 0 or (bool(output) and looks_valid
                                     and "traceback" not in lower)
    return bool(ok), process.returncode, output


def _ui_status(available: bool, auth_status: str, policy_blocked: bool) -> str:
    if policy_blocked:
        return "blocked"
    if not available:
        return "missing"
    if auth_status in {"MISSING_KEY", "PARTIAL"}:
        return "needs_key"
    return "ready"


def check_tool(tool_id: str, *, force: bool = True, smoke: bool = True) -> ToolCheck:
    from hub.models import ExecutionMode

    capability = capabilities.get_tool(tool_id)
    if capability is None:
        return ToolCheck(tool_id=tool_id, available=False, detail="unknown tool",
                         install_hint=install_hint(tool_id), ui_status="missing")
    policy_blocked = capability.execution_mode == ExecutionMode.INTRUSIVE_BLOCKED
    auth_status, auth_detail = capabilities.capability_auth(capability)
    if tool_id.lower() in _BUILTIN_TOOLS or capability.invocation.kind == "builtin":
        status = capabilities.health_check(tool_id, force=force)
        avail = bool(status and status.available)
        return ToolCheck(
            tool_id=tool_id,
            available=avail,
            resolver="builtin",
            location=capability.invocation.builtin_ref or "",
            smoke_ok=avail,
            smoke_exit_code=0 if avail else None,
            smoke_output=(status.detail if status else "")[:SMOKE_OUTPUT_LIMIT],
            detail=status.detail if status else "",
            auth_status=auth_status,
            auth_detail=auth_detail,
            install_hint="" if avail else install_hint(tool_id),
            policy_blocked=policy_blocked,
            ui_status=_ui_status(avail, auth_status, policy_blocked),
        )
    binary = capability.invocation.binary or tool_id
    resolved = locator.resolve_tool(tool_id, binary, force=force)
    if smoke:
        smoke_ok, exit_code, output = smoke_tool(resolved, tool_id)
    else:
        smoke_ok = resolved.available
        exit_code = None
        output = "smoke skipped (--no-smoke)" if resolved.available else ""
    return ToolCheck(
        tool_id=tool_id,
        available=resolved.available,
        resolver=resolved.source,
        location=resolved.location,
        smoke_ok=smoke_ok,
        smoke_exit_code=exit_code,
        smoke_output=output,
        detail=resolved.detail,
        auth_status=auth_status,
        auth_detail=auth_detail,
        install_hint="" if resolved.available else install_hint(tool_id),
        policy_blocked=policy_blocked,
        ui_status=_ui_status(resolved.available, auth_status, policy_blocked),
    )


def run_doctor(*, provision: bool = False, force: bool = True,
               smoke: bool = True) -> dict[str, Any]:
    """Check every registered tool; optionally provision first."""
    started = time.time()
    provisioning: dict[str, Any] = {}
    if provision:
        from hub.toolchain.provision import provision_toolchain
        provisioning = provision_toolchain()
        locator.reset_cache()
    checks = [check_tool(cap.tool_id, force=force, smoke=smoke)
              for cap in capabilities.all_capabilities()]
    rows = [check.as_dict() for check in checks]
    healthy = [row for row in rows if row["ok"]]
    available = [row for row in rows if row["available"]]
    missing = [row["tool_id"] for row in rows if not row["available"]]
    smoke_failed = [row["tool_id"] for row in rows
                    if row["available"] and not row["smoke_ok"]]
    auth_ready = [row for row in rows if row.get("auth_ready", True)]
    auth_blocked = [row["tool_id"] for row in rows if not row.get("auth_ready", True)]
    return {
        "status": "ok" if len(available) == len(rows) else "incomplete",
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_sec": round(time.time() - started, 2),
        "total": len(rows),
        "available": len(available),
        "healthy": len(healthy),
        "smoke_skipped": not smoke,
        "missing": missing,
        "smoke_failed": smoke_failed,
        "auth_ready": len(auth_ready),
        "auth_blocked": auth_blocked,
        "tools": rows,
        "provisioning": provisioning,
        "managed_bin_dirs": [str(p) for p in locator.managed_bin_dirs()],
        "wsl": {
            "available": locator.wsl_available(),
            "distro": locator.wsl_distro(),
            "probe": locator._detect_wsl().get("probe", ""),
        },
        "table": render_doctor_table(rows),
    }


def render_doctor_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| # | Tool | Available | Smoke | Auth | Resolver | Location |",
        "|---|------|-----------|-------|------|----------|----------|",
    ]
    for index, row in enumerate(rows, start=1):
        available = "✅ AVAILABLE" if row["available"] else "❌ MISSING"
        smoke = "✅ ok" if row["smoke_ok"] else "❌ fail"
        auth = row.get("auth_status", "NOT_REQUIRED")
        auth_icon = {"CONFIGURED": "🔑 ", "KEYLESS_LIMITED": "🔓 ",
                     "NOT_REQUIRED": "— "}.get(auth, "⚠️ ")
        location = row["location"] or ""
        if len(location) > 70:
            location = "…" + location[-69:]
        lines.append(
            f"| {index} | `{row['tool_id']}` | {available} | {smoke} | "
            f"{auth_icon}{auth} | {row['resolver'] or '-'} | "
            f"{location.replace('|', '/')} |"
        )
    return "\n".join(lines)


def doctor_summary_line(result: dict[str, Any]) -> str:
    mode_note = "smoke skipped" if result.get("smoke_skipped") else f"smoke-checked in {result['duration_sec']}s"
    line = (f"{result['available']}/{result['total']} tools AVAILABLE, "
            f"{result['healthy']}/{result['total']} healthy "
            f"({mode_note})")
    if "auth_ready" in result:
        line += (f"; credentials ready for {result['auth_ready']}/{result['total']} "
                 f"tools")
    return line


def format_doctor_report(result: dict[str, Any]) -> str:
    lines = [
        "AI OSINT Hub — toolchain doctor",
        "=" * 32,
        f"Managed bin dirs: {', '.join(result['managed_bin_dirs'])}",
        f"WSL bridge: {'✅ ' + str(result['wsl']['distro']) if result['wsl']['available'] else '❌ ' + str(result['wsl']['probe'])}",
        "",
        result["table"],
        "",
        doctor_summary_line(result),
    ]
    if result["missing"]:
        lines.append("Missing: " + ", ".join(result["missing"]))
        lines.append("Install hints:")
        for tool_id in result["missing"]:
            lines.append(f"  - {tool_id}: {install_hint(tool_id)}")
    if result["smoke_failed"]:
        lines.append("Available but smoke-failed: " + ", ".join(result["smoke_failed"]))
    if result.get("auth_blocked"):
        lines.append("Awaiting API credentials (skipped by pivot planner): "
                     + ", ".join(result["auth_blocked"]))
        lines.append("Configure via the Web UI API Keys drawer or "
                     "`python -m hub.cli auth set <provider> <value>`.")
    provisioning = result.get("provisioning") or {}
    if provisioning:
        actions = provisioning.get("actions") or []
        if actions:
            lines.append("")
            lines.append("Provisioning actions:")
            for action in actions[:40]:
                lines.append(f"  - {action.get('tool_id', '')}: {action.get('action', '')} — "
                             f"{action.get('detail', '')}")
    return "\n".join(lines)


__all__ = [
    "SMOKE_ARGS",
    "ToolCheck",
    "check_tool",
    "smoke_tool",
    "run_doctor",
    "render_doctor_table",
    "format_doctor_report",
    "doctor_summary_line",
    "install_hint",
]
