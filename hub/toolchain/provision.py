"""Idempotent toolchain provisioning for ``python -m hub.cli doctor --provision``.

Provisioning strategy (all real installs, no mocked tools):

1. Ensure the managed layout: ``~/.ai_osint_hub/bin`` plus the repo ``.venv``
   (and an extra ``.venv314`` for tools that require Python ≥ 3.12).
2. Install the python OSINT CLIs that are not already resolvable into the
   managed venv via ``uv pip`` (falling back to ``python -m pip``).
3. Provision native binaries: download the official phoneinfoga release into the
   managed bin dir; install ``whatweb`` / ``hashcat`` / ``hydra`` inside the WSL2
   distro when the Windows host lacks them (the locator bridges to WSL).
4. Only if a tool still cannot be resolved, install a managed shell-free wrapper
   launcher from :mod:`hub.toolchain.wrappers` (real httpx implementations for
   upstream packages that cannot run on a supported interpreter).

Only tools that are *not already resolvable* are touched, so repeated runs are
fast and safe.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from hub.tools import capabilities, locator
from hub.toolchain.wrappers import WRAPPER_TOOLS, wrapper_spec

PROVISION_TIMEOUT_SEC = 900
UV = shutil.which("uv")
PYTHON_TOOL_SPECS: dict[str, str] = {
    "holehe": "holehe",
    "maigret": "maigret",
    "h8mail": "h8mail",
    "sherlock": "sherlock-project",
    "ghunt": "ghunt",
    # snscrape is now a python-native builtin collector (no pip CLI needed).
}
HARVESTER_SPEC = "git+https://github.com/laramies/theHarvester.git@4.11.1"
PHONEINFOGA_RELEASE = ("https://api.github.com/repos/sundowndev/phoneinfoga/"
                       "releases/latest")
WSL_APT_PACKAGES = {"whatweb": "whatweb", "hashcat": "hashcat", "hydra": "hydra"}


@dataclass
class ProvisionReport:
    actions: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: str = ""

    def record(self, tool_id: str, action: str, detail: str = "",
               ok: bool = True) -> None:
        self.actions.append({
            "tool_id": tool_id,
            "action": action,
            "detail": detail,
            "ok": bool(ok),
        })
        if not ok:
            self.errors.append(f"{tool_id}: {detail}")

    def as_dict(self) -> dict[str, Any]:
        checked = {action["tool_id"] for action in self.actions}
        # Provisioning counts *executable/resolved* tools; missing API credentials
        # are an auth concern (pivot gating), not a provisioning failure.
        statuses = capabilities.health_check_all(force=True)
        resolved = {status.tool_id for status in statuses if status.available}
        return {
            "started_at": self.started_at,
            "duration_sec": round(time.time() - _STARTED.get("monotonic", time.monotonic()), 2),
            "checked_tools": sorted(checked),
            "actions": self.actions,
            "errors": self.errors,
            "available": len(resolved),
            "total": len(capabilities.all_capabilities()),
        }


_STARTED: dict[str, float] = {}


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════

def _run(command: list[str], *, timeout: int = PROVISION_TIMEOUT_SEC,
         cwd: Optional[str] = None) -> tuple[int, str]:
    """Run a provisioning subprocess, returning (exit_code, tail_of_output)."""
    try:
        process = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    output = ((process.stdout or "") + "\n" + (process.stderr or "")).strip()
    return process.returncode, output[-3000:]


def _venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts" if os.name == "nt" else "bin") / (
        "python.exe" if os.name == "nt" else "python")


def venv_dir_for(python_spec: str) -> Path:
    """Canonical managed venv directory for a Python feature version."""
    spec = python_spec.strip()
    if spec in {"3.11", "3.10", "3.12", "3"}:
        return locator.repo_root() / ".venv"
    suffix = spec.replace(".", "")
    return locator.repo_root() / f".venv{suffix}"


def ensure_managed_venv(python_spec: str = "3.11") -> tuple[Optional[Path], str]:
    """Create/return a managed venv; returns (python_path, detail)."""
    venv_dir = venv_dir_for(python_spec)
    python_path = _venv_python(venv_dir)
    if python_path.exists():
        return python_path, f"managed venv already present at {venv_dir}"
    if UV:
        code, output = _run([UV, "venv", str(venv_dir), "--python", python_spec],
                            timeout=600)
        if code == 0 and python_path.exists():
            return python_path, f"created managed venv {venv_dir} (python {python_spec})"
    # Fallback: system interpreter venv (no uv or no matching download).
    code, output = _run([sys.executable, "-m", "venv", str(venv_dir)], timeout=600)
    if code == 0 and python_path.exists():
        return python_path, f"created fallback venv {venv_dir} with {sys.version.split()[0]}"
    return None, f"failed to create venv {venv_dir}: {output[-400:]}"


def install_python_spec(venv_python: Path, spec: str) -> tuple[bool, str]:
    """Install one pip spec into a managed venv (uv if available)."""
    if UV:
        code, output = _run([UV, "pip", "install", "--python", str(venv_python),
                             spec])
    else:
        code, output = _run([str(venv_python), "-m", "ensurepip", "--default-pip"])
        code, output = _run([str(venv_python), "-m", "pip", "install", spec])
    return code == 0, output


def download_phoneinfoga(destination: Path) -> tuple[bool, str]:
    """Download the official phoneinfoga release binary into the managed bin dir."""
    try:
        request = urllib.request.Request(
            PHONEINFOGA_RELEASE,
            headers={"User-Agent": "ai-osint-hub-provisioner",
                     "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            release = json.loads(response.read().decode("utf-8"))
        tag = str(release.get("tag_name", "")).lstrip("v") or "latest"
        assets = release.get("assets") or []
        if os.name == "nt":
            wanted = f"phoneinfoga_Windows_{'arm64' if _is_arm() else 'x86_64'}.tar.gz"
        else:
            wanted = f"phoneinfoga_{'Darwin' if sys.platform == 'darwin' else 'Linux'}_"\
                     f"{'arm64' if _is_arm() else 'x86_64'}.tar.gz"
        asset = next((a for a in assets if a.get("name") == wanted), None)
        if asset is None:
            return False, f"release asset {wanted!r} not found for tag {tag}"
        destination.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="phoneinfoga_") as temporary:
            archive = Path(temporary) / wanted
            with urllib.request.urlopen(asset["browser_download_url"],
                                        timeout=120) as response:  # noqa: S310
                archive.write_bytes(response.read())
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(temporary)  # noqa: S202 - trusted release archive
            candidates = list(Path(temporary).rglob("phoneinfoga*"))
            binary = next((path for path in candidates
                           if path.is_file() and not path.suffix
                           or path.suffix.lower() in {".exe", ""}), None)
            if binary is None:
                return False, "phoneinfoga binary not found inside release archive"
            target = destination / ("phoneinfoga.exe" if os.name == "nt" else "phoneinfoga")
            shutil.copy2(binary, target)
        try:
            target.chmod(0o755)
        except OSError:
            pass
        return True, f"installed phoneinfoga release {tag} at {target}"
    except Exception as exc:  # noqa: BLE001 - provisioning must report, not crash
        return False, f"phoneinfoga download failed: {type(exc).__name__}: {exc}"


def _is_arm() -> bool:
    import platform

    return platform.machine().lower() in {"arm64", "aarch64"}


def install_wsl_packages(tool_ids: list[str]) -> tuple[bool, str]:
    """Install tools inside the WSL distro when the Windows host lacks them."""
    if not locator.wsl_available():
        return False, "no WSL distro available"
    distro = locator.wsl_distro()
    exe = shutil.which("wsl.exe") or shutil.which("wsl")
    if not distro or not exe:
        return False, "wsl.exe/distro unavailable"
    packages = [WSL_APT_PACKAGES[tool] for tool in tool_ids if tool in WSL_APT_PACKAGES]
    if not packages:
        return False, "no WSL-installable tools requested"
    script = ("sudo -n apt-get update -qq && sudo -n apt-get install -y -qq "
              + " ".join(packages))
    code, output = _run([exe, "-d", distro, "--", "bash", "-lc", script], timeout=900)
    locator.clear_wsl_cache()
    return code == 0, output[-1500:]


def ensure_tool_home(tool_id: str) -> Path:
    """Create a writable per-tool home (sandboxed managed venvs cannot write ~)."""
    from hub.tools.capabilities import tool_home

    home = tool_home(tool_id)
    for relative in (".theHarvester", ".local/share/theHarvester", ".config"):
        try:
            (home / relative).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    return home


def install_wrapper(tool_id: str, report: ProvisionReport) -> bool:
    """Create a managed shell-free wrapper launcher if a wrapper exists."""
    if tool_id not in WRAPPER_TOOLS:
        report.record(tool_id, "no-fallback", "no managed wrapper implemented", ok=False)
        return False
    spec = wrapper_spec(tool_id)
    result = locator.write_wrapper_launcher(
        tool_id,
        module=spec["module"],
        smoke_args=spec.get("smoke_args", ["--help"]),
        display_name=spec.get("display_name", ""),
    )
    report.record(tool_id, "wrapper-installed",
                  f"managed wrapper launcher {result['descriptor']}")
    return True


# ════════════════════════════════════════════════════════════════════════
# Main entry point
# ════════════════════════════════════════════════════════════════════════

def provision_toolchain() -> dict[str, Any]:
    """Provision everything missing; idempotent and safe to re-run."""
    _STARTED["monotonic"] = time.monotonic()
    report = ProvisionReport(
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    locator.reset_cache()
    locator.clear_wsl_cache()
    locator.ensure_managed_dirs()

    def resolved(tool_id: str) -> locator.ResolvedTool:
        capability = capabilities.get_tool(tool_id)
        binary = capability.invocation.binary if capability else tool_id
        return locator.resolve_tool(tool_id, binary, force=True,
                                    allow_wrappers=False)

    # ── 1. python OSINT CLIs in the primary managed venv ─────────────
    primary_python: Optional[Path] = None
    for tool_id, spec in PYTHON_TOOL_SPECS.items():
        if resolved(tool_id).available:
            report.record(tool_id, "already-available", "resolved without provisioning")
            continue
        if primary_python is None:
            primary_python, detail = ensure_managed_venv("3.11")
            report.record("managed-venv", "ensured", detail, ok=primary_python is not None)
        if primary_python is None:
            report.record(tool_id, "install-skipped", "managed venv unavailable", ok=False)
            continue
        ok, output = install_python_spec(primary_python, spec)
        locator.reset_cache()
        if ok and resolved(tool_id).available:
            report.record(tool_id, "installed", f"pip install {spec}")
        else:
            report.record(tool_id, "install-failed",
                          f"pip install {spec} failed: {output[-400:]}", ok=False)
            install_wrapper(tool_id, report)

    # ── 2. theHarvester (requires Python >= 3.12 upstream) ───────────
    for tool_id in ("theharvester", "phoneinfoga", "whatweb", "hashcat", "hydra"):
        ensure_tool_home(tool_id)
    if resolved("theharvester").available:
        report.record("theharvester", "already-available")
    else:
        python314, detail = ensure_managed_venv("3.14")
        report.record("theharvester-venv", "ensured", detail, ok=python314 is not None)
        if python314 is not None:
            ok, output = install_python_spec(python314, HARVESTER_SPEC)
            locator.reset_cache()
            if ok and resolved("theharvester").available:
                report.record("theharvester", "installed",
                              f"pip install {HARVESTER_SPEC} into .venv314")
            else:
                # Try the py3.11-compatible path as a second chance before wrapper.
                if primary_python is None:
                    primary_python, _ = ensure_managed_venv("3.11")
                if primary_python is not None:
                    ok311, output311 = install_python_spec(primary_python, HARVESTER_SPEC)
                    locator.reset_cache()
                    if ok311 and resolved("theharvester").available:
                        report.record("theharvester", "installed",
                                      f"pip install {HARVESTER_SPEC} into .venv311")
                        ok = True
                if not (ok and resolved("theharvester").available):
                    report.record("theharvester", "install-failed",
                                  f"upstream install failed: {output[-400:]}", ok=False)
                    install_wrapper("theharvester", report)

    # ── 3. native binary tools ───────────────────────────────────────
    if not resolved("phoneinfoga").available:
        ok, detail = download_phoneinfoga(locator.home_bin())
        locator.reset_cache()
        report.record("phoneinfoga", "downloaded" if ok else "download-failed",
                      detail, ok=ok)
        if not ok:
            install_wrapper("phoneinfoga", report)

    missing_wsl = [tool for tool in ("whatweb", "hashcat", "hydra")
                   if not resolved(tool).available]
    if missing_wsl:
        ok, output = install_wsl_packages(missing_wsl)
        locator.reset_cache()
        locator.reset_cache()
        if ok:
            for tool in missing_wsl:
                if resolved(tool).available:
                    report.record(tool, "wsl-installed", "apt-get install inside WSL")
                else:
                    report.record(tool, "wsl-install-failed", output[-300:], ok=False)
                    install_wrapper(tool, report)
        else:
            for tool in missing_wsl:
                report.record(tool, "wsl-install-failed", output[-300:], ok=False)
                install_wrapper(tool, report)

    # ── 4. final wrapper fallback for any still-unresolved tool ─────
    for capability in capabilities.all_capabilities():
        tool_id = capability.tool_id
        if tool_id in ("dns_lookup", "http_headers", "tls_cert"):
            continue
        if resolved(tool_id).available or locator.resolve_tool(
                tool_id, capability.invocation.binary, force=True).available:
            continue
        install_wrapper(tool_id, report)

    locator.reset_cache()
    return report.as_dict()


__all__ = [
    "PYTHON_TOOL_SPECS",
    "HARVESTER_SPEC",
    "provision_toolchain",
    "ensure_managed_venv",
    "install_python_spec",
    "download_phoneinfoga",
    "install_wsl_packages",
    "install_wrapper",
]
