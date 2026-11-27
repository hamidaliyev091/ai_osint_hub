"""Toolchain locator — how the hub finds and launches every OSINT tool.

Resolution order (Spec: managed dirs → host PATH → WSL2 bridge → packaged
python wrappers):

1. **Managed launcher descriptors** in ``~/.ai_osint_hub/bin/<tool>.launcher.json``
   (shell-free ``python -m hub.toolchain.wrappers.<tool>`` launchers created by
   ``hub.cli doctor --provision``).
2. **Managed native executables** in ``~/.ai_osint_hub/bin`` and the managed
   venv scripts directory (``<repo>/.venv/Scripts`` on Windows,
   ``<repo>/.venv/bin`` on POSIX). Prepended automatically so freshly installed
   binaries are found without restarting the shell/Windows PATH.
3. **Host PATH** via :func:`shutil.which`.
4. **WSL2 transparent bridge** (Windows): if the binary exists inside the WSL
   distro, execute it as ``wsl.exe -d <distro> -- bash -lc 'exec "$0" "$@"' <tool>``
   with ``shell=False`` on the Windows side.
5. **Packaged python wrapper fallback** for tools whose upstream package cannot
   run on this interpreter (real ``httpx`` passive implementations live in
   :mod:`hub.toolchain.wrappers`).

Everything is cached briefly; ``force=True`` re-probes (used by doctor).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

MANAGED_BIN_ENV = "AI_OSINT_HUB_BIN"
MANAGED_VENV_ENV = "AI_OSINT_HUB_VENV_BIN"
PYTHON_ENV = "AI_OSINT_HUB_PYTHON"
WSL_ENV = "AI_OSINT_HUB_WSL"                 # "0" disables the WSL bridge
WSL_DISTRO_ENV = "AI_OSINT_HUB_WSL_DISTRO"   # default: Ubuntu / first distro
CACHE_TTL_SEC = 45.0
WSL_PROBE_TIMEOUT_SEC = 12
NMAP_PROBE_TIMEOUT_SEC = 2.0
TRAMPOLINE_PROBE_TIMEOUT_SEC = 3.0
_DLL_INIT_FAILED_CODES = frozenset({-1073741502, 3221225794})  # 0xC0000142
# Persisted resolution cache: keeps repeated CLI/MCP processes from paying the
# WSL cold-start probe cost on every invocation.
DISK_CACHE_TTL_SEC = 900.0

__all__ = [
    "ResolvedTool",
    "repo_root",
    "home_bin",
    "managed_venv_bin",
    "managed_bin_dirs",
    "extra_host_bin_dirs",
    "python_executable",
    "resolve_tool",
    "reset_cache",
    "wrapper_module_name",
    "wrapper_descriptor_path",
    "write_wrapper_launcher",
    "remove_wrapper_launcher",
    "enrich_child_env",
    "install_hint",
    "wsl_available",
    "wsl_distro",
    "wsl_which",
    "clear_wsl_cache",
]


@dataclass(frozen=True)
class ResolvedTool:
    """Result of resolving one logical tool name."""

    tool_id: str
    available: bool
    source: str = "none"          # managed-home | managed-venv | python-wrapper |
                                  # path | wsl | none
    detail: str = ""
    argv_prefix: tuple[str, ...] = ()
    binary_path: Optional[str] = None
    env_extra: dict[str, str] = field(default_factory=dict)

    def command(self, args: Iterable[str] = ()) -> list[str]:
        """Full argv for the resolved tool."""
        return [*self.argv_prefix, *[str(arg) for arg in args]]

    @property
    def location(self) -> str:
        return self.binary_path or " ".join(self.argv_prefix) or "unresolved"


# ════════════════════════════════════════════════════════════════════════
# Managed directories
# ════════════════════════════════════════════════════════════════════════

def repo_root() -> Path:
    """Repository root inferred from this module's location."""
    return Path(__file__).resolve().parents[2]


def _is_windows() -> bool:
    """Indirection helper so tests can simulate Windows without mutating os.name."""
    return os.name == "nt"


def home_bin() -> Path:
    override = os.environ.get(MANAGED_BIN_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".ai_osint_hub" / "bin").resolve()


def managed_venv_bin() -> Path:
    override = os.environ.get(MANAGED_VENV_ENV)
    if override:
        return Path(override).expanduser().resolve()
    venv = repo_root() / ".venv"
    return (venv / ("Scripts" if _is_windows() else "bin")).resolve()


def managed_venv_bin_dirs() -> list[Path]:
    """All managed venv script dirs (primary .venv then extra .venv314 etc.)."""
    directories: list[Path] = [managed_venv_bin()]
    for candidate in sorted(repo_root().glob(".venv*")):
        bin_dir = candidate / ("Scripts" if _is_windows() else "bin")
        if candidate.is_dir() and bin_dir not in directories:
            directories.append(bin_dir.resolve())
    return directories


def managed_bin_dirs() -> list[Path]:
    """Managed lookup directories in priority order."""
    directories = [home_bin(), *managed_venv_bin_dirs()]
    seen: set[str] = set()
    ordered: list[Path] = []
    for directory in directories:
        key = str(directory).lower() if _is_windows() else str(directory)
        if key not in seen:
            seen.add(key)
            ordered.append(directory)
    return ordered


def python_executable() -> str:
    return os.environ.get(PYTHON_ENV) or sys.executable


def ensure_managed_dirs() -> list[Path]:
    directories = managed_bin_dirs()
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
    return directories


# ════════════════════════════════════════════════════════════════════════
# Persisted resolution cache (WSL probes are expensive: cold-start per process)
# ════════════════════════════════════════════════════════════════════════

def _disk_cache_path() -> Path:
    return home_bin().parent / "toolchain_cache.json"


def load_disk_cache(*, force: bool = False) -> dict[str, Any]:
    path = _disk_cache_path()
    if force or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_disk_cache(data: dict[str, Any]) -> None:
    if os.environ.get("AI_OSINT_HUB_DISK_CACHE", "1").strip() == "0":
        return
    path = _disk_cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        pass


def _fresh(entry: Any) -> bool:
    return (isinstance(entry, dict)
            and (time.time() - float(entry.get("checked_at", 0) or 0))
            < DISK_CACHE_TTL_SEC)


# ════════════════════════════════════════════════════════════════════════
# Launcher descriptors (managed shell-free python wrappers)
# ════════════════════════════════════════════════════════════════════════

def wrapper_module_name(tool_id: str) -> str:
    return f"hub.toolchain.wrappers.{tool_id.strip().lower()}"


def wrapper_descriptor_path(tool_id: str) -> Path:
    return home_bin() / f"{tool_id.strip().lower()}.launcher.json"


def _read_launcher(tool_id: str) -> Optional[dict[str, Any]]:
    path = wrapper_descriptor_path(tool_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _module_importable(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def _resolve_launcher(tool_id: str) -> Optional[ResolvedTool]:
    data = _read_launcher(tool_id)
    if data is None:
        return None
    kind = str(data.get("kind", "python-module"))
    if kind != "python-module":
        return None
    module = str(data.get("module") or wrapper_module_name(tool_id))
    if not module.startswith("hub.toolchain.wrappers."):
        return ResolvedTool(tool_id=tool_id, available=False, source="managed-home",
                            detail=f"refused unsafe launcher module {module!r}")
    if not _module_importable(module):
        return ResolvedTool(tool_id=tool_id, available=False, source="managed-home",
                            detail=f"launcher points at missing module {module!r}")
    env_extra = {"PYTHONPATH": str(repo_root())}
    env_extra.update({str(k): str(v) for k, v in (data.get("env_extra") or {}).items()})
    return ResolvedTool(
        tool_id=tool_id,
        available=True,
        source="python-wrapper",
        detail=f"managed python wrapper module {module}",
        argv_prefix=(python_executable(), "-m", module),
        binary_path=str(wrapper_descriptor_path(tool_id)),
        env_extra=env_extra,
    )


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def write_wrapper_launcher(tool_id: str, *, module: Optional[str] = None,
                           smoke_args: Optional[list[str]] = None,
                           display_name: str = "") -> dict[str, str]:
    """Create the managed launcher descriptor + human-facing ``.cmd``/``.py`` files.

    The hardened runtime uses the shell-free JSON descriptor; the ``.cmd`` (Windows
    console) and ``.py`` files are provided for humans and other tools that expect
    an executable on disk. Nothing here performs network I/O.
    """
    tool_id = tool_id.strip().lower()
    module = module or wrapper_module_name(tool_id)
    directory = home_bin()
    directory.mkdir(parents=True, exist_ok=True)
    repo = str(repo_root())
    python = python_executable()

    py_path = directory / f"{tool_id}.py"
    _write_text(py_path, (
        '"""Managed launcher for the AI OSINT Hub tool wrapper (auto-generated)."""\n'
        "import os\nimport sys\n\n"
        f"REPO_ROOT = {repo!r}\n"
        "if REPO_ROOT not in sys.path:\n    sys.path.insert(0, REPO_ROOT)\n\n"
        f"from {module} import main\n\n"
        'if __name__ == "__main__":\n    raise SystemExit(main(sys.argv[1:]))\n'
    ))

    cmd_path = directory / f"{tool_id}.cmd"
    _write_text(cmd_path, (
        "@echo off\r\n"
        "setlocal\r\n"
        f"\"{python}\" \"%~dp0{tool_id}.py\" %*\r\n"
        "exit /b %ERRORLEVEL%\r\n"
    ))

    sh_path = directory / f"{tool_id}"
    _write_text(sh_path, (
        "#!/bin/sh\n"
        f'exec "{python}" "{directory / (tool_id + ".py")}" "$@"\n'
    ))
    try:
        os.chmod(sh_path, 0o755)
    except OSError:
        pass

    descriptor = {
        "tool_id": tool_id,
        "display_name": display_name or f"{tool_id} (managed wrapper)",
        "kind": "python-module",
        "module": module,
        "smoke_args": list(smoke_args or ["--help"]),
        "env_extra": {"PYTHONPATH": repo},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    descriptor_path = wrapper_descriptor_path(tool_id)
    _write_text(descriptor_path, json.dumps(descriptor, indent=2) + "\n")
    reset_cache()
    return {
        "tool_id": tool_id,
        "descriptor": str(descriptor_path),
        "python": str(py_path),
        "windows_cmd": str(cmd_path),
        "posix_script": str(sh_path),
    }


def remove_wrapper_launcher(tool_id: str) -> None:
    tool_id = tool_id.strip().lower()
    for path in (wrapper_descriptor_path(tool_id),
                 home_bin() / f"{tool_id}.py",
                 home_bin() / f"{tool_id}.cmd",
                 home_bin() / tool_id):
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass
    reset_cache()


# ════════════════════════════════════════════════════════════════════════
# WSL2 bridge
# ════════════════════════════════════════════════════════════════════════

_WSL_STATE: dict[str, Any] = {"checked": False, "exe": None, "distro": None,
                              "distros": [], "probe": None, "errors": {}}
_WSL_CACHE: dict[str, tuple[float, Optional[str]]] = {}


def _wsl_exe() -> Optional[str]:
    if not _is_windows() or os.environ.get(WSL_ENV, "").strip() == "0":
        return None
    return shutil.which("wsl.exe") or shutil.which("wsl")


def _decode_wsl_list(raw: bytes) -> list[str]:
    for encoding in ("utf-16-le", "utf-8", "mbcs"):
        try:
            text = raw.decode(encoding, errors="strict")
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    names: list[str] = []
    for line in text.replace("\x00", "").splitlines():
        candidate = line.strip().lstrip("*").strip()
        if not candidate or candidate.lower().startswith("name "):
            continue
        if candidate.lower() in {"docker-desktop", "docker-desktop-data"}:
            continue
        names.append(candidate)
    return names


def _detect_wsl() -> dict[str, Any]:
    if _WSL_STATE["checked"]:
        return _WSL_STATE
    _WSL_STATE["checked"] = True
    exe = _wsl_exe()
    _WSL_STATE["exe"] = exe
    if not exe:
        _WSL_STATE["probe"] = "wsl.exe not found or disabled"
        return _WSL_STATE
    cache = load_disk_cache()
    cached = cache.get("wsl") or {}
    requested = os.environ.get(WSL_DISTRO_ENV, "").strip()
    if _fresh(cached) and cached.get("distro"):
        distro = requested or str(cached.get("distro"))
        _WSL_STATE["distro"] = distro
        _WSL_STATE["distros"] = list(cached.get("distros") or [distro])
        _WSL_STATE["probe"] = f"wsl bridge ready (distro={distro}, cached)"
        return _WSL_STATE
    try:
        process = subprocess.run([exe, "-l", "-q"], capture_output=True,
                                 stdin=subprocess.DEVNULL,
                                 timeout=WSL_PROBE_TIMEOUT_SEC)
        distros = _decode_wsl_list(process.stdout or b"")
    except (OSError, subprocess.SubprocessError) as exc:
        distros = []
        _WSL_STATE["probe"] = f"wsl -l failed: {type(exc).__name__}: {exc}"
    distro: Optional[str] = None
    if requested and (not distros or requested in distros):
        distro = requested
    elif "Ubuntu" in distros:
        distro = "Ubuntu"
    elif distros:
        distro = distros[0]
    _WSL_STATE["distros"] = distros
    _WSL_STATE["distro"] = distro
    if distro and not _WSL_STATE.get("probe"):
        _WSL_STATE["probe"] = f"wsl bridge ready (distro={distro})"
    elif not distro:
        _WSL_STATE["probe"] = "no usable WSL distro found"
    if distro:
        cache["wsl"] = {"distro": distro, "distros": distros,
                        "checked_at": time.time()}
        save_disk_cache(cache)
    return _WSL_STATE


def wsl_available() -> bool:
    return bool(_detect_wsl().get("distro"))


def wsl_distro() -> Optional[str]:
    return _detect_wsl().get("distro")


def clear_wsl_cache() -> None:
    _WSL_STATE.update({"checked": False, "exe": None, "distro": None,
                       "distros": [], "probe": None, "errors": {}})
    _WSL_CACHE.clear()
    cache = load_disk_cache(force=True)
    cache.pop("wsl", None)
    cache.pop("wsl_which", None)
    save_disk_cache(cache)


def wsl_which(binary: str, *, force: bool = False) -> Optional[str]:
    """Return the Linux path of ``binary`` inside WSL, or None."""
    state = _detect_wsl()
    exe = state.get("exe")
    distro = state.get("distro")
    if not exe or not distro or not binary:
        return None
    key = f"{distro}|{binary}"
    cached = _WSL_CACHE.get(key)
    if cached and not force and (time.monotonic() - cached[0]) < CACHE_TTL_SEC:
        return cached[1]
    if not force:
        disk_cache = load_disk_cache()
        entry = (disk_cache.get("wsl_which") or {}).get(key)
        if _fresh(entry):
            result = entry.get("path") or None
            _WSL_CACHE[key] = (time.monotonic(), result)
            return result
    argv = [exe, "-d", str(distro), "--exec", "/usr/bin/which", binary]
    try:
        process = subprocess.run(argv, capture_output=True,
                                 stdin=subprocess.DEVNULL,
                                 timeout=WSL_PROBE_TIMEOUT_SEC)
        output = (process.stdout or b"").decode("utf-8", errors="replace").strip()
        path = next((line.strip() for line in output.splitlines() if line.strip()),
                    None)
        result = path if process.returncode == 0 and path else None
    except (OSError, subprocess.SubprocessError) as exc:
        _WSL_STATE["errors"][binary] = f"{type(exc).__name__}: {exc}"
        result = None
    _WSL_CACHE[key] = (time.monotonic(), result)
    disk_cache = load_disk_cache()
    disk_cache.setdefault("wsl_which", {})[key] = {
        "path": result, "checked_at": time.time(),
    }
    save_disk_cache(disk_cache)
    return result


def _resolve_wsl(tool_id: str, binary: str) -> Optional[ResolvedTool]:
    path = wsl_which(binary)
    if not path:
        return None
    distro = wsl_distro()
    exe = shutil.which("wsl.exe") or shutil.which("wsl")
    if not exe or not distro:
        return None
    return ResolvedTool(
        tool_id=tool_id,
        available=True,
        source="wsl",
        detail=f"WSL2 bridge ({distro}) at {path}",
        # Shell-free: wsl.exe --exec runs the Linux binary directly.
        argv_prefix=(exe, "-d", distro, "--exec", binary),
        binary_path=f"wsl://{distro}{path}",
    )


# ════════════════════════════════════════════════════════════════════════
# Native resolution & cross-platform hints
# ════════════════════════════════════════════════════════════════════════

def _creation_flags() -> dict[str, Any]:
    if _is_windows() and hasattr(subprocess, "CREATE_NO_WINDOW"):
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


def _windows_executable_names(binary: str) -> list[str]:
    if not _is_windows():
        return [binary]
    suffixes = [""] if Path(binary).suffix else [".exe", ".com", ".cmd", ".bat"]
    return [binary + suffix for suffix in suffixes]


def _probe_dll_init_failed(exe_path: Path) -> bool:
    """Return True if a Windows trampoline fails with STATUS_DLL_INIT_FAILED (0xC0000142)."""
    for flag in ("--help", "--version"):
        try:
            process = subprocess.run(
                [str(exe_path), flag],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=TRAMPOLINE_PROBE_TIMEOUT_SEC,
                **_creation_flags(),
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return process.returncode in _DLL_INIT_FAILED_CODES
    return False


def _find_console_script_entrypoint(site_packages: Path, script_name: str) -> Optional[str]:
    """Look up ``module:func`` for ``script_name`` in dist-info entry_points.txt."""
    if not site_packages.is_dir():
        return None
    target_key = script_name.strip().lower()
    for ep_file in sorted(site_packages.glob("*.dist-info/entry_points.txt")):
        try:
            lines = ep_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        in_console_scripts = False
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                in_console_scripts = line[1:-1].strip().lower() == "console_scripts"
                continue
            if not in_console_scripts or "=" not in line:
                continue
            name_part, _, spec_part = line.partition("=")
            if name_part.strip().lower() == target_key:
                spec = spec_part.split("[", 1)[0].strip()
                if re.fullmatch(r"[A-Za-z0-9_.]+:[A-Za-z0-9_.]+", spec):
                    return spec
    return None


def _resolve_venv_python_entrypoint(
    directory: Path,
    candidate: Path,
    source: str,
) -> Optional[ResolvedTool]:
    """Bypass a broken Windows uv-trampoline .exe using the venv's python.exe."""
    venv_python = directory / "python.exe"
    if not venv_python.is_file():
        return None
    stem = candidate.stem
    site_packages = directory.parent / "Lib" / "site-packages"
    entry_spec = _find_console_script_entrypoint(site_packages, stem)
    if entry_spec is not None:
        mod_name, _, func_path = entry_spec.partition(":")
        code = (
            "import functools, importlib, sys; "
            f"sys.argv[0] = {stem!r}; "
            f"fn = functools.reduce(getattr, {func_path.split('.')!r}, "
            f"importlib.import_module({mod_name!r})); "
            "sys.exit(fn())"
        )
        return ResolvedTool(
            tool_id="",
            available=True,
            source=source,
            detail=f"managed venv python entrypoint {entry_spec} (trampoline bypass)",
            argv_prefix=(str(venv_python), "-c", code),
            binary_path=str(candidate),
        )
    script_py = directory / f"{stem}-script.py"
    if script_py.is_file():
        return ResolvedTool(
            tool_id="",
            available=True,
            source=source,
            detail=f"managed venv script {script_py} (trampoline bypass)",
            argv_prefix=(str(venv_python), str(script_py)),
            binary_path=str(candidate),
        )
    main_py = site_packages / stem / "__main__.py"
    if main_py.is_file():
        return ResolvedTool(
            tool_id="",
            available=True,
            source=source,
            detail=f"managed venv module {stem} (trampoline bypass)",
            argv_prefix=(str(venv_python), "-m", stem),
            binary_path=str(candidate),
        )
    return None


def _find_in_managed(binary: str) -> Optional[ResolvedTool]:
    for index, directory in enumerate(managed_bin_dirs()):
        if not directory.exists():
            continue
        source = "managed-home" if index == 0 else "managed-venv"
        for candidate_name in _windows_executable_names(binary):
            candidate = directory / candidate_name
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() in {".cmd", ".bat"}:
                # Batch wrappers are shell-interpreted by Windows; the hardened
                # runtime does not execute them. A shell-free launcher descriptor
                # (created by --provision) takes priority over this path.
                continue
            if (
                _is_windows()
                and source == "managed-venv"
                and candidate.suffix.lower() == ".exe"
                and _probe_dll_init_failed(candidate)
            ):
                fallback = _resolve_venv_python_entrypoint(directory, candidate, source)
                if fallback is not None:
                    return fallback
            return ResolvedTool(
                tool_id="", available=True, source=source,
                detail=f"managed executable {candidate}",
                argv_prefix=(str(candidate),), binary_path=str(candidate),
            )
    return None


def extra_host_bin_dirs(platform_name: Optional[str] = None) -> list[Path]:
    """Extra non-default PATH directories checked on macOS and Linux."""
    plat = (platform_name or sys.platform).lower()
    if plat.startswith("win") or (platform_name is None and _is_windows()):
        return []
    if plat == "darwin":
        return [Path("/opt/homebrew/bin"), Path("/usr/local/bin")]
    if plat.startswith("linux"):
        return [Path.home() / ".local" / "bin", Path("/usr/local/bin"), Path("/snap/bin")]
    return []


def _resolve_host_path(tool_id: str, binary: str) -> Optional[ResolvedTool]:
    path = shutil.which(binary)
    if not path:
        for directory in extra_host_bin_dirs():
            candidate = directory / binary
            if candidate.is_file() and os.access(candidate, os.X_OK):
                path = str(candidate)
                break
    if not path:
        return None
    suffix = Path(path).suffix.lower()
    if suffix in {".cmd", ".bat", ".ps1"}:
        return ResolvedTool(
            tool_id=tool_id, available=False, source="path",
            detail=(f"found {path} but batch/PowerShell launchers are not executed "
                    f"by the hardened runtime; provide a native binary or a "
                    f"managed wrapper"),
            binary_path=path,
        )
    return ResolvedTool(
        tool_id=tool_id, available=True, source="path",
        detail=f"host PATH executable {path}",
        argv_prefix=(path,), binary_path=path,
    )


def _probe_windows_nmap(binary_path: str) -> bool:
    """Return True if native Windows nmap responds to --version within 2.0s."""
    try:
        process = subprocess.run(
            [binary_path, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=NMAP_PROBE_TIMEOUT_SEC,
            **_creation_flags(),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return process.returncode == 0


def _normalize_platform(platform_name: Optional[str] = None) -> str:
    raw = (platform_name or sys.platform).strip().lower()
    if raw in {"darwin", "mac", "macos", "osx"}:
        return "darwin"
    if raw.startswith("win") or raw == "nt":
        return "windows"
    return "linux"


_INSTALL_HINTS: dict[str, dict[str, str]] = {
    "holehe": {
        "darwin": "uv tool install holehe (or ai-osint-hub doctor --provision)",
        "linux": "uv tool install holehe (or ai-osint-hub doctor --provision)",
        "windows": "uv tool install holehe (or ai-osint-hub doctor --provision)",
    },
    "maigret": {
        "darwin": "uv tool install maigret (or ai-osint-hub doctor --provision)",
        "linux": "uv tool install maigret (or ai-osint-hub doctor --provision)",
        "windows": "uv tool install maigret (or ai-osint-hub doctor --provision)",
    },
    "h8mail": {
        "darwin": "uv tool install h8mail (or ai-osint-hub doctor --provision)",
        "linux": "uv tool install h8mail (or ai-osint-hub doctor --provision)",
        "windows": "uv tool install h8mail (or ai-osint-hub doctor --provision)",
    },
    "sherlock": {
        "darwin": "uv tool install sherlock-project (or brew install sherlock)",
        "linux": "uv tool install sherlock-project (or ai-osint-hub doctor --provision)",
        "windows": "uv tool install sherlock-project (or ai-osint-hub doctor --provision)",
    },
    "ghunt": {
        "darwin": "uv tool install ghunt (or ai-osint-hub doctor --provision)",
        "linux": "uv tool install ghunt (or ai-osint-hub doctor --provision)",
        "windows": "uv tool install ghunt (or ai-osint-hub doctor --provision)",
    },
    "theharvester": {
        "darwin": "ai-osint-hub doctor --provision (or brew install theharvester)",
        "linux": "ai-osint-hub doctor --provision (or sudo apt install -y theharvester)",
        "windows": "ai-osint-hub doctor --provision",
    },
    "phoneinfoga": {
        "darwin": "brew install phoneinfoga (or ai-osint-hub doctor --provision)",
        "linux": "ai-osint-hub doctor --provision",
        "windows": "ai-osint-hub doctor --provision",
    },
    "nmap": {
        "darwin": "brew install nmap",
        "linux": "sudo apt install -y nmap",
        "windows": "winget install Insecure.Nmap (or install in WSL: sudo apt install -y nmap)",
    },
    "amass": {
        "darwin": "brew install amass",
        "linux": "sudo snap install amass (or go install github.com/owasp-amass/amass/v4/...@master)",
        "windows": "scoop install amass (or go install github.com/owasp-amass/amass/v4/...@master)",
    },
    "gobuster": {
        "darwin": "brew install gobuster",
        "linux": "sudo apt install -y gobuster",
        "windows": "go install github.com/OJ/gobuster/v3@latest (or WSL: sudo apt install -y gobuster)",
    },
    "whatweb": {
        "darwin": "brew install whatweb",
        "linux": "sudo apt install -y whatweb",
        "windows": "ai-osint-hub doctor --provision (installs in WSL2: sudo apt install -y whatweb)",
    },
    "hashcat": {
        "darwin": "brew install hashcat",
        "linux": "sudo apt install -y hashcat",
        "windows": "ai-osint-hub doctor --provision (or winget install Hashcat.Hashcat)",
    },
    "hydra": {
        "darwin": "brew install hydra",
        "linux": "sudo apt install -y hydra",
        "windows": "ai-osint-hub doctor --provision (installs in WSL2: sudo apt install -y hydra)",
    },
}

_BUILTIN_TOOL_IDS = frozenset({
    "dns_lookup", "http_headers", "tls_cert", "snscrape", "photon_crawler",
    "github_osint", "virustotal_lookup", "shodan_lookup", "censys_lookup",
    "hunter_lookup", "gravatar_lookup", "pgp_keyserver", "rdap_lookup",
    "wayback_cdx", "darkweb_ahmia", "crtsh_lookup", "asn_bgp_lookup",
    "favicon_hash", "media_forensics",
})


def install_hint(tool_id: str, platform_name: Optional[str] = None) -> str:
    """Return a concise per-OS installation command for ``tool_id``."""
    key = tool_id.strip().lower()
    if key in _BUILTIN_TOOL_IDS:
        return "Built-in Python collector (included with ai-osint-hub)"
    plat = _normalize_platform(platform_name)
    per_os = _INSTALL_HINTS.get(key)
    if per_os and plat in per_os:
        return per_os[plat]
    if plat == "darwin":
        return f"brew install {key} (or ai-osint-hub doctor --provision)"
    if plat == "linux":
        return f"sudo apt install -y {key} (or ai-osint-hub doctor --provision)"
    return "ai-osint-hub doctor --provision"


# ════════════════════════════════════════════════════════════════════════
# Cache + public resolver
# ════════════════════════════════════════════════════════════════════════

_CACHE: dict[tuple[str, str, bool, bool], tuple[float, ResolvedTool]] = {}


def reset_cache() -> None:
    _CACHE.clear()


def _cache_key(tool_id: str, binary: str | None,
               allow_wrappers: bool, allow_wsl: bool):
    return (tool_id.strip().lower(), binary or "", allow_wrappers, allow_wsl)


def resolve_tool(tool_id: str, binary: Optional[str] = None, *,
                 force: bool = False,
                 allow_wrappers: bool = True,
                 allow_wsl: bool = True) -> ResolvedTool:
    """Resolve one logical tool to an executable argv prefix.

    ``allow_wrappers=False`` restricts resolution to *real* installed binaries
    (used by provisioning to decide whether a fallback wrapper is needed).
    ``allow_wsl=False`` disables the WSL2 bridge.
    """
    tool_key = tool_id.strip().lower()
    binary_key = (binary or tool_key).strip()
    key = _cache_key(tool_key, binary_key, allow_wrappers, allow_wsl)
    now = time.monotonic()
    if not force:
        cached = _CACHE.get(key)
        if cached and (now - cached[0]) < CACHE_TTL_SEC:
            return cached[1]

    resolved = _resolve_uncached(tool_key, binary_key,
                                 allow_wrappers=allow_wrappers,
                                 allow_wsl=allow_wsl)
    _CACHE[key] = (time.monotonic(), resolved)
    return resolved


def _resolve_uncached(tool_id: str, binary: str, *, allow_wrappers: bool,
                      allow_wsl: bool) -> ResolvedTool:
    if allow_wrappers:
        launcher = _resolve_launcher(tool_id)
        if launcher is not None:
            return launcher

    managed = _find_in_managed(binary)
    if managed is not None:
        if (
            _is_windows()
            and binary.strip().lower() in {"nmap", "nmap.exe"}
            and managed.binary_path
            and not _probe_windows_nmap(managed.binary_path)
        ):
            if allow_wsl:
                wsl = _resolve_wsl(tool_id, "nmap")
                if wsl is not None:
                    return wsl
        else:
            return ResolvedTool(
                tool_id=tool_id, available=managed.available, source=managed.source,
                detail=managed.detail, argv_prefix=managed.argv_prefix,
                binary_path=managed.binary_path, env_extra=dict(managed.env_extra),
            )

    host = _resolve_host_path(tool_id, binary)
    if host is not None:
        if (
            _is_windows()
            and binary.strip().lower() in {"nmap", "nmap.exe"}
            and host.available
            and host.binary_path
            and not _probe_windows_nmap(host.binary_path)
        ):
            if allow_wsl:
                wsl = _resolve_wsl(tool_id, "nmap")
                if wsl is not None:
                    return wsl
            return ResolvedTool(
                tool_id=tool_id, available=False, source="path",
                detail=(f"native Windows nmap at {host.binary_path} timed out or failed "
                        f"2.0s probe; WSL fallback unavailable"),
                binary_path=host.binary_path,
            )
        return host

    if allow_wsl:
        wsl = _resolve_wsl(tool_id, binary)
        if wsl is not None:
            return wsl

    if allow_wrappers:
        module = wrapper_module_name(tool_id)
        if _module_importable(module):
            return ResolvedTool(
                tool_id=tool_id, available=True, source="python-wrapper",
                detail=f"packaged python wrapper module {module}",
                argv_prefix=(python_executable(), "-m", module),
                binary_path=module,
                env_extra={"PYTHONPATH": str(repo_root())},
            )

    wsl_note = ""
    state = _detect_wsl()
    if state.get("errors", {}).get(binary):
        wsl_note = f"; WSL probe error: {state['errors'][binary]}"
    elif allow_wsl and not state.get("distro"):
        wsl_note = f"; WSL: {state.get('probe')}"
    return ResolvedTool(
        tool_id=tool_id, available=False, source="none",
        detail=f"binary {binary!r} not found in managed dirs, PATH"
               + (" or WSL" if allow_wsl else "") + wsl_note,
    )


# ════════════════════════════════════════════════════════════════════════
# Child environment
# ════════════════════════════════════════════════════════════════════════

def enrich_child_env(environment: dict[str, str],
                     resolved: Optional[ResolvedTool] = None) -> dict[str, str]:
    """Prepend managed bin dirs to a child PATH and merge trusted extra env."""
    enriched = dict(environment)
    managed = [str(directory) for directory in managed_bin_dirs() if directory.exists()]
    current_path = enriched.get("PATH") or os.environ.get("PATH", "")
    parts = managed + ([current_path] if current_path else [])
    if _is_windows():
        # WSL.exe needs SystemRoot; scrub_environment already allows it.
        enriched["PATH"] = os.pathsep.join(parts)
    else:
        enriched["PATH"] = os.pathsep.join(parts)
    if resolved is not None:
        for key, value in resolved.env_extra.items():
            enriched[str(key)] = str(value)
    return enriched


def locate_all(tool_ids_and_binaries: Iterable[tuple[str, str]], *,
               force: bool = False) -> dict[str, ResolvedTool]:
    return {tool_id: resolve_tool(tool_id, binary, force=force)
            for tool_id, binary in tool_ids_and_binaries}
