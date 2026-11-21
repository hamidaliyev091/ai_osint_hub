"""Hardened async tool runtime — the only path from a plan to an actual tool run.

Guarantees enforced here (all in deterministic Python, never by the LLM):

  * **Policy gate first** — :func:`hub.security.policy.check_capability` runs
    before any binary is spawned or collector imported.
  * **Availability probe** — a missing binary / unimportable collector becomes
    ``MISSING_BINARY`` without spawning anything.
  * **No shell** — argument vectors built by
    :func:`hub.tools.capabilities.build_argv` are executed with
    ``asyncio.create_subprocess_exec`` (shell=False by construction).
  * **Scrubbed environment** — children only see a minimal allowlist of
    non-secret environment variables.
  * **Isolated working directory** — every run gets a fresh temporary scratch
    directory, removed afterwards.
  * **Bounded execution** — timeout enforced; on expiry the whole process tree
    is killed (``taskkill /F /T`` on Windows, ``killpg(SIGKILL)`` elsewhere).
  * **Rate limiting + concurrency** — per-tool token bucket plus a global
    semaphore and a smaller "heavy local" semaphore for active/intrusive tools.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Optional

from hub.models import (
    ErrorCode,
    ExecutionMode,
    ExecutionStatus,
    ScopeConfig,
    ToolCapability,
    ToolRunResult,
    param_hash,
    utc_now,
)
from hub.security import policy
from hub.tools import capabilities, locator
from hub.tools.builtin import BuiltinOutput

__all__ = ["RunContext", "ToolRuntime", "scrub_environment", "TokenBucket"]

#: Environment variables a child process may inherit (case-insensitive).
_ENV_ALLOWLIST = frozenset({
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
    "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "PROGRAMDATA", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "OS",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    # Unicode safety for Python-based OSINT CLIs on Windows (ghunt/rich etc.).
    "PYTHONIOENCODING", "PYTHONUTF8", "PYTHONUNBUFFERED", "NO_COLOR", "TERM",
})
#: Grace period for a collector's internal timeout before the runtime hard-cancels.
_BUILTIN_GRACE_S = 5.0
#: How long to wait for a killed process tree to be reaped.
_KILL_GRACE_S = 10.0


def scrub_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a child environment containing only non-secret allowlisted vars.

    API keys, tokens, investigation state and everything else in the parent
    environment are dropped. ``extra`` is caller-trusted (never derived from
    untrusted OSINT data) and is merged last.
    """
    environment: dict[str, str] = {}
    for key, value in os.environ.items():
        if key.upper() in _ENV_ALLOWLIST:
            environment[key] = value
    for key, value in (extra or {}).items():
        environment[str(key)] = str(value)
    return environment


class TokenBucket:
    """Async token bucket used for per-tool rate limiting.

    ``burst`` caps how many immediate acquisitions are possible; the long-run
    rate is ``rate_per_sec``. Waiting is serialized by an internal lock so
    concurrent callers are spaced deterministically.
    """

    def __init__(self, rate_per_sec: float, burst: float = 1.0) -> None:
        rate = float(rate_per_sec)
        if rate <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self.rate_per_sec = rate
        self.burst = max(1.0, float(burst))
        self._tokens = self.burst
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until one token is available, then consume it."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = max(0.0, now - self._last_refill)
                self._last_refill = now
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate_per_sec)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens) / self.rate_per_sec)


@dataclass(frozen=True)
class RunContext:
    """Per-run execution context assembled by the investigation engine."""

    investigation_id: str
    entity_id: str
    scope: ScopeConfig
    allow_authorized_tools: bool = False
    allow_intrusive: bool = False
    max_concurrent_tools: int = 8
    timeout_override_s: int | None = None
    scratch_dir: str | os.PathLike | None = None


@dataclass
class _Outcome:
    """Internal normalized outcome of one execution attempt."""

    status: ExecutionStatus
    error_code: Optional[ErrorCode] = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error_message: str = ""


def _decode(data: Any) -> str:
    if not data:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def _process_flags() -> dict[str, Any]:
    """Platform flags that keep the child in its own group and windowless."""
    if os.name == "nt":
        return {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW,
        }
    return {"start_new_session": True}


async def _spawn_process(argv: list[str], *, cwd: str, env: dict[str, str],
                         flags: dict[str, Any]):
    """Spawn one child process (shell=False by construction).

    Kept as a module-level function so tests can prove *no spawn attempt* happens
    for policy/availability failures.
    """
    return await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
        **flags,
    )


def _load_builtin_collector(builtin_ref: Optional[str]):
    """Import and return the ``module:function`` collector referenced by a manifest."""
    if not builtin_ref or ":" not in builtin_ref:
        raise ImportError(f"invalid builtin reference: {builtin_ref!r}")
    module_path, _, function_name = builtin_ref.partition(":")
    module = importlib.import_module(module_path)
    collector = getattr(module, function_name)
    if not callable(collector):
        raise TypeError(f"builtin reference is not callable: {builtin_ref!r}")
    return collector


class ToolRuntime:
    """Async, policy-gated, resource-bounded executor for OSINT capabilities.

    Instances are event-loop affine: construct one inside the running loop (or
    use one runtime per ``asyncio.run`` call).
    """

    def __init__(
        self,
        *,
        max_concurrent_tools: int = 8,
        scratch_root: str | os.PathLike | None = None,
        env_extra: dict[str, str] | None = None,
    ) -> None:
        if max_concurrent_tools < 1:
            raise ValueError("max_concurrent_tools must be >= 1")
        self.max_concurrent_tools = int(max_concurrent_tools)
        self.heavy_concurrency = max(1, self.max_concurrent_tools // 4)
        self._slots = asyncio.Semaphore(self.max_concurrent_tools)
        self._heavy_slots = asyncio.Semaphore(self.heavy_concurrency)
        self._scratch_root = (os.fspath(scratch_root)
                              if scratch_root is not None else None)
        self._env_extra = {str(key): str(value) for key, value in (env_extra or {}).items()}
        self._buckets: dict[str, TokenBucket] = {}
        self._context_slots: dict[str, tuple[int, asyncio.Semaphore]] = {}
        self._temp_dirs: set[str] = set()
        self._closed = False

    # ── public API ────────────────────────────────────────────────────
    async def run(self, capability: ToolCapability, params: dict,
                  context: RunContext) -> ToolRunResult:
        """Execute one capability invocation under the full security policy."""
        started_at = utc_now()
        start_monotonic = time.monotonic()
        safe_params: dict[str, Any] = dict(params) if isinstance(params, dict) else {}
        try:
            # Load env/vault secrets and register them with the redaction filter
            # before any raw output, error or artifact can be produced.
            from hub.credentials import ensure_credentials

            ensure_credentials()
        except Exception:  # noqa: BLE001 - credential loading must never break runtime
            pass

        def finish(outcome: _Outcome) -> ToolRunResult:
            from hub.security.redaction import redact, redact_obj

            return ToolRunResult(
                tool_id=capability.tool_id,
                entity_id=context.entity_id,
                params=redact_obj(safe_params),
                status=outcome.status,
                error_code=outcome.error_code,
                stdout=redact(outcome.stdout),
                stderr=redact(outcome.stderr),
                exit_code=outcome.exit_code,
                duration_ms=int((time.monotonic() - start_monotonic) * 1000),
                error_message=redact(outcome.error_message),
                started_at=started_at,
                params_hash=param_hash(capability.tool_id, safe_params),
            )

        if self._closed:
            return finish(_Outcome(ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR,
                                   error_message="runtime is closed"))

        # 1. Deterministic policy gate — before spawn and before health probing.
        decision = policy.check_capability(
            capability,
            safe_params,
            context.scope,
            allow_authorized_tools=True if context.allow_authorized_tools else None,
            allow_intrusive=True if context.allow_intrusive else None,
        )
        if not decision.allowed:
            return finish(_Outcome(
                ExecutionStatus.ERROR,
                decision.error_code or ErrorCode.SCOPE_BLOCKED,
                error_message=decision.reason,
            ))

        # 2. Parameter validation (unknown extra keys are tolerated, invalid known ones are not).
        param_errors = [
            error for error in capabilities.validate_params(capability, safe_params)
            if not error.startswith("unknown parameters")
        ]
        if param_errors:
            return finish(_Outcome(
                ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR,
                error_message="invalid parameters: " + "; ".join(param_errors),
            ))

        # 3. Availability probe — never spawn a binary that does not exist.
        available, detail = self._availability(capability)
        if not available:
            return finish(_Outcome(ExecutionStatus.ERROR, ErrorCode.MISSING_BINARY,
                                   error_message=detail))

        # 3b. Credential gate — keyless/optional tools are skipped cleanly instead
        # of wasting budget on unauthenticated runs. github stays KEYLESS_LIMITED.
        try:
            auth_ready = capabilities.capability_auth_ready(capability)
            auth_status, auth_detail = capabilities.capability_auth(capability)
        except Exception:  # noqa: BLE001
            auth_ready, auth_status, auth_detail = True, "NOT_REQUIRED", ""
        if not auth_ready:
            return finish(_Outcome(
                ExecutionStatus.ERROR, ErrorCode.AUTHORIZATION_REQUIRED,
                error_message=(f"{auth_status}: {auth_detail} — configure credentials "
                               f"in the Web UI API Keys drawer or 'python -m hub.cli auth set'"),
            ))

        timeout_s = (context.timeout_override_s
                     if context.timeout_override_s is not None
                     else capability.timeout_sec)
        try:
            timeout_s = max(1, int(timeout_s))
        except (TypeError, ValueError):
            timeout_s = capability.timeout_sec

        # 4. Per-tool rate limit, then concurrency slots (heavy local tools last).
        await self._bucket_for(capability).acquire()
        heavy = capability.execution_mode in {
            ExecutionMode.ACTIVE_RECON, ExecutionMode.INTRUSIVE_BLOCKED,
        }
        context_slots = self._context_semaphore(context)
        try:
            if heavy:
                async with self._heavy_slots:
                    async with self._slots:
                        outcome = await self._execute_with_context_slot(
                            context_slots, capability, safe_params, context, timeout_s
                        )
            else:
                async with self._slots:
                    outcome = await self._execute_with_context_slot(
                        context_slots, capability, safe_params, context, timeout_s
                    )
        except Exception as exc:  # noqa: BLE001 - runtime must always return a result
            outcome = _Outcome(
                ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR,
                error_message=f"runtime error: {type(exc).__name__}: {exc}",
            )
        return finish(outcome)

    async def aclose(self) -> None:
        """Release runtime resources and remove any leftover scratch directories."""
        self._closed = True
        for path in list(self._temp_dirs):
            shutil.rmtree(path, ignore_errors=True)
        self._temp_dirs.clear()
        self._buckets.clear()
        self._context_slots.clear()

    # ── internals ─────────────────────────────────────────────────────
    def _context_semaphore(self, context: RunContext) -> Optional[asyncio.Semaphore]:
        """Per-investigation concurrency cap when the context asks for a tighter one."""
        try:
            limit = max(1, int(context.max_concurrent_tools))
        except (TypeError, ValueError):
            limit = self.max_concurrent_tools
        limit = min(limit, self.max_concurrent_tools)
        if limit >= self.max_concurrent_tools:
            return None  # global semaphore already enforces the bound
        key = context.investigation_id or "_default"
        cached = self._context_slots.get(key)
        if cached is None or cached[0] != limit:
            cached = (limit, asyncio.Semaphore(limit))
            self._context_slots[key] = cached
        return cached[1]

    async def _execute_with_context_slot(self, context_slots: Optional[asyncio.Semaphore],
                                         capability: ToolCapability, params: dict[str, Any],
                                         context: RunContext, timeout_s: int) -> _Outcome:
        if context_slots is None:
            return await self._execute(capability, params, context, timeout_s)
        async with context_slots:
            return await self._execute(capability, params, context, timeout_s)

    def _bucket_for(self, capability: ToolCapability) -> TokenBucket:
        bucket = self._buckets.get(capability.tool_id)
        if bucket is None:
            bucket = TokenBucket(capability.rate_limit_rps)
            self._buckets[capability.tool_id] = bucket
        return bucket

    def _availability(self, capability: ToolCapability) -> tuple[bool, str]:
        invocation = capability.invocation
        if invocation.kind == "builtin":
            try:
                _load_builtin_collector(invocation.builtin_ref)
            except Exception as exc:  # noqa: BLE001
                return False, f"collector unavailable: {type(exc).__name__}: {exc}"
            return True, "python-native collector importable"
        binary = invocation.binary or ""
        resolved = locator.resolve_tool(capability.tool_id, binary)
        return bool(resolved.available), resolved.detail

    async def _execute(self, capability: ToolCapability, params: dict[str, Any],
                       context: RunContext, timeout_s: int) -> _Outcome:
        if capability.invocation.kind == "builtin":
            return await self._run_builtin(capability, params, context, timeout_s)
        return await self._run_binary(capability, params, context, timeout_s)

    async def _run_builtin(self, capability: ToolCapability, params: dict[str, Any],
                           context: RunContext, timeout_s: int) -> _Outcome:
        try:
            collector = _load_builtin_collector(capability.invocation.builtin_ref)
        except Exception as exc:  # noqa: BLE001
            return _Outcome(ExecutionStatus.ERROR, ErrorCode.MISSING_BINARY,
                            error_message=f"collector import failed: {type(exc).__name__}: {exc}")
        try:
            output = await asyncio.wait_for(
                collector(params, timeout_sec=timeout_s, scope=context.scope),
                timeout=timeout_s + _BUILTIN_GRACE_S,
            )
        except (asyncio.TimeoutError, TimeoutError):
            message = f"collector timed out after {timeout_s}s: {capability.tool_id}"
            return _Outcome(ExecutionStatus.TIMEOUT, ErrorCode.TIMEOUT, error_message=message)
        except Exception as exc:  # noqa: BLE001 - a collector must never crash a run
            message = f"collector failed: {type(exc).__name__}: {exc}"
            return _Outcome(ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR, error_message=message)

        if not isinstance(output, BuiltinOutput):
            return _Outcome(
                ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR,
                error_message=f"collector returned unsupported type {type(output).__name__}",
            )
        if output.error_code is not None:
            status = (ExecutionStatus.TIMEOUT
                      if output.error_code == ErrorCode.TIMEOUT
                      else ExecutionStatus.ERROR)
            return _Outcome(status, output.error_code, output.stdout, output.stderr,
                            output.exit_code,
                            output.error_message or output.stderr or str(output.error_code.value))
        if output.exit_code != 0:
            return _Outcome(
                ExecutionStatus.ERROR, ErrorCode.NONZERO_EXIT,
                output.stdout, output.stderr, output.exit_code,
                output.error_message or f"collector exit code {output.exit_code}",
            )
        return _Outcome(ExecutionStatus.SUCCESS, None, output.stdout, output.stderr,
                        output.exit_code, output.error_message)

    async def _run_binary(self, capability: ToolCapability, params: dict[str, Any],
                          context: RunContext, timeout_s: int) -> _Outcome:
        base = (os.fspath(context.scratch_dir) if context.scratch_dir is not None
                else self._scratch_root)
        scratch_dir: str
        if base:
            try:
                os.makedirs(base, exist_ok=True)
            except OSError as exc:
                return _Outcome(ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR,
                                error_message=f"cannot create scratch root {base!r}: {exc}")
            scratch_dir = tempfile.mkdtemp(prefix=f"{capability.tool_id}_", dir=base)
        else:
            scratch_dir = tempfile.mkdtemp(prefix=f"ai_osint_hub_{capability.tool_id}_")
        self._temp_dirs.add(scratch_dir)
        try:
            try:
                logical_argv = capabilities.build_argv(capability, params)
            except Exception as exc:  # noqa: BLE001
                return _Outcome(ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR,
                                error_message=f"failed to build argv: {type(exc).__name__}: {exc}")
            # Resolve via managed bins -> PATH -> WSL2 bridge -> managed wrapper.
            resolved = locator.resolve_tool(capability.tool_id, logical_argv[0])
            if not resolved.available:
                return _Outcome(ExecutionStatus.ERROR, ErrorCode.MISSING_BINARY,
                                error_message=f"tool unavailable: {resolved.detail}")
            argv = resolved.command(logical_argv[1:])
            environment = locator.enrich_child_env(
                scrub_environment(self._env_extra), resolved)
            environment.update(capabilities.invocation_env(capability))
            try:
                process = await _spawn_process(
                    argv, cwd=scratch_dir, env=environment, flags=_process_flags()
                )
            except FileNotFoundError as exc:
                return _Outcome(ExecutionStatus.ERROR, ErrorCode.MISSING_BINARY,
                                error_message=f"binary not found: {exc}")
            except Exception as exc:  # noqa: BLE001
                return _Outcome(ExecutionStatus.ERROR, ErrorCode.SPAWN_ERROR,
                                error_message=f"failed to spawn: {type(exc).__name__}: {exc}")

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=timeout_s
                )
            except (asyncio.TimeoutError, TimeoutError):
                await self._kill_process_tree(process)
                try:
                    await asyncio.wait_for(process.communicate(), timeout=_KILL_GRACE_S)
                except Exception:  # noqa: BLE001 - best effort reaping
                    pass
                exit_code = process.returncode if process.returncode is not None else -1
                message = f"{capability.tool_id} timed out after {timeout_s}s; process tree killed"
                return _Outcome(ExecutionStatus.TIMEOUT, ErrorCode.TIMEOUT,
                                exit_code=exit_code, error_message=message)

            stdout = _decode(stdout_bytes)
            stderr = _decode(stderr_bytes)
            exit_code = process.returncode if process.returncode is not None else -1
            if exit_code != 0:
                if (capability.invocation.tolerate_nonzero_with_stdout
                        and stdout.strip()):
                    # Tool completed its work but exited non-zero on warnings
                    # (e.g. maigret site errors / console-encoding warnings).
                    return _Outcome(ExecutionStatus.SUCCESS, None, stdout,
                                    stderr, exit_code, "")
                return _Outcome(ExecutionStatus.ERROR, ErrorCode.NONZERO_EXIT,
                                stdout, stderr, exit_code,
                                f"non-zero exit code {exit_code}")
            return _Outcome(ExecutionStatus.SUCCESS, None, stdout, stderr, exit_code, "")
        finally:
            self._temp_dirs.discard(scratch_dir)
            shutil.rmtree(scratch_dir, ignore_errors=True)

    async def _kill_process_tree(self, process) -> None:
        """Hard-kill a child process and its whole tree."""
        if process.returncode is not None:
            return
        if os.name == "nt":  # pragma: no cover - platform specific
            try:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill", "/F", "/T", "/PID", str(process.pid),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=scrub_environment(self._env_extra),
                )
                await asyncio.wait_for(killer.wait(), timeout=_KILL_GRACE_S)
                return
            except Exception:  # noqa: BLE001 - fall back to direct kill
                pass
        else:  # pragma: no cover - platform specific
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                return
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            process.kill()
        except ProcessLookupError:
            pass
