"""Tests for the hardened async tool runtime.

No network is used. Real subprocesses are limited to ``sys.executable -c ...``
payloads; concurrency/rate-limit behaviour is proved with python-native builtin
collectors defined in this module.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time

import pytest

from hub.models import (
    EntityType,
    ErrorCode,
    ExecutionMode,
    ExecutionStatus,
    InvocationSpec,
    ParameterSpec,
    ScopeConfig,
    ToolCapability,
)
from hub.tools import capabilities
from hub.tools.base import ParseOutput
from hub.tools.builtin import BuiltinOutput
from hub.tools.runtime import RunContext, TokenBucket, ToolRuntime, scrub_environment
import hub.tools.runtime as runtime_module

PYTHON = sys.executable

# ════════════════════════════════════════════════════════════════════════
# Deterministic builtin collectors used by the concurrency tests
# ════════════════════════════════════════════════════════════════════════

_PEAK = {"active": 0, "peak": 0, "calls": 0}


def _reset_peak() -> None:
    _PEAK.update(active=0, peak=0, calls=0)


async def _slow_collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    _PEAK["active"] += 1
    _PEAK["calls"] += 1
    _PEAK["peak"] = max(_PEAK["peak"], _PEAK["active"])
    try:
        await asyncio.sleep(float(params.get("delay", 0.05)))
    finally:
        _PEAK["active"] -= 1
    return BuiltinOutput(stdout=json.dumps({"ok": True}), exit_code=0)


async def _error_collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    return BuiltinOutput(error_code=ErrorCode.SCOPE_BLOCKED, exit_code=-1,
                         error_message="blocked by test collector")


async def _nonzero_collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    return BuiltinOutput(stdout="{}", stderr="bad", exit_code=7)


async def _raising_collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    raise RuntimeError("collector exploded")


async def _timeout_raising_collect(params: dict, *, timeout_sec: int,
                                   scope: ScopeConfig) -> BuiltinOutput:
    raise asyncio.TimeoutError("collector timed out")


def _fake_parse(raw_stdout: str, target: str = "") -> ParseOutput:
    return ParseOutput()


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════

def _capability(
    tool_id: str = "test_python",
    *,
    binary: str = PYTHON,
    args: tuple[str, ...] = ("-c", "print('ok')"),
    timeout_sec: int = 30,
    rate_limit_rps: float = 100.0,
    mode: ExecutionMode = ExecutionMode.PASSIVE,
    parameters: dict[str, ParameterSpec] | None = None,
    kind: str = "binary",
    builtin_ref: str | None = None,
) -> ToolCapability:
    invocation = (
        InvocationSpec(kind="builtin", builtin_ref=builtin_ref)
        if kind == "builtin"
        else InvocationSpec(kind="binary", binary=binary, prefix_args=list(args))
    )
    return ToolCapability(
        tool_id=tool_id,
        display_name="instrumented test capability",
        description="deterministic test capability for the runtime suite",
        accepted_entity_types=[EntityType.DOMAIN],
        produced_entity_types=[EntityType.IP],
        execution_mode=mode,
        parameters=parameters or {},
        timeout_sec=timeout_sec,
        rate_limit_rps=rate_limit_rps,
        invocation=invocation,
        parser_ref="hub.tools.parsers.dns_lookup:parse",
    )


def _builtin_capability(tool_id: str, collector: str,
                        mode: ExecutionMode = ExecutionMode.PASSIVE) -> ToolCapability:
    parameters = {
        "target": ParameterSpec(name="target", type="string", required=True, format="hostname"),
        "delay": ParameterSpec(name="delay", type="number", required=False),
    }
    return _capability(tool_id=tool_id, kind="builtin",
                       builtin_ref=f"tests.test_runtime:{collector}",
                       mode=mode, parameters=parameters, rate_limit_rps=100.0)


def _context(**overrides) -> RunContext:
    values = {
        "investigation_id": "inv-runtime-test",
        "entity_id": "ent-runtime-test",
        "scope": ScopeConfig(),
    }
    values.update(overrides)
    return RunContext(**values)


def _run(coro):
    """pytest-asyncio is not installed; drive async tests with asyncio.run."""
    return asyncio.run(coro)


async def _run_once(capability: ToolCapability, params: dict | None = None,
                    context: RunContext | None = None,
                    **runtime_kwargs) -> object:
    runtime = ToolRuntime(**runtime_kwargs)
    try:
        return await runtime.run(capability, params or {}, context or _context())
    finally:
        await runtime.aclose()


# ════════════════════════════════════════════════════════════════════════
# Failure classification
# ════════════════════════════════════════════════════════════════════════

def test_missing_binary_is_classified_without_spawning(monkeypatch):
    spawn_attempts: list[tuple] = []

    async def _never_spawn(*args, **kwargs):
        spawn_attempts.append((args, kwargs))
        raise AssertionError("runtime must not spawn a missing binary")

    monkeypatch.setattr(runtime_module, "_spawn_process", _never_spawn)
    capability = _capability(binary="definitely-not-a-real-binary-xyz", args=())
    result = _run(_run_once(capability))

    assert spawn_attempts == []
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.MISSING_BINARY
    assert "not found" in result.error_message
    assert result.exit_code == -1
    assert result.params_hash


def test_python_child_success(tmp_path):
    capability = _capability(args=("-c", "print('hello-runtime')"))
    context = _context(scratch_dir=tmp_path)
    result = _run(_run_once(capability, {}, context))

    assert result.status == ExecutionStatus.SUCCESS
    assert result.error_code is None
    assert result.exit_code == 0
    assert "hello-runtime" in result.stdout
    assert result.duration_ms >= 0
    assert result.started_at
    assert result.tool_id == "test_python"
    assert result.entity_id == "ent-runtime-test"
    # Isolated scratch directory was cleaned up afterwards.
    assert list(tmp_path.iterdir()) == []


def test_nonzero_exit_is_classified():
    capability = _capability(
        args=("-c", "import sys; sys.stderr.write('boom-exit'); sys.exit(3)")
    )
    result = _run(_run_once(capability))

    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.NONZERO_EXIT
    assert result.exit_code == 3
    assert "boom-exit" in result.stderr


def test_timeout_kills_process_tree():
    capability = _capability(args=("-c", "import time; time.sleep(30)"), timeout_sec=30)
    context = _context(timeout_override_s=1)  # override wins over capability timeout
    started = time.monotonic()
    result = _run(_run_once(capability, {}, context))
    elapsed = time.monotonic() - started

    assert result.status == ExecutionStatus.TIMEOUT
    assert result.error_code == ErrorCode.TIMEOUT
    assert elapsed < 10.0, f"timeout did not kill the child quickly (took {elapsed:.1f}s)"


def test_builtin_collector_timeout_is_mapped():
    capability = _builtin_capability("test_builtin_timeout", "_timeout_raising_collect")
    result = _run(_run_once(capability, {"target": "example.com"}))

    assert result.status == ExecutionStatus.TIMEOUT
    assert result.error_code == ErrorCode.TIMEOUT


def test_builtin_collector_error_codes_are_mapped():
    capability = _builtin_capability("test_builtin_error", "_error_collect")
    result = _run(_run_once(capability, {"target": "example.com"}))
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.SCOPE_BLOCKED

    capability = _builtin_capability("test_builtin_nonzero", "_nonzero_collect")
    result = _run(_run_once(capability, {"target": "example.com"}))
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.NONZERO_EXIT
    assert result.exit_code == 7

    capability = _builtin_capability("test_builtin_raises", "_raising_collect")
    result = _run(_run_once(capability, {"target": "example.com"}))
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.SPAWN_ERROR
    assert "collector exploded" in result.error_message


def test_builtin_collector_success():
    capability = _builtin_capability("test_builtin_ok", "_slow_collect")
    result = _run(_run_once(capability, {"target": "example.com", "delay": 0.0}))
    assert result.status == ExecutionStatus.SUCCESS
    assert json.loads(result.stdout) == {"ok": True}


def test_missing_builtin_collector_is_classified_without_dispatch(monkeypatch):
    capability = _capability(kind="builtin",
                             builtin_ref="hub.tools.builtin.does_not_exist:collect")
    result = _run(_run_once(capability, {}))
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.MISSING_BINARY
    assert "collector unavailable" in result.error_message


def test_invalid_parameters_block_spawn(monkeypatch):
    async def _never_spawn(*args, **kwargs):
        raise AssertionError("must not spawn with invalid parameters")

    monkeypatch.setattr(runtime_module, "_spawn_process", _never_spawn)
    parameters = {"target": ParameterSpec(name="target", type="string", required=True,
                                          format="hostname")}
    capability = _capability(parameters=parameters)
    result = _run(_run_once(capability, {}))
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.SPAWN_ERROR
    assert "missing required parameter" in result.error_message


def test_intrusive_capability_is_policy_blocked_without_spawning(monkeypatch):
    spawn_attempts: list[tuple] = []

    async def _never_spawn(*args, **kwargs):
        spawn_attempts.append((args, kwargs))
        raise AssertionError("intrusive capability must never spawn")

    monkeypatch.setattr(runtime_module, "_spawn_process", _never_spawn)
    hydra = capabilities.get_tool("hydra")
    assert hydra is not None
    result = _run(_run_once(hydra, {"service": "ssh", "username": "u", "password": "p"}))

    assert spawn_attempts == []
    assert result.status == ExecutionStatus.ERROR
    assert result.error_code == ErrorCode.INTRUSIVE_BLOCKED


# ════════════════════════════════════════════════════════════════════════
# Environment scrubbing
# ════════════════════════════════════════════════════════════════════════

def test_environment_is_scrubbed(monkeypatch):
    monkeypatch.setenv("AI_OSINT_HUB_TEST_SECRET_TOKEN", "super-secret-value-123")
    capability = _capability(
        args=("-c", "import json, os; print(json.dumps(dict(os.environ)))")
    )
    result = _run(_run_once(capability))
    assert result.status == ExecutionStatus.SUCCESS

    child_env = json.loads(result.stdout)
    upper_keys = {key.upper() for key in child_env}
    assert "AI_OSINT_HUB_TEST_SECRET_TOKEN" not in upper_keys
    assert "super-secret-value-123" not in result.stdout
    assert "PATH" in upper_keys


def test_scrub_environment_allowlist_and_extra(monkeypatch):
    monkeypatch.setenv("AI_OSINT_HUB_TEST_SECRET_TOKEN", "super-secret-value-123")
    environment = scrub_environment({"EXPLICIT_EXTRA": "yes"})
    upper_keys = {key.upper() for key in environment}
    assert "AI_OSINT_HUB_TEST_SECRET_TOKEN" not in upper_keys
    assert "PATH" in upper_keys
    assert environment["EXPLICIT_EXTRA"] == "yes"


# ════════════════════════════════════════════════════════════════════════
# Concurrency + rate limiting
# ════════════════════════════════════════════════════════════════════════

def test_overall_semaphore_bounds_peak_concurrency():
    _reset_peak()

    async def main():
        runtime = ToolRuntime(max_concurrent_tools=3)
        try:
            capabilities_list = [
                _builtin_capability(f"test_conc_{index}", "_slow_collect")
                for index in range(6)
            ]
            context = _context(scope=ScopeConfig())
            results = await asyncio.gather(*[
                runtime.run(capability, {"target": f"host{index}.example.com", "delay": 0.08},
                            context)
                for index, capability in enumerate(capabilities_list)
            ])
        finally:
            await runtime.aclose()
        return results

    results = _run(main())
    assert all(result.status == ExecutionStatus.SUCCESS for result in results)
    assert _PEAK["calls"] == 6
    assert _PEAK["peak"] <= 3, f"peak concurrency {_PEAK['peak']} exceeded max_concurrent_tools=3"
    assert _PEAK["peak"] >= 2


def test_heavy_semaphore_limits_active_recon():
    _reset_peak()

    async def main():
        runtime = ToolRuntime(max_concurrent_tools=8)  # heavy slots = 8 // 4 = 2
        try:
            capabilities_list = [
                _builtin_capability(f"test_heavy_{index}", "_slow_collect",
                                    mode=ExecutionMode.ACTIVE_RECON)
                for index in range(6)
            ]
            context = _context(scope=ScopeConfig(allow_active_recon=True))
            results = await asyncio.gather(*[
                runtime.run(capability, {"target": f"host{index}.example.com", "delay": 0.08},
                            context)
                for index, capability in enumerate(capabilities_list)
            ])
        finally:
            await runtime.aclose()
        return results

    results = _run(main())
    assert all(result.status == ExecutionStatus.SUCCESS for result in results)
    assert _PEAK["calls"] == 6
    assert _PEAK["peak"] <= 2, f"heavy peak {_PEAK['peak']} exceeded heavy limit 2"
    assert _PEAK["peak"] == 2


def test_context_concurrency_cap_tightens_overall_limit():
    _reset_peak()

    async def main():
        runtime = ToolRuntime(max_concurrent_tools=8)
        try:
            capabilities_list = [
                _builtin_capability(f"test_ctx_{index}", "_slow_collect")
                for index in range(6)
            ]
            # RunContext asks for a tighter per-investigation bound than the runtime.
            context = _context(scope=ScopeConfig(), max_concurrent_tools=2)
            results = await asyncio.gather(*[
                runtime.run(capability, {"target": f"host{index}.example.com", "delay": 0.08},
                            context)
                for index, capability in enumerate(capabilities_list)
            ])
        finally:
            await runtime.aclose()
        return results

    results = _run(main())
    assert all(result.status == ExecutionStatus.SUCCESS for result in results)
    assert _PEAK["peak"] <= 2, f"context peak {_PEAK['peak']} exceeded context cap 2"
    assert _PEAK["peak"] == 2


def test_token_bucket_spaces_acquisitions():
    async def main():
        bucket = TokenBucket(rate_per_sec=10.0, burst=1.0)
        await bucket.acquire()  # first token available immediately
        started = time.monotonic()
        await bucket.acquire()
        return time.monotonic() - started

    elapsed = _run(main())
    assert elapsed >= 0.05, f"second acquisition was not rate limited ({elapsed:.3f}s)"
    assert elapsed < 1.0


def test_token_bucket_burst_allows_immediate_acquisitions():
    async def main():
        bucket = TokenBucket(rate_per_sec=10.0, burst=2.0)
        started = time.monotonic()
        await bucket.acquire()
        await bucket.acquire()
        return time.monotonic() - started

    elapsed = _run(main())
    assert elapsed < 0.1


def test_token_bucket_rejects_invalid_rate():
    with pytest.raises(ValueError):
        TokenBucket(rate_per_sec=0.0)


def test_runtime_rejects_invalid_concurrency():
    with pytest.raises(ValueError):
        ToolRuntime(max_concurrent_tools=0)
