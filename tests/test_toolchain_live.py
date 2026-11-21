"""Opt-in live toolchain test — 28/28 doctor plus real tool executions.

Run with::

    AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_toolchain_live.py -q

All targets are benign/public: RFC-2606 example.com, a public well-known
username, and a reserved example phone number (+1 415 555 2671).
"""

import asyncio
import os

import pytest

from hub.models import ScopeConfig
from hub.toolchain.doctor import run_doctor
from hub.tools import capabilities, locator
from hub.tools.runtime import RunContext, ToolRuntime

pytestmark = pytest.mark.skipif(
    os.environ.get("AI_OSINT_HUB_LIVE") != "1",
    reason="live toolchain test; set AI_OSINT_HUB_LIVE=1 to enable",
)


def _run_tool(tool_id: str, params: dict, *, scope: ScopeConfig | None = None,
              timeout_override: int | None = None):
    async def main():
        runtime = ToolRuntime(max_concurrent_tools=4)
        try:
            context = RunContext(
                investigation_id="live-toolchain",
                entity_id="live-entity",
                scope=scope or ScopeConfig(),
                timeout_override_s=timeout_override,
            )
            return await runtime.run(capabilities.get_tool(tool_id), params, context)
        finally:
            await runtime.aclose()

    return asyncio.run(main())


def test_doctor_reports_all_17_tools_available():
    locator.reset_cache()
    result = run_doctor(provision=False, force=True)
    assert result["total"] == 28, result
    assert result["available"] == 28, result["missing"]
    assert result["healthy"] == 28, result["smoke_failed"]


@pytest.mark.parametrize("tool_id,params,scope", [
    ("holehe", {"email": "test@example.com"}, None),
    ("whatweb", {"target": "example.com"},
     ScopeConfig(allow_domains=["example.com"], allow_active_recon=True)),
    ("phoneinfoga", {"phone": "+14155552671"}, None),
])
def test_live_tool_execution(tool_id, params, scope):
    capability = capabilities.get_tool(tool_id)
    assert capability is not None
    result = _run_tool(tool_id, params, scope=scope, timeout_override=240)
    assert result.status.value == "SUCCESS", (result.status, result.error_code,
                                              result.error_message, result.stderr[-400:])
    assert result.stdout.strip()


def test_live_sherlock_execution():
    result = _run_tool("sherlock", {"username": "torvalds"}, timeout_override=420)
    assert result.status.value == "SUCCESS", (result.status, result.error_message,
                                              result.stderr[-400:])
    assert "http" in result.stdout.lower()
