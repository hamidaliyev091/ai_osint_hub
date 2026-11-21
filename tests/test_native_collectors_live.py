"""Opt-in live smoke for Phase-7 native collectors + fixed maigret.

Run with::

    AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_native_collectors_live.py -q

Targets are benign/public endpoints (example.com, public GitHub profile).
"""

import asyncio
import os

import pytest

from hub.models import ScopeConfig
from hub.tools import capabilities
from hub.tools.runtime import RunContext, ToolRuntime

pytestmark = pytest.mark.skipif(
    os.environ.get("AI_OSINT_HUB_LIVE") != "1",
    reason="live native-collector test; set AI_OSINT_HUB_LIVE=1 to enable",
)


def _run_tool(tool_id: str, params: dict, *, timeout_override: int = 180,
              scope: ScopeConfig | None = None):
    async def main():
        runtime = ToolRuntime(max_concurrent_tools=3)
        try:
            context = RunContext(
                investigation_id="live-native-collectors",
                entity_id="live-entity",
                scope=scope or ScopeConfig(),
                timeout_override_s=timeout_override,
            )
            return await runtime.run(capabilities.get_tool(tool_id), params, context)
        finally:
            await runtime.aclose()

    return asyncio.run(main())


def _assert_success(result, tool_id: str):
    assert result.status.value == "SUCCESS", (
        tool_id, result.status, result.error_code, result.error_message,
        result.stderr[-500:])
    assert result.stdout.strip(), f"{tool_id} returned empty stdout"


def test_maigret_live_execution():
    result = _run_tool("maigret", {"username": "torvalds"}, timeout_override=420)
    _assert_success(result, "maigret")
    assert "http" in result.stdout.lower()


def test_github_osint_live_execution():
    result = _run_tool("github_osint", {"username": "torvalds"}, timeout_override=120)
    _assert_success(result, "github_osint")
    assert "torvalds" in result.stdout.lower()


def test_rdap_lookup_live_execution():
    result = _run_tool("rdap_lookup", {"target": "example.com"}, timeout_override=120)
    _assert_success(result, "rdap_lookup")
    assert "example.com" in result.stdout.lower()


def test_wayback_cdx_live_execution():
    result = _run_tool("wayback_cdx", {"target": "example.com"}, timeout_override=180)
    _assert_success(result, "wayback_cdx")
    assert "example.com" in result.stdout.lower()


def test_photon_crawler_live_execution():
    scope = ScopeConfig(allow_domains=["example.com"])
    result = _run_tool("photon_crawler", {"target": "example.com"},
                       timeout_override=120, scope=scope)
    _assert_success(result, "photon_crawler")
    assert "example.com" in result.stdout.lower()


def test_theharvester_crtsh_live_execution():
    result = _run_tool("theharvester", {"domain": "example.com"},
                       timeout_override=240)
    _assert_success(result, "theharvester")
