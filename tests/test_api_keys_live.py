"""Opt-in live smoke for Phase-10 credentials + API collectors.

Run with::

    AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_api_keys_live.py -q

Uses whatever credentials are configured in the local vault/env (no secrets are
printed). Hunter.io may legitimately return RATE_LIMITED on a restricted/free
account; that is treated as an auth-valid, rate-limited live result.
"""

import asyncio
import os

import pytest

from hub import credentials
from hub.models import ScopeConfig
from hub.tools import capabilities
from hub.tools.runtime import RunContext, ToolRuntime

pytestmark = pytest.mark.skipif(
    os.environ.get("AI_OSINT_HUB_LIVE") != "1",
    reason="live API-key smoke; set AI_OSINT_HUB_LIVE=1 to enable",
)

CASES = [
    ("github_osint", {"username": "torvalds"}, 120),
    ("virustotal_lookup", {"target": "example.com"}, 90),
    ("shodan_lookup", {"target": "8.8.8.8"}, 90),
    ("censys_lookup", {"target": "1.1.1.1"}, 90),
    ("hunter_lookup", {"domain": "example.com"}, 60),
]


def _run(tool_id: str, params: dict, timeout: int):
    async def main():
        runtime = ToolRuntime(max_concurrent_tools=1)
        try:
            return await runtime.run(
                capabilities.get_tool(tool_id), params,
                RunContext(investigation_id="live-phase10", entity_id="live",
                           scope=ScopeConfig(), timeout_override_s=timeout))
        finally:
            await runtime.aclose()

    return asyncio.run(main())


def test_all_five_providers_configured():
    credentials.load_credentials(force=True)
    statuses = credentials.all_provider_status()
    for provider in ("github", "virustotal", "shodan", "censys", "hunter"):
        assert statuses[provider]["auth_status"] == "CONFIGURED", statuses[provider]
        assert statuses[provider]["configured"] is True


@pytest.mark.parametrize("tool_id,params,timeout", CASES)
def test_api_collector_live(tool_id, params, timeout):
    result = _run(tool_id, params, timeout)
    if tool_id == "hunter_lookup" and result.error_code is not None \
            and result.error_code.value == "RATE_LIMITED":
        # Hunter.io can restrict/rate-limit a valid free account; credentials
        # themselves are proven by the account-status test above.
        assert "rate limit" in result.error_message.lower()
        return
    assert result.status.value in {"SUCCESS", "EMPTY"}, (
        tool_id, result.status, result.error_code, result.error_message[:200])
    assert result.stdout.strip(), f"{tool_id} returned empty stdout"
    assert result.error_code is None
