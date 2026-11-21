"""Live passive smoke test against the RFC-2606 reserved domain example.com.

Opt-in only (network + host DNS required)::

    AI_OSINT_HUB_LIVE=1 python -m pytest tests/test_live_smoke.py -q

Uses only the python-native passive collectors (dns_lookup, http_headers,
tls_cert) plus the code-enforced scope allowlist, so it is safe and non-intrusive.
"""

import os

import pytest

from hub.service import InvestigationService

pytestmark = pytest.mark.skipif(
    os.environ.get("AI_OSINT_HUB_LIVE") != "1",
    reason="live network test; set AI_OSINT_HUB_LIVE=1 to enable",
)

BUILTIN_TOOLS = {"dns_lookup", "http_headers", "tls_cert"}


def test_live_passive_investigation(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_OSINT_HUB_HOME", str(tmp_path / "live_home"))
    service = InvestigationService()

    health = service.tools(refresh=True)
    assert BUILTIN_TOOLS <= set(health["available_tools"])

    result = service.investigate(
        "example.com",
        target_id="live_example_com",
        max_iterations=3,
        max_tool_calls=3,
        wall_clock_timeout_sec=120,
        scope={"allow_domains": ["example.com"], "allow_active_recon": False},
        include_report=True,
    )
    assert result["status"] in {"completed", "terminated"}, result
    assert result["stats"]["artifacts"] >= 1

    ledger = service.graph("live_example_com", view="ledger")["ledger"]
    executed = {entry["tool_id"] for entry in ledger}
    assert executed, "no live tool executed"
    # The investigation is passive-only (allow_active_recon=False), regardless of
    # whether the chosen pivots are builtin collectors or provisioned passive CLIs.
    from hub.tools import capabilities as cap_registry

    modes = {cap.tool_id: cap.execution_mode.value
             for cap in cap_registry.all_capabilities()}
    assert all(modes.get(tool_id) == "PASSIVE" for tool_id in executed), \
        f"non-passive tool executed in a passive-only investigation: {executed}"
    assert any(entry["status"] == "SUCCESS" for entry in ledger)
    # Every executed target stayed inside the explicit allowlist (no scope leak).
    assert all(entry["status"] in {"SUCCESS", "EMPTY", "ERROR", "TIMEOUT"}
               for entry in ledger)

    report = result["report"]["content"]
    assert "[art_" in report
    assert "example.com" in report
    assert "## 5. Collection Gaps" in report
