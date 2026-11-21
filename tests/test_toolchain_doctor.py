"""Toolchain doctor tests — resolution + real smoke-check logic (no network)."""

from __future__ import annotations

import sys

import pytest

from hub.models import EntityType, ExecutionMode, InvocationSpec, ParameterSpec, ToolCapability
from hub.toolchain import doctor
from hub.tools import capabilities, locator


@pytest.fixture()
def stub_registry(isolated_mock_registry):
    stub = ToolCapability(
        tool_id="stubtool",
        display_name="Stub tool",
        description="doctor test stub",
        accepted_entity_types=[EntityType.USERNAME],
        produced_entity_types=[EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"username": ParameterSpec(name="username", format="username",
                                              required=True)},
        timeout_sec=10,
        rate_limit_rps=1.0,
        invocation=InvocationSpec(kind="binary", binary="python"),
        parser_ref="tests.mock_tools:parse_mock",
    )
    isolated_mock_registry(stub)
    return stub


def _resolved(argv_prefix, *, available=True) -> locator.ResolvedTool:
    return locator.ResolvedTool(tool_id="stub", available=available,
                                source="path", argv_prefix=tuple(argv_prefix))


class TestSmokeTool:
    def test_successful_version_smoke(self):
        resolved = _resolved([sys.executable, "-c",
                              "print('stubtool 1.0.0 usage: options')"])
        ok, code, output = doctor.smoke_tool(resolved, "stubtool")
        assert ok is True
        assert code == 0
        assert "stubtool" in output

    def test_help_exit_one_still_ok_when_usage_printed(self):
        resolved = _resolved([sys.executable, "-c",
                              "print('usage: stubtool --help options'); raise SystemExit(1)"])
        ok, code, output = doctor.smoke_tool(resolved, "stubtool")
        assert ok is True
        assert code == 1
        assert "usage" in output.lower()

    def test_silent_failure_not_ok(self):
        resolved = _resolved([sys.executable, "-c", "raise SystemExit(3)"])
        ok, code, _ = doctor.smoke_tool(resolved, "stubtool")
        assert ok is False
        assert code == 3

    def test_unavailable_tool_skips_spawn(self):
        ok, code, output = doctor.smoke_tool(_resolved([], available=False), "stubtool")
        assert ok is False and code is None and output == ""


class TestCheckTool:
    def test_available_path_tool(self, stub_registry):
        locator.reset_cache()
        check = doctor.check_tool("stubtool", force=True)
        assert check.available is True
        assert check.smoke_ok is True
        assert check.resolver in {"path", "managed-home", "managed-venv"}
        assert check.smoke_exit_code == 0

    def test_builtin_tool_healthy(self, isolated_mock_registry):
        from hub.models import ToolCapability as TC

        builtin = TC(
            tool_id="docsbuiltin",
            display_name="Docs builtin",
            description="stub builtin",
            accepted_entity_types=[EntityType.DOMAIN],
            produced_entity_types=[EntityType.IP],
            invocation=InvocationSpec(
                kind="builtin", builtin_ref="hub.tools.builtin.dns_lookup:collect"),
            parser_ref="hub.tools.parsers.dns_lookup:parse",
            parameters={"target": ParameterSpec(name="target", format="hostname",
                                                required=True)},
        )
        isolated_mock_registry(builtin)
        check = doctor.check_tool("docsbuiltin", force=True)
        assert check.available is True
        assert check.resolver == "builtin"
        assert check.smoke_ok is True


class TestRunDoctor:
    def test_summary_and_table(self, stub_registry):
        from hub.models import ToolCapability as TC

        builtin = TC(
            tool_id="docsbuiltin",
            display_name="Docs builtin",
            description="stub builtin",
            accepted_entity_types=[EntityType.DOMAIN],
            produced_entity_types=[EntityType.IP],
            invocation=InvocationSpec(
                kind="builtin", builtin_ref="hub.tools.builtin.dns_lookup:collect"),
            parser_ref="hub.tools.parsers.dns_lookup:parse",
            parameters={"target": ParameterSpec(name="target", format="hostname",
                                                required=True)},
        )
        capabilities.register(builtin, replace=True)
        result = doctor.run_doctor(provision=False, force=True)
        assert result["total"] == 2
        assert result["available"] == 2
        assert result["healthy"] == 2
        assert result["missing"] == []
        assert "✅ AVAILABLE" in result["table"]
        assert "2/2 tools AVAILABLE" in doctor.doctor_summary_line(result)
        report = doctor.format_doctor_report(result)
        assert "toolchain doctor" in report
        assert "Managed bin dirs" in report

    def test_provision_invokes_provisioner(self, stub_registry, monkeypatch):
        from hub.models import ToolCapability as TC

        builtin = TC(
            tool_id="docsbuiltin",
            display_name="Docs builtin",
            description="stub builtin",
            accepted_entity_types=[EntityType.DOMAIN],
            produced_entity_types=[EntityType.IP],
            invocation=InvocationSpec(
                kind="builtin", builtin_ref="hub.tools.builtin.dns_lookup:collect"),
            parser_ref="hub.tools.parsers.dns_lookup:parse",
            parameters={"target": ParameterSpec(name="target", format="hostname",
                                                required=True)},
        )
        capabilities.register(builtin, replace=True)
        import hub.toolchain.provision as provision

        called = {}
        monkeypatch.setattr(provision, "provision_toolchain",
                            lambda: called.setdefault("yes", {"actions": [
                                {"tool_id": "stubtool", "action": "faked",
                                 "detail": "", "ok": True}]}))
        result = doctor.run_doctor(provision=True, force=True)
        assert called.get("yes")
        assert result["provisioning"]["actions"][0]["action"] == "faked"

    def test_missing_tool_reported(self, stub_registry, monkeypatch):
        monkeypatch.setattr(locator, "resolve_tool",
                            lambda *a, **k: locator.ResolvedTool(
                                tool_id="stubtool", available=False,
                                source="none", detail="not found"))
        check = doctor.check_tool("stubtool", force=True)
        assert check.available is False
        assert check.smoke_ok is False
        assert "not found" in check.detail
