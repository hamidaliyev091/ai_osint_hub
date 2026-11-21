"""Phase 10 tests — credential vault, redaction, TheHarvester sync, API tools, web routes."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hub import credentials
from hub.models import EntityType, ErrorCode, ScopeConfig, ToolCapability
from hub.security import redaction
from hub.tools import capabilities

REPO = Path(__file__).resolve().parents[1]


# ════════════════════════════════════════════════════════════════════════
# Fixtures
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def vault_home(tmp_path, monkeypatch):
    """Isolated credential vault + writable tool home; no provider env leakage."""
    home = tmp_path / "state"
    toolhome = tmp_path / "toolhome"
    home.mkdir()
    monkeypatch.setenv("AI_OSINT_HUB_HOME", str(home))
    monkeypatch.setenv("AI_OSINT_HUB_TOOL_HOME", str(toolhome))
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "VIRUSTOTAL_API_KEY", "VT_API_KEY",
                 "SHODAN_API_KEY", "SHODAN_KEY", "CENSYS_API_ID",
                 "CENSYS_API_SECRET", "CENSYS_TOKEN", "CENSYS_API_TOKEN",
                 "HUNTER_API_KEY", "HUNTERIO_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    credentials.reload_credentials()
    redaction.clear_secrets()
    capabilities.clear_health_cache()
    yield {"home": home, "toolhome": toolhome}
    redaction.clear_secrets()
    capabilities.clear_health_cache()


def _write_vault(data: dict) -> None:
    path = credentials.vault_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "providers": data}), encoding="utf-8")
    credentials.reload_credentials()


# ════════════════════════════════════════════════════════════════════════
# Vault + provider status
# ════════════════════════════════════════════════════════════════════════

class TestCredentialVault:
    def test_vault_path_is_outside_repo_and_uses_state_home(self, vault_home):
        path = credentials.vault_path()
        assert path == (vault_home["home"] / "credentials.json").resolve()
        assert REPO.resolve() not in path.parents

    def test_missing_keys_report_clean_status(self, vault_home):
        status = credentials.all_provider_status()
        assert status["virustotal"]["auth_status"] == credentials.MISSING_KEY
        assert status["shodan"]["configured"] is False
        assert status["censys"]["auth_status"] == credentials.MISSING_KEY
        # GitHub is usable keyless; it is never "missing".
        assert status["github"]["auth_status"] == credentials.KEYLESS_LIMITED
        assert status["github"]["ready"] is True

    def test_save_provider_masks_and_persists(self, vault_home):
        info = credentials.save_provider("virustotal", {"api_key": "vt-" + "a" * 32})
        assert info["auth_status"] == credentials.CONFIGURED
        assert info["configured"] is True
        saved = credentials.vault_path().read_text(encoding="utf-8")
        assert "vt-" + "a" * 32 in saved        # vault file (outside repo) holds raw
        assert info["fields"]["api_key"]["masked"].endswith("aaaa")
        assert "vt-" + "a" * 32 != info["fields"]["api_key"]["masked"]
        assert "vt-" + "a" * 32 not in json.dumps(info)

    def test_env_overrides_vault(self, vault_home, monkeypatch):
        _write_vault({"shodan": {"api_key": "vault-key-123456"}})
        assert credentials.get_secret("shodan", "api_key") == "vault-key-123456"
        monkeypatch.setenv("SHODAN_API_KEY", "env-key-abcdef")
        credentials.reload_credentials()
        assert credentials.get_secret("shodan", "api_key") == "env-key-abcdef"
        assert credentials.provider_status("shodan")["auth_status"] == credentials.CONFIGURED

    def test_censys_accepts_basic_or_pat(self, vault_home):
        credentials.save_provider("censys", {"api_id": "censys_abc123",
                                             "api_secret": "s" * 40})
        assert credentials.provider_status("censys")["auth_status"] == credentials.CONFIGURED
        credentials.save_provider("censys", {"token": "censys_pat_" + "x" * 20})
        assert credentials.provider_status("censys")["auth_status"] == credentials.CONFIGURED

    def test_censys_partial_status(self, vault_home):
        credentials.save_provider("censys", {"api_id": "censys_only_id"})
        info = credentials.provider_status("censys")
        assert info["auth_status"] == credentials.PARTIAL
        assert info["ready"] is False
        assert "api_secret" in info["missing_fields"]

    def test_configure_from_mapping(self, vault_home):
        saved = credentials.configure_from_mapping({
            "github_token": "gh-" + "1" * 20,
            "virustotal_api_key": "vt-" + "2" * 20,
            "shodan_api_key": "sh-" + "3" * 20,
            "censys_api_id": "censys_id",
            "censys_api_secret": "cs-" + "4" * 20,
            "hunter_api_key": "hu-" + "5" * 20,
        })
        assert set(saved) == {"github", "virustotal", "shodan", "censys", "hunter"}
        assert all(s["auth_status"] == credentials.CONFIGURED for s in saved.values())

    def test_auth_summary_and_tool_status(self, vault_home):
        assert credentials.auth_summary()["configured"] == 0
        credentials.save_provider("github", {"token": "gh-" + "9" * 20})
        assert credentials.auth_ready_for_tool("github_osint") is True
        assert credentials.auth_status_for_tool("viriustotal") == credentials.NOT_REQUIRED
        assert credentials.auth_ready_for_tool("virustotal_lookup") is False
        capabilities.clear_health_cache()
        status = capabilities.health_check("virustotal_lookup", force=True)
        assert status is not None and status.auth_status == "MISSING_KEY"
        assert status.auth_ready is False


class TestSecretRedaction:
    def test_registered_secret_is_redacted(self, vault_home):
        secret = "super-secret-token-" + "x" * 10
        credentials.save_provider("hunter", {"api_key": secret})
        text = f"request failed key={secret} for hunter"
        redacted = redaction.redact(text)
        assert secret not in redacted
        assert "[REDACTED:HUNTER]" in redacted
        assert redaction.masked_preview(secret).endswith(secret[-4:])

    def test_redact_obj_nested(self, vault_home):
        secret = "nested-secret-" + "z" * 12
        credentials.save_provider("shodan", {"api_key": secret})
        payload = {"outer": [{"key": secret}, f"x{secret}y"]}
        redacted = redaction.redact_obj(payload)
        assert secret not in json.dumps(redacted)
        assert "[REDACTED:SHODAN]" in json.dumps(redacted)

    def test_full_secret_not_in_status_or_service_output(self, vault_home):
        secret = "ghp_" + "q" * 36
        credentials.save_provider("github", {"token": secret})
        from hub.service import InvestigationService

        service = InvestigationService()
        payload = service.credentials()
        serialized = json.dumps(payload)
        assert secret not in serialized
        assert payload["providers"]["github"]["fields"]["token"]["masked"].endswith("qqqq")

    def test_runtime_redacts_collector_output(self, vault_home, monkeypatch):
        """A collector that accidentally echoes a secret must not leak it."""
        secret = "leaky-secret-" + "w" * 12
        credentials.save_provider("virustotal", {"api_key": secret})
        from hub.tools import runtime as runtime_mod
        from hub.tools.runtime import RunContext, ToolRuntime
        from hub.tools.builtin import BuiltinOutput

        async def fake_collector(params, *, timeout_sec, scope):
            return BuiltinOutput(stdout=f"raw key={secret}\n", exit_code=0)

        monkeypatch.setattr(runtime_mod, "_load_builtin_collector",
                            lambda ref: fake_collector)
        monkeypatch.setattr(runtime_mod.ToolRuntime, "_availability",
                            lambda self, cap: (True, "test"))
        capability = ToolCapability(
            tool_id="secret_probe", display_name="Secret probe",
            description="test",
            accepted_entity_types=[EntityType.USERNAME],
            produced_entity_types=[EntityType.USERNAME],
            invocation=capabilities.InvocationSpec(
                kind="builtin", builtin_ref="tests.probe:collect"),
            parser_ref="hub.tools.parsers.holehe:parse",
            auth_provider="virustotal",
        )
        result = asyncio.run(ToolRuntime().run(
            capability, {"username": "x"},
            RunContext(investigation_id="t", entity_id="e", scope=ScopeConfig())))
        assert secret not in result.stdout
        assert "[REDACTED:VIRUSTOTAL]" in result.stdout


class TestHarvesterConfigSync:
    def test_yaml_materialized_in_tool_home(self, vault_home):
        import yaml

        credentials.save_provider("github", {"token": "gh-" + "a" * 20})
        credentials.save_provider("virustotal", {"api_key": "vt-" + "b" * 20})
        credentials.save_provider("shodan", {"api_key": "sh-" + "c" * 20})
        credentials.save_provider("hunter", {"api_key": "hu-" + "d" * 20})
        credentials.save_provider("censys", {"api_id": "censys_id",
                                             "api_secret": "cs-" + "e" * 20})
        path = credentials.theharvester_config_path()
        assert path == (vault_home["toolhome"] / "theharvester" / ".theHarvester"
                        / "api-keys.yaml")
        assert path.is_file()
        data = yaml.safe_load(path.read_text(encoding="utf-8"))["apikeys"]
        assert data["github"]["key"].startswith("gh-")
        assert data["virustotal"]["key"].startswith("vt-")
        assert data["shodan"]["key"].startswith("sh-")
        assert data["hunter"]["key"].startswith("hu-")
        assert data["censys"]["id"] == "censys_id"
        assert data["censys"]["secret"].startswith("cs-")
        assert REPO.resolve() not in path.parents or (vault_home["toolhome"]
                                                      in path.parents)

    def test_preserves_unknown_provider_sections(self, vault_home):
        import yaml

        path = credentials.theharvester_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump({"apikeys": {"brave": {"key": "keep-me"}}}),
                        encoding="utf-8")
        credentials.save_provider("shodan", {"api_key": "sh-" + "f" * 20})
        data = yaml.safe_load(path.read_text(encoding="utf-8"))["apikeys"]
        assert data["brave"]["key"] == "keep-me"
        assert data["shodan"]["key"].startswith("sh-")


class TestOptionalTools:
    def test_ghunt_and_h8mail_optional_unconfigured(self, vault_home):
        capabilities.clear_health_cache()
        for tool_id in ("ghunt", "h8mail"):
            status = capabilities.health_check(tool_id, force=True)
            assert status is not None
            assert status.auth_status == "OPTIONAL_UNCONFIGURED"
            assert status.auth_ready is False
            assert capabilities.capability_auth_ready(
                capabilities.get_tool(tool_id)) is False

    def test_optional_tool_becomes_configured_with_config(self, vault_home):
        (vault_home["toolhome"] / "h8mail").mkdir(parents=True, exist_ok=True)
        (vault_home["toolhome"] / "h8mail" / "config.ini").write_text(
            "[h8mail]\n", encoding="utf-8")
        capabilities.clear_health_cache()
        status = capabilities.health_check("h8mail", force=True)
        assert status.auth_status == "CONFIGURED"
        assert capabilities.capability_auth_ready(capabilities.get_tool("h8mail"))


# ════════════════════════════════════════════════════════════════════════
# Web API — /api/credentials + UI modal
# ════════════════════════════════════════════════════════════════════════

class TestCredentialsWebApi:
    @pytest.fixture()
    def client(self, vault_home):
        from fastapi.testclient import TestClient

        from hub.web import create_app

        app = create_app()
        with TestClient(app) as test_client:
            yield test_client

    def test_get_credentials_masked(self, client):
        credentials.save_provider("github", {"token": "ghp_" + "r" * 36})
        response = client.get("/api/credentials")
        assert response.status_code == 200
        payload = response.json()
        assert payload["providers"]["github"]["configured"] is True
        assert "ghp_" + "r" * 36 not in response.text
        assert payload["providers"]["github"]["fields"]["token"]["masked"].endswith("rrrr")

    def test_post_credentials_saves_and_syncs(self, vault_home, client):
        response = client.post("/api/credentials", json={
            "github_token": "ghp_" + "s" * 36,
            "virustotal_api_key": "vt-" + "t" * 30,
            "shodan_api_key": "sh-" + "u" * 30,
            "censys_api_id": "censys_web_id",
            "censys_api_secret": "cs-" + "v" * 30,
            "hunter_api_key": "hu-" + "w" * 30,
        })
        assert response.status_code == 200, response.text
        body = response.text
        assert "ghp_" + "s" * 36 not in body
        assert "vt-" + "t" * 30 not in body
        payload = response.json()
        assert set(payload["saved"]) == {"github", "virustotal", "shodan",
                                         "censys", "hunter"}
        updated = client.get("/api/credentials").json()
        assert updated["providers"]["virustotal"]["auth_status"] == "CONFIGURED"
        assert credentials.theharvester_config_path().is_file()

    def test_ui_has_api_keys_drawer(self, client):
        response = client.get("/")
        assert response.status_code == 200
        html = response.text
        for marker in ("API Keys", "api-keys-modal", "key-github", "key-virustotal",
                       "key-shodan", "key-censys-id", "key-censys-secret",
                       "key-hunter", "Save &amp; Sync Keys", "open-api-keys",
                       "cred-status-github"):
            assert marker in html, marker

    def test_auth_status_reflected_in_tools(self, client):
        credentials.save_provider("virustotal", {"api_key": "vt-" + "x" * 30})
        capabilities.clear_health_cache()
        payload = client.get("/api/tools?refresh=true").json()
        rows = {row["tool_id"]: row for row in payload["tools"]}
        assert rows["virustotal_lookup"]["auth_status"] == "CONFIGURED"
        assert rows["virustotal_lookup"]["auth_ready"] is True
        assert payload["total"] == 28


# ════════════════════════════════════════════════════════════════════════
# Phase-10 API collectors + parsers (mocked transport, no network)
# ════════════════════════════════════════════════════════════════════════

class TestApiCollectorsAndParsers:
    """Focused coverage mirroring the dedicated mocked-transport suite."""

    def test_virustotal_collector_and_parser(self, monkeypatch):
        from tests import test_api_collectors_phase10 as api

        api._set_secrets(monkeypatch, virustotal={"api_key": api.VT_KEY})
        api._install_transport(monkeypatch, api._vt_handler({}))
        result = api._collect(api.virustotal_lookup, {"target": "example.com"})
        assert result.exit_code == 0 and result.error_code is None
        payload = json.loads(result.stdout)
        assert payload["auth_status"] == "CONFIGURED"
        assert api.VT_KEY not in result.stdout
        parsed = api.virustotal_parser.parse(result.stdout, "example.com")
        types = {entity.type.value for entity in parsed.entities}
        assert "subdomain" in types
        assert parsed.relations

    def test_shodan_collector_and_parser(self, monkeypatch):
        from tests import test_api_collectors_phase10 as api

        api._set_secrets(monkeypatch, shodan={"api_key": api.SHODAN_KEY})
        api._install_transport(monkeypatch, api._shodan_handler({}))
        result = api._collect(api.shodan_lookup, {"target": "1.2.3.4"})
        assert result.exit_code == 0 and result.error_code is None
        assert api.SHODAN_KEY not in result.stdout
        parsed = api.shodan_parser.parse(result.stdout, "1.2.3.4")
        types = {entity.type.value for entity in parsed.entities}
        assert "port" in types or "service" in types
        assert parsed.relations

    def test_censys_collector_and_parser(self, monkeypatch):
        from tests import test_api_collectors_phase10 as api

        api._set_secrets(monkeypatch, censys={"token": api.CENSYS_TOKEN})
        api._install_transport(monkeypatch, api._censys_handler({}))
        result = api._collect(api.censys_lookup, {"target": "8.8.8.8"})
        assert result.exit_code == 0 and result.error_code is None
        assert api.CENSYS_TOKEN not in result.stdout
        parsed = api.censys_parser.parse(result.stdout, "8.8.8.8")
        types = {entity.type.value for entity in parsed.entities}
        assert {"ip", "port", "service"} & types
        assert parsed.relations

    def test_hunter_collector_and_parser(self, monkeypatch):
        from tests import test_api_collectors_phase10 as api

        api._set_secrets(monkeypatch, hunter={"api_key": api.HUNTER_KEY})
        api._install_transport(monkeypatch, api._hunter_handler({}))
        result = api._collect(api.hunter_lookup, {"domain": "example.com"})
        assert result.exit_code == 0 and result.error_code is None
        assert api.HUNTER_KEY not in result.stdout
        parsed = api.hunter_parser.parse(result.stdout, "example.com")
        types = {entity.type.value for entity in parsed.entities}
        assert {"email", "person"} & types
        assert parsed.relations

    def test_missing_keys_fail_closed(self, monkeypatch):
        from tests import test_api_collectors_phase10 as api

        api._set_secrets(monkeypatch)  # no provider keys
        api._install_transport(monkeypatch, api._forbidden)
        for module, params in ((api.virustotal_lookup, {"target": "example.com"}),
                               (api.shodan_lookup, {"target": "1.2.3.4"}),
                               (api.censys_lookup, {"target": "8.8.8.8"}),
                               (api.hunter_lookup, {"domain": "example.com"})):
            result = api._collect(module, params)
            assert result.error_code is ErrorCode.AUTHORIZATION_REQUIRED

    def test_all_api_parsers_never_raise(self):
        from tests import test_api_collectors_phase10 as api

        for parser in api.ALL_PARSERS:
            assert parser.parse("", "") is not None
            assert parser.parse("{not json", "") is not None
            assert parser.parse("[]", "") is not None


# ════════════════════════════════════════════════════════════════════════
# CLI parity — auth status / set
# ════════════════════════════════════════════════════════════════════════

class TestAuthCli:
    def _run(self, args, *, home, toolhome):
        env = os.environ.copy()
        env["AI_OSINT_HUB_HOME"] = str(home)
        env["AI_OSINT_HUB_TOOL_HOME"] = str(toolhome)
        for name in ("GITHUB_TOKEN", "GH_TOKEN", "VIRUSTOTAL_API_KEY",
                     "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
                     "CENSYS_TOKEN", "HUNTER_API_KEY"):
            env.pop(name, None)
        return subprocess.run(
            [sys.executable, "-m", "hub.cli", *args],
            cwd=str(REPO), env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=300,
        )

    def test_auth_status_masks_secrets(self, vault_home):
        credentials.save_provider("hunter", {"api_key": "hu-" + "y" * 30})
        process = self._run(["auth", "status"], home=vault_home["home"],
                            toolhome=vault_home["toolhome"])
        assert process.returncode == 0, process.stderr
        assert "CONFIGURED" in process.stdout
        assert "hu-" + "y" * 30 not in process.stdout
        assert "hunter" in process.stdout.lower()

    def test_auth_set_saves_vault_and_yaml(self, vault_home):
        token = "ghp_" + "z" * 36
        process = self._run(["auth", "set", "github", token],
                            home=vault_home["home"],
                            toolhome=vault_home["toolhome"])
        assert process.returncode == 0, process.stderr
        assert token not in process.stdout and token not in process.stderr
        assert credentials.vault_path().is_file()
        credentials.reload_credentials()
        assert credentials.provider_status("github")["auth_status"] == "CONFIGURED"
        yaml_path = vault_home["toolhome"] / "theharvester" / ".theHarvester" / "api-keys.yaml"
        assert yaml_path.is_file()
        assert token in yaml_path.read_text(encoding="utf-8")
