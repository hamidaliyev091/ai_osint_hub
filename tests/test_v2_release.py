"""Deterministic offline release verification tests for AI OSINT Hub v2.0.0.

Covers:
1. Cross-platform locator.py (0xC0000142 trampoline fallback, Windows nmap -> WSL2
   fallback, macOS/Linux PATH dirs, install_hint) + wheel/package-data Cytoscape check.
2. Synthetic demo case seeder (hub/demo.py) with zero network I/O.
3. Portable .osintcase.zip bundles (round-trip, PII redaction, Zip-Slip, backslash,
   symlink, zip-bomb/compression ratio, bad SHA-256, overwrite guard, corrupt SQLite).
4. AI hardware presets, get_ai_status pull_commands, CLI subcommands (web, demo,
   export, import, mcp-config, doctor --no-smoke, optional investigate raw_input).
5. Web Workbench v2 routes (/api/demo, /api/investigations/{id}/bundle,
   /api/bundles/import, /api/mcp-config), DOM Markdown XSS safety, Ctrl+K command
   palette & scope modal markers, and MCP App content[0].text fallback + _meta.ui.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.resources
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from hub.ai import (
    AI_PRESETS_CATALOG,
    AIConfig,
    AIHardwarePreset,
    AIProviderKind,
    get_ai_status,
    load_ai_config,
    update_ai_config,
)
from hub.bundle import (
    BUNDLE_EXTENSION,
    BUNDLE_FORMAT,
    BUNDLE_FORMAT_VERSION,
    MAX_COMPRESSION_RATIO,
    MAX_UNCOMPRESSED_BYTES,
    export_case_bundle,
    import_case_bundle,
)
from hub.demo import DEMO_TARGET_ID, DEMO_TITLE, seed_demo_case
from hub.erkg.store import ERKGStore
from hub.investigation.engine import InvestigationEngine
from hub.mcp_server import _MCP_WORKBENCH_HTML, mcp
from hub.models import (
    PROVENANCE_AI_INFERRED,
    EntityType,
    EpistemicStatus,
)
from hub.security.redaction import clear_secrets, register_secret
from hub.service import InvestigationService
from hub.tools import locator
from hub.web import WORKBENCH_HTML, create_app
from tests.mock_tools import MockRunner, empty_output, identity_output, make_capability, parse_mock

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(args: list[str], *, hub_home: Path, timeout: int = 120):
    env = dict(os.environ)
    env["AI_OSINT_HUB_HOME"] = str(hub_home)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "hub.cli", *args],
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


# ════════════════════════════════════════════════════════════════════════
# 1. Cross-platform locator.py & package data
# ════════════════════════════════════════════════════════════════════════

class TestCrossPlatformLocatorAndPackaging:
    def test_windows_trampoline_0xc0000142_fallback(self, tmp_path, monkeypatch):
        venv_dir = tmp_path / "repo" / ".venv314"
        scripts_dir = venv_dir / "Scripts"
        site_pkg = venv_dir / "Lib" / "site-packages"
        dist_info = site_pkg / "theHarvester-4.11.1.dist-info"
        scripts_dir.mkdir(parents=True)
        dist_info.mkdir(parents=True)
        (scripts_dir / "python.exe").write_text("fake-py", encoding="utf-8")
        exe_path = scripts_dir / "theHarvester.exe"
        exe_path.write_text("fake-exe", encoding="utf-8")
        (dist_info / "entry_points.txt").write_text(
            "[console_scripts]\ntheHarvester = theHarvester.__main__:entry_point\n",
            encoding="utf-8",
        )

        monkeypatch.setenv(locator.MANAGED_BIN_ENV, str(tmp_path / "home_bin"))
        monkeypatch.setenv(locator.MANAGED_VENV_ENV, str(tmp_path / "repo" / ".venv" / "Scripts"))
        monkeypatch.setenv(locator.WSL_ENV, "0")
        monkeypatch.setattr(locator, "repo_root", lambda: tmp_path / "repo")
        monkeypatch.setattr(locator.os, "name", "nt")
        monkeypatch.setattr(locator, "_probe_dll_init_failed", lambda p: p == exe_path)
        locator.reset_cache()

        resolved = locator.resolve_tool("theharvester", "theHarvester", force=True, allow_wrappers=False)
        assert resolved.available is True
        assert resolved.source == "managed-venv"
        assert resolved.argv_prefix[0] == str(scripts_dir / "python.exe")
        assert resolved.argv_prefix[1] == "-c"
        assert "theHarvester.__main__" in resolved.argv_prefix[2]
        assert "entry_point" in resolved.argv_prefix[2]

    def test_windows_nmap_timeout_falls_back_to_wsl2(self, tmp_path, monkeypatch):
        win_nmap = tmp_path / "nmap.exe"
        win_nmap.write_text("fake", encoding="utf-8")
        wsl_exe = tmp_path / "wsl.exe"
        wsl_exe.write_text("fake-wsl", encoding="utf-8")

        monkeypatch.setenv(locator.MANAGED_BIN_ENV, str(tmp_path / "empty_bin"))
        monkeypatch.setenv(locator.MANAGED_VENV_ENV, str(tmp_path / "empty_venv"))
        monkeypatch.delenv(locator.WSL_ENV, raising=False)
        monkeypatch.setattr(locator, "repo_root", lambda: tmp_path / "empty_repo")
        monkeypatch.setattr(locator.os, "name", "nt")

        def fake_which(name: str):
            if name == "nmap":
                return str(win_nmap)
            if name in {"wsl.exe", "wsl"}:
                return str(wsl_exe)
            return None

        monkeypatch.setattr(locator.shutil, "which", fake_which)
        monkeypatch.setattr(locator, "_probe_windows_nmap", lambda path: False)
        monkeypatch.setattr(
            locator,
            "_resolve_wsl",
            lambda tid, b: locator.ResolvedTool(
                tool_id=tid,
                available=True,
                source="wsl",
                detail="WSL2 bridge (Ubuntu) at /usr/bin/nmap",
                argv_prefix=(str(wsl_exe), "-d", "Ubuntu", "--exec", b),
                binary_path="wsl://Ubuntu/usr/bin/nmap",
            ),
        )
        locator.reset_cache()

        resolved = locator.resolve_tool("nmap", "nmap", force=True, allow_wrappers=False)
        assert resolved.available is True
        assert resolved.source == "wsl"
        assert resolved.argv_prefix == (str(wsl_exe), "-d", "Ubuntu", "--exec", "nmap")

    def test_macos_linux_extra_path_dirs_and_install_hints(self):
        darwin_dirs = locator.extra_host_bin_dirs("darwin")
        assert Path("/opt/homebrew/bin") in darwin_dirs
        assert Path("/usr/local/bin") in darwin_dirs

        linux_dirs = locator.extra_host_bin_dirs("linux")
        assert Path("/usr/local/bin") in linux_dirs
        assert Path("/snap/bin") in linux_dirs
        assert Path.home() / ".local" / "bin" in linux_dirs

        assert locator.extra_host_bin_dirs("windows") == []

        assert "brew install nmap" in locator.install_hint("nmap", "darwin")
        assert "apt install" in locator.install_hint("nmap", "linux")
        assert "winget" in locator.install_hint("nmap", "windows")
        assert "Built-in" in locator.install_hint("dns_lookup", "linux")

    def test_package_data_and_cytoscape_discoverable(self):
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        pkg_data = pyproject["tool"]["setuptools"]["package-data"]["hub"]
        assert "static/*" in pkg_data
        assert "static/**/*" in pkg_data
        deps = " ".join(pyproject["project"]["dependencies"])
        assert "Pillow" in deps

        cy_res = importlib.resources.files("hub").joinpath("static", "vendor", "cytoscape.min.js")
        assert cy_res.is_file()
        assert len(cy_res.read_bytes()) > 50_000


# ════════════════════════════════════════════════════════════════════════
# 2. Synthetic demo case (hub/demo.py)
# ════════════════════════════════════════════════════════════════════════

class TestSyntheticDemoCase:
    def test_seed_demo_case_zero_network_and_epistemic_integrity(self, tmp_path, monkeypatch):
        def _forbid_network(*args, **kwargs):
            raise AssertionError("seed_demo_case must not perform any network I/O")

        monkeypatch.setattr(socket, "getaddrinfo", _forbid_network)
        monkeypatch.setattr(socket, "create_connection", _forbid_network)
        monkeypatch.setattr(httpx, "get", _forbid_network)
        monkeypatch.setattr(httpx, "post", _forbid_network)

        summary = seed_demo_case(tmp_path)
        assert summary["status"] == "ok"
        assert summary["target_id"] == DEMO_TARGET_ID
        assert summary["title"] == DEMO_TITLE
        assert summary["synthetic"] is True
        assert summary["entity_count"] >= 12
        assert summary["claim_count"] >= 15
        assert summary["contradiction_count"] >= 1

        db_path = tmp_path / "investigations" / DEMO_TARGET_ID / "erkg.sqlite3"
        assert db_path.is_file()

        store = ERKGStore(db_path, investigation_id=DEMO_TARGET_ID)
        try:
            entities = store.list_entities(DEMO_TARGET_ID)
            claims = store.list_claims(DEMO_TARGET_ID)
            contradictions = store.list_contradictions(DEMO_TARGET_ID)
            insights = store.list_ai_insights(DEMO_TARGET_ID)
            hypotheses = store.list_hypotheses(DEMO_TARGET_ID)

            types = {e.type for e in entities}
            assert {
                EntityType.PERSON,
                EntityType.USERNAME,
                EntityType.EMAIL,
                EntityType.DOMAIN,
                EntityType.SUBDOMAIN,
                EntityType.IP,
                EntityType.ASN,
                EntityType.ORGANIZATION,
                EntityType.HASH,
            }.issubset(types)

            statuses = {c.status for c in claims}
            assert EpistemicStatus.CONFIRMED in statuses
            assert EpistemicStatus.CONTRADICTED in statuses
            assert EpistemicStatus.HYPOTHESIS in statuses

            confirmed_multi = [
                c for c in claims
                if c.status == EpistemicStatus.CONFIRMED and len(c.independent_sources) >= 3
            ]
            assert confirmed_multi, "Demo must include 3-source corroborated CONFIRMED claims"

            ai_claims = [c for c in claims if PROVENANCE_AI_INFERRED in c.independent_sources]
            assert ai_claims
            assert all(c.status == EpistemicStatus.HYPOTHESIS for c in ai_claims)
            assert all(c.confidence <= 0.35 for c in ai_claims)
            assert len(contradictions) >= 1
            assert len(insights) >= 1
            assert len(hypotheses) >= 2
        finally:
            store.close()

        # overwrite=False returns existing summary without failing
        summary2 = seed_demo_case(tmp_path, overwrite=False)
        assert summary2["already_existed"] is True


# ════════════════════════════════════════════════════════════════════════
# 3. Portable .osintcase.zip bundles (hub/bundle.py)
# ════════════════════════════════════════════════════════════════════════

class TestPortableCaseBundles:
    def test_bundle_roundtrip_and_pii_redaction(self, tmp_path):
        seed_demo_case(tmp_path)
        register_secret("sk-test-secret-bundle-value-9999", "TEST_PROVIDER")
        try:
            zip_bytes, manifest = export_case_bundle(tmp_path, DEMO_TARGET_ID, redact_pii=False)
            assert manifest["format"] == BUNDLE_FORMAT
            assert manifest["version"] == BUNDLE_FORMAT_VERSION
            assert manifest["redacted"] is False
            assert "erkg.sqlite3" in manifest["files"]

            # Re-import under a new target_id
            imported = import_case_bundle(tmp_path, zip_bytes, new_target_id="case_demo_reimported")
            assert imported["status"] == "ok"
            assert imported["target_id"] == "case_demo_reimported"
            re_db = tmp_path / "investigations" / "case_demo_reimported" / "erkg.sqlite3"
            assert re_db.is_file()

            # Overwrite guard when overwrite=False
            with pytest.raises(FileExistsError):
                import_case_bundle(tmp_path, zip_bytes, new_target_id="case_demo_reimported", overwrite=False)

            # Overwrite succeeds when overwrite=True
            over = import_case_bundle(tmp_path, zip_bytes, new_target_id="case_demo_reimported", overwrite=True)
            assert over["status"] == "ok"

            # Redacted export scrubs emails and secrets
            red_zip, red_manifest = export_case_bundle(tmp_path, DEMO_TARGET_ID, redact_pii=True)
            assert red_manifest["redacted"] is True
            red_res = import_case_bundle(tmp_path, red_zip, new_target_id="case_demo_redacted")
            assert red_res["redacted"] is True

            red_db = tmp_path / "investigations" / "case_demo_redacted" / "erkg.sqlite3"
            conn = sqlite3.connect(str(red_db))
            try:
                blob = json.dumps(conn.execute("SELECT raw_input FROM investigations").fetchall())
                emails = json.dumps(conn.execute("SELECT canonical_value FROM entities").fetchall())
                assert "e.vance@aurora-meridian.example" not in blob
                assert "e.vance@aurora-meridian.example" not in emails
                assert "[REDACTED:EMAIL]" in emails
            finally:
                conn.close()
        finally:
            clear_secrets()

    def test_malicious_bundle_rejections(self, tmp_path):
        seed_demo_case(tmp_path)
        valid_zip, valid_manifest = export_case_bundle(tmp_path, DEMO_TARGET_ID)

        def _make_evil_zip(modify_fn) -> bytes:
            buf = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(valid_zip), "r") as zin, zipfile.ZipFile(buf, "w") as zout:
                modify_fn(zin, zout)
            return buf.getvalue()

        # 1. Zip-Slip ../ traversal
        def _zip_slip(zin, zout):
            for info in zin.infolist():
                zout.writestr(info, zin.read(info.filename))
            zout.writestr("../../evil.txt", b"pwned")

        with pytest.raises(ValueError, match="Path traversal|Unexpected"):
            import_case_bundle(tmp_path, _make_evil_zip(_zip_slip), overwrite=True)

        # 2. Windows backslash traversal (patch literal backslash into ZIP headers)
        def _backslash(zin, zout):
            for info in zin.infolist():
                zout.writestr(info, zin.read(info.filename))
            zout.writestr("raw/xx/evil.txt", b"pwned")

        raw_backslash_zip = _make_evil_zip(_backslash).replace(
            b"raw/xx/evil.txt", b"raw\\..\\evil.txt"
        )
        with pytest.raises(ValueError, match="Unsafe bundle member|Path traversal"):
            import_case_bundle(tmp_path, raw_backslash_zip, overwrite=True)

        # 3. Unix symlink entry (0o120000)
        def _symlink(zin, zout):
            for info in zin.infolist():
                zout.writestr(info, zin.read(info.filename))
            sym = zipfile.ZipInfo("raw/link.txt")
            sym.create_system = 3
            sym.external_attr = (0o120777 << 16)
            zout.writestr(sym, b"/etc/passwd")

        with pytest.raises(ValueError, match="Symlink"):
            import_case_bundle(tmp_path, _make_evil_zip(_symlink), overwrite=True)

        # 4. Bad SHA-256 in manifest.json
        def _bad_sha(zin, zout):
            for info in zin.infolist():
                data = zin.read(info.filename)
                if info.filename == "manifest.json":
                    m = json.loads(data.decode("utf-8"))
                    m["files"]["erkg.sqlite3"]["sha256"] = "0" * 64
                    data = json.dumps(m).encode("utf-8")
                zout.writestr(info, data)

        with pytest.raises(ValueError, match="SHA-256"):
            import_case_bundle(tmp_path, _make_evil_zip(_bad_sha), overwrite=True)

        # 5. Zip bomb / compression ratio exceeding MAX_COMPRESSION_RATIO
        buf_bomb = io.BytesIO()
        with zipfile.ZipFile(buf_bomb, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.writestr("manifest.json", json.dumps(valid_manifest).encode("utf-8"))
            # 10 MB of zeros compresses to ~10 KB -> ratio ~1000x >> MAX_COMPRESSION_RATIO (50.0)
            zf.writestr("erkg.sqlite3", b"\x00" * (10 * 1024 * 1024))

        with pytest.raises(ValueError, match="Compression ratio|MAX_COMPRESSION_RATIO|MAX_UNCOMPRESSED_BYTES"):
            import_case_bundle(tmp_path, buf_bomb.getvalue(), overwrite=True)

        # 6. Corrupted SQLite DB failing integrity_check (with matching SHA-256)
        corrupt_db = b"not a valid sqlite database"
        def _corrupt_db(zin, zout):
            import hashlib

            for info in zin.infolist():
                if info.filename == "erkg.sqlite3":
                    zout.writestr("erkg.sqlite3", corrupt_db)
                elif info.filename == "manifest.json":
                    m = json.loads(zin.read("manifest.json").decode("utf-8"))
                    m["files"]["erkg.sqlite3"] = {
                        "sha256": hashlib.sha256(corrupt_db).hexdigest(),
                        "size": len(corrupt_db),
                    }
                    zout.writestr("manifest.json", json.dumps(m).encode("utf-8"))
                else:
                    zout.writestr(info, zin.read(info.filename))

        with pytest.raises(ValueError, match="SQLite integrity_check|database"):
            import_case_bundle(tmp_path, _make_evil_zip(_corrupt_db), overwrite=True)


# ════════════════════════════════════════════════════════════════════════
# 4. AI hardware presets & CLI v2 subcommands
# ════════════════════════════════════════════════════════════════════════

class TestAIPresetsAndCLIV2:
    def test_ai_presets_catalog_and_pull_commands(self, tmp_hub_home):
        cfg = load_ai_config()
        assert cfg.enabled is False
        assert cfg.preset == AIHardwarePreset.DISABLED

        assert set(AI_PRESETS_CATALOG.keys()) == {
            "disabled", "cpu_light", "vram_8gb", "vram_16gb_plus", "cloud_byok"
        }

        # Preset defaults applied + explicit override in same payload wins
        st = update_ai_config({
            "preset": "vram_8gb",
            "keep_alive": "120s",
        })
        assert st["enabled"] is True
        assert st["preset"] == "vram_8gb"
        assert st["provider"] == "ollama"
        assert st["models"]["ollama"] == "gemma4:e4b"
        assert st["models"]["ollama_vision"] == "qwen2.5vl:7b"
        assert st["models"]["ollama_embedding"] == "embeddinggemma"
        assert st["num_ctx"] == 8192
        assert st["keep_alive"] == "120s"

        report = get_ai_status(probe_local=False)
        assert report["preset"] == "vram_8gb"
        assert "vram_8gb" in report["presets_catalog"]
        assert "ollama pull gemma4:e4b" in report["pull_commands"]
        assert "ollama pull qwen2.5vl:7b" in report["pull_commands"]

    def test_cli_v2_subcommands_offline(self, tmp_path):
        hub_home = tmp_path / "hub_home"
        hub_home.mkdir()

        # web --help
        web_help = _run_cli(["web", "--help"], hub_home=hub_home)
        assert web_help.returncode == 0
        assert "--open" in web_help.stdout
        assert "--no-port-fallback" in web_help.stdout

        # doctor --no-smoke --json exits 0
        doc = _run_cli(["doctor", "--no-smoke", "--json"], hub_home=hub_home)
        assert doc.returncode == 0
        doc_json = json.loads(doc.stdout)
        assert doc_json["smoke_skipped"] is True

        # demo --json
        demo_res = _run_cli(["demo", "--json"], hub_home=hub_home)
        assert demo_res.returncode == 0
        demo_json = json.loads(demo_res.stdout)
        assert demo_json["target_id"] == DEMO_TARGET_ID

        # export -> import round-trip
        bundle_file = tmp_path / f"test_export{BUNDLE_EXTENSION}"
        exp_res = _run_cli(
            ["export", DEMO_TARGET_ID, "--out", str(bundle_file), "--redact-pii", "--json"],
            hub_home=hub_home,
        )
        assert exp_res.returncode == 0
        exp_json = json.loads(exp_res.stdout)
        assert exp_json["redacted"] is True
        assert bundle_file.is_file()

        imp_res = _run_cli(
            ["import", str(bundle_file), "--target-id", "cli_imported_case", "--json"],
            hub_home=hub_home,
        )
        assert imp_res.returncode == 0
        imp_json = json.loads(imp_res.stdout)
        assert imp_json["target_id"] == "cli_imported_case"

        # mcp-config for all 4 clients
        for client_name in ("antigravity", "claude", "cursor", "vscode"):
            mcp_res = _run_cli(["mcp-config", "--client", client_name, "--json"], hub_home=hub_home)
            assert mcp_res.returncode == 0
            mcp_json = json.loads(mcp_res.stdout)
            assert mcp_json["client"] == client_name
            assert mcp_json["snippet_json"]

        # investigate without positional raw_input (structured flags only)
        inv_res = _run_cli(
            [
                "investigate",
                "--domain",
                "example.com",
                "--max-iterations",
                "1",
                "--min-pivot-threshold",
                "0.99",
                "--json",
            ],
            hub_home=hub_home,
        )
        assert inv_res.returncode == 0, inv_res.stderr
        inv_json = json.loads(inv_res.stdout)
        assert inv_json["status"] in {"completed", "terminated"}


# ════════════════════════════════════════════════════════════════════════
# 5. Web Workbench v2 routes, DOM XSS safety, Ctrl+K, MCP App fallback
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def v2_workbench(tmp_path, tmp_hub_home, isolated_mock_registry):
    caps = [make_capability("mock_u", [EntityType.USERNAME], [EntityType.SOCIAL_PROFILE])]
    isolated_mock_registry(*caps)

    def engine_factory():
        return InvestigationEngine(
            runner=MockRunner(default=lambda c, p: empty_output()),
            parser_resolver=lambda cap: parse_mock,
            health_probe=lambda cap: True,
            state_root=tmp_path / "state",
        )

    service = InvestigationService(engine_factory=engine_factory)
    app = create_app(service)
    with TestClient(app) as client:
        yield client, service


class TestWebV2RoutesAndSecurity:
    def test_web_v2_demo_bundle_and_mcp_routes(self, v2_workbench):
        client, _ = v2_workbench

        # POST /api/demo
        res_demo = client.post("/api/demo", json={"overwrite": True})
        assert res_demo.status_code == 200
        demo_data = res_demo.json()
        assert demo_data["target_id"] == DEMO_TARGET_ID

        # GET /api/investigations/{id}/bundle?redact_pii=true
        res_exp = client.get(f"/api/investigations/{DEMO_TARGET_ID}/bundle?redact_pii=true")
        assert res_exp.status_code == 200
        assert res_exp.headers["content-type"] == "application/zip"
        assert res_exp.headers["x-bundle-redacted"] == "true"

        # POST /api/bundles/import (JSON base64)
        b64 = base64.b64encode(res_exp.content).decode("ascii")
        res_imp = client.post(
            "/api/bundles/import",
            json={"filename": "aurora.osintcase.zip", "data_base64": b64, "target_id": "web_imported"},
        )
        assert res_imp.status_code == 200
        assert res_imp.json()["target_id"] == "web_imported"

        # Duplicate import without overwrite -> 409
        res_dup = client.post(
            "/api/bundles/import",
            json={"filename": "aurora.osintcase.zip", "data_base64": b64, "target_id": "web_imported"},
        )
        assert res_dup.status_code == 409

        # Malicious zip payload -> 400
        bad_buf = io.BytesIO()
        with zipfile.ZipFile(bad_buf, "w") as zf:
            zf.writestr("../evil.txt", b"x")
        res_bad = client.post(
            "/api/bundles/import",
            content=bad_buf.getvalue(),
            headers={"content-type": "application/zip"},
        )
        assert res_bad.status_code == 400

        # GET /api/mcp-config
        res_mcp = client.get("/api/mcp-config?client=antigravity")
        assert res_mcp.status_code == 200
        assert "mcpServers" in res_mcp.json()["snippet"]

        res_mcp_bad = client.get("/api/mcp-config?client=unknown_client")
        assert res_mcp_bad.status_code == 400

    def test_workbench_ux_markers_and_dom_markdown_xss_safety(self):
        # Required UX markers
        assert 'id="cmd-palette-modal"' in WORKBENCH_HTML
        assert 'id="scope-auth-modal"' in WORKBENCH_HTML
        assert 'id="confirm-scope-auth"' in WORKBENCH_HTML
        assert 'id="btn-load-demo"' in WORKBENCH_HTML
        assert 'id="dossier-mode-rendered"' in WORKBENCH_HTML
        assert 'id="dossier-mode-raw"' in WORKBENCH_HTML
        assert "isSafeHref" in WORKBENCH_HTML
        assert "renderMarkdownSafe" in WORKBENCH_HTML

        # Strict XSS ban
        assert "innerHTML" not in WORKBENCH_HTML.split("<script>", 1)[1]
        assert "outerHTML" not in WORKBENCH_HTML
        assert "insertAdjacentHTML" not in WORKBENCH_HTML
        assert "document.write" not in WORKBENCH_HTML
        assert "backdrop-filter" not in WORKBENCH_HTML.lower()

        # Verify isSafeHref & renderMarkdownSafe strip javascript: via Node if present
        node = shutil.which("node")
        if node:
            fn_match = re.search(
                r"(function isSafeHref\(rawUrl\)[\s\S]+?function setDossierMode\()",
                WORKBENCH_HTML,
            )
            assert fn_match
            snippet = fn_match.group(1).rsplit("function setDossierMode(", 1)[0]
            harness = f"""
function make(tag, cls, txt) {{
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt !== undefined && txt !== null) e.textContent = String(txt);
  return e;
}}
var links = [];
var texts = [];
var document = {{
  createElement: function(tag) {{
    var node = {{
      tagName: tag.toUpperCase(),
      attrs: {{}},
      children: [],
      style: {{}},
      _text: "",
      setAttribute: function(k, v) {{ this.attrs[k] = v; }},
      appendChild: function(c) {{ this.children.push(c); return c; }},
      removeChild: function(c) {{}},
      get firstChild() {{ return this.children[0] || null; }}
    }};
    Object.defineProperty(node, "textContent", {{
      get: function() {{ return this._text; }},
      set: function(v) {{ this._text = String(v); texts.push(this._text); }}
    }});
    if (tag === "a") links.push(node);
    return node;
  }},
  createTextNode: function(t) {{
    texts.push(String(t));
    return {{ nodeType: 3, textContent: String(t) }};
  }}
}};
{snippet}
var root = document.createElement("div");
renderMarkdownSafe("[bad](javascript:alert(1)) and [ok](https://example.com) and [evil](data:text/html,<script>)", root);
if (links.length !== 1 || links[0].attrs.href !== "https://example.com/") {{
  throw new Error("Unsafe link allowlist behavior: " + JSON.stringify(links));
}}
console.log("XSS_CHECK_OK");
"""
            proc = subprocess.run(
                [node, "-e", harness],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert proc.returncode == 0, proc.stderr
            assert "XSS_CHECK_OK" in proc.stdout

    def test_mcp_app_content_text_fallback_and_visibility_meta(self):
        assert "result.content" in _MCP_WORKBENCH_HTML
        assert "extractToolData" in _MCP_WORKBENCH_HTML
        assert "ui/notifications/tool-result" in _MCP_WORKBENCH_HTML
        assert "JSON.parse(block.text)" in _MCP_WORKBENCH_HTML
        assert "innerHTML" not in _MCP_WORKBENCH_HTML

        # Verify _meta.ui.visibility on registered MCP tools
        async def _check():
            tools = await mcp.list_tools()
            by_name = {t.name: t for t in tools}
            assert "open_workbench_view" in by_name
            wb_meta = by_name["open_workbench_view"].meta or {}
            assert wb_meta["ui"]["visibility"] == ["model", "app"]
            assert wb_meta["ui"]["resourceUri"] == "ui://ai-osint-hub/workbench.html"
            for tool_name in ("investigate", "step", "status", "graph", "tools", "report"):
                t_meta = by_name[tool_name].meta or {}
                assert t_meta["ui"]["visibility"] == ["model", "app"]

        asyncio.run(_check())
