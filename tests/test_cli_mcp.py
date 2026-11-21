"""CLI + MCP parity tests (no network; subprocess uses real host capabilities)."""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_cli(args: list[str], *, hub_home: Path, timeout: int = 120):
    env = dict(os.environ)
    env["AI_OSINT_HUB_HOME"] = str(hub_home)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "hub.cli", *args],
        cwd=str(REPO_ROOT), env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )


@pytest.fixture()
def hub_home(tmp_path) -> Path:
    home = tmp_path / "hub_home"
    home.mkdir(parents=True, exist_ok=True)
    return home


class TestCli:
    def test_tools_json(self, hub_home):
        process = run_cli(["tools", "--json"], hub_home=hub_home)
        assert process.returncode == 0, process.stderr
        payload = json.loads(process.stdout)
        assert payload["status"] == "ok"
        assert payload["total"] == 28
        assert "dns_lookup" in payload["available_tools"]
        assert payload["mcp_tool_definitions"] == payload["total"]

    def test_investigate_status_graph_report_flow(self, hub_home):
        process = run_cli(
            ["investigate", "hamid091", "--max-iterations", "1",
             "--max-tool-calls", "1", "--min-pivot-threshold", "0.99",
             "--json"],
            hub_home=hub_home,
        )
        assert process.returncode == 0, process.stderr
        investigated = json.loads(process.stdout)
        assert investigated["status"] in {"completed", "terminated"}
        target_id = investigated["target_id"]
        assert target_id

        status = run_cli(["status", target_id, "--json"], hub_home=hub_home)
        assert status.returncode == 0, status.stderr
        status_payload = json.loads(status.stdout)
        assert status_payload["status"] == "ok"
        assert status_payload["investigation"]["target_id"] == target_id

        graph = run_cli(["graph", target_id, "--view", "claims", "--json"],
                        hub_home=hub_home)
        assert graph.returncode == 0, graph.stderr
        graph_payload = json.loads(graph.stdout)
        assert graph_payload["status"] == "ok"
        assert graph_payload["claims"]

        report = run_cli(["report", target_id, "--format", "md", "--json"],
                         hub_home=hub_home)
        assert report.returncode == 0, report.stderr
        report_payload = json.loads(report.stdout)
        assert report_payload["status"] == "complete"
        assert "# Intelligence Dossier" in report_payload["content"]

        listing = run_cli(["list", "--json"], hub_home=hub_home)
        assert listing.returncode == 0, listing.stderr
        list_payload = json.loads(listing.stdout)
        assert list_payload["count"] >= 1
        assert any(item["target_id"] == target_id
                   for item in list_payload["investigations"])

    def test_report_out_file(self, hub_home, tmp_path):
        process = run_cli(["investigate", "hamid091", "--max-iterations", "1",
                           "--min-pivot-threshold", "0.99", "--json"],
                          hub_home=hub_home)
        target_id = json.loads(process.stdout)["target_id"]
        out = tmp_path / "reports" / "case.md"
        report = run_cli(["report", target_id, "--out", str(out), "--json"],
                         hub_home=hub_home)
        assert report.returncode == 0, report.stderr
        assert out.exists()
        assert "Intelligence Dossier" in out.read_text(encoding="utf-8")

    def test_serve_help(self, hub_home):
        process = run_cli(["serve", "--help"], hub_home=hub_home)
        assert process.returncode == 0, process.stderr
        assert "--port" in process.stdout and "--host" in process.stdout

    def test_structured_multi_clue_intake(self, hub_home):
        investigate = run_cli(
            ["investigate", "", "--name", "Linus Torvalds",
             "--email", "linus@kernel.org", "--domain", "kernel.org",
             "--username", "torvalds", "--min-pivot-threshold", "0.99",
             "--max-iterations", "1", "--json"],
            hub_home=hub_home,
        )
        assert investigate.returncode == 0, investigate.stderr
        target_id = json.loads(investigate.stdout)["target_id"]
        graph = run_cli(["graph", target_id, "--view", "entities", "--json"],
                        hub_home=hub_home)
        assert graph.returncode == 0, graph.stderr
        entities = json.loads(graph.stdout)["entities"]
        values = {entity["canonical_value"] for entity in entities}
        assert {"linus torvalds", "torvalds", "linus@kernel.org",
                "kernel.org"}.issubset(values)

    def test_report_html_export(self, hub_home, tmp_path):
        investigate = run_cli(
            ["investigate", "hamid091", "--min-pivot-threshold", "0.99",
             "--max-iterations", "1", "--json"],
            hub_home=hub_home,
        )
        target_id = json.loads(investigate.stdout)["target_id"]
        out = tmp_path / "dossier.html"
        report = run_cli(["report", target_id, "--format", "html",
                          "--out", str(out), "--json"], hub_home=hub_home)
        assert report.returncode == 0, report.stderr
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html>")
        payload = json.loads(report.stdout)
        assert payload["format"] == "html"
        assert payload["report_html"].startswith("<!DOCTYPE html>")

    def test_error_paths_are_json(self, hub_home):
        process = run_cli(["status", "does-not-exist", "--json"], hub_home=hub_home)
        assert process.returncode == 1
        payload = json.loads(process.stdout)
        assert payload["status"] == "error"
        assert "not found" in payload["errors"][0].lower()

    def test_doctor_command_wired(self, hub_home):
        process = run_cli(["doctor", "--json"], hub_home=hub_home, timeout=300)
        assert process.returncode in (0, 1)  # 1 only if host toolchain incomplete
        payload = json.loads(process.stdout)
        assert payload["total"] == 28
        assert "tools" in payload and len(payload["tools"]) == 28
        assert all("smoke_ok" in row for row in payload["tools"])

    def test_human_output_tools(self, hub_home):
        process = run_cli(["tools"], hub_home=hub_home)
        assert process.returncode == 0
        assert "capability health" in process.stdout
        assert "| Tool |" in process.stdout


class TestMcp:
    def test_module_imports_without_server_run(self):
        import hub.mcp_server as server

        assert server.mcp.name == "AI OSINT Hub"
        assert callable(server.main)

    def test_declared_tools(self):
        import hub.mcp_server as server

        tools = asyncio.run(server.mcp.list_tools())
        names = {tool.name for tool in tools}
        assert {"investigate", "step", "status", "graph", "tools", "doctor",
                "report"} <= names

    def test_stdio_jsonrpc_handshake(self, tmp_path):
        """Real MCP protocol: initialize + tools/list over stdio, then EOF."""
        home = tmp_path / "mcp_proto_home"
        home.mkdir()
        env = dict(os.environ,
                   AI_OSINT_HUB_HOME=str(home),
                   PYTHONIOENCODING="utf-8")
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "0.0.1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        payload = "".join(json.dumps(message) + "\n" for message in messages)
        process = subprocess.run(
            [sys.executable, "-m", "hub.mcp_server"], cwd=str(REPO_ROOT), env=env,
            input=payload, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120,
        )
        assert process.returncode == 0, process.stderr
        responses = {}
        for line in (process.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in message:
                responses[message["id"]] = message
        assert responses[1]["result"]["serverInfo"]["name"] == "AI OSINT Hub"
        names = {tool["name"] for tool in responses[2]["result"]["tools"]}
        assert {"investigate", "step", "status", "graph", "tools", "report"} <= names

    def test_mcp_operations_match_cli_service(self, tmp_path, monkeypatch):
        import hub.mcp_server as server

        monkeypatch.setenv("AI_OSINT_HUB_HOME", str(tmp_path / "mcp_home"))
        # Health check
        health = server.tools()
        assert health["status"] == "ok"
        # Autonomous loop (username seed -> no matching tools on host -> clean stop)
        investigated = server.investigate("hamid091", max_iterations=1,
                                          max_tool_calls=1, min_pivot_threshold=0.99,
                                          include_report=True)
        assert investigated["status"] in {"completed", "terminated"}
        target_id = investigated["target_id"]
        assert investigated.get("report_md", "").startswith("# Intelligence Dossier")
        # Graph views
        summary = server.graph(target_id, view="summary")
        assert summary["status"] == "ok"
        claims = server.graph(target_id, view="claims")
        assert claims["claims"]
        # status + report JSON
        assert server.status(target_id)["investigation"]["target_id"] == target_id
        report = server.report(target_id, format="json")
        assert report["dossier"]["investigation"]["target_id"] == target_id
        # step on halted investigation returns a clean stopped result (no crash)
        step_result = server.step(target_id)
        assert step_result["status"] in {"stopped", "active", "error"}
