"""Legacy v1 orchestrator shim tests (Windows import regression + JSON contract)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_shell(*args: str, hub_home: Path, timeout: int = 120):
    env = dict(os.environ)
    env["AI_OSINT_HUB_HOME"] = str(hub_home)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "hub.orchestrate", *args],
        cwd=str(REPO_ROOT), env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )


@pytest.fixture()
def hub_home(tmp_path) -> Path:
    home = tmp_path / "legacy_home"
    home.mkdir(parents=True, exist_ok=True)
    return home


def test_legacy_module_imports_on_this_platform():
    """v1 crashed on Windows with ModuleNotFoundError: fcntl — must never regress."""
    process = subprocess.run(
        [sys.executable, "-c", "import hub.orchestrate; print('ok')"],
        cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL, capture_output=True,
        text=True, encoding="utf-8", timeout=120,
    )
    assert process.returncode == 0, process.stderr
    assert "ok" in process.stdout
    source = (REPO_ROOT / "hub" / "orchestrate.py").read_text(encoding="utf-8")
    assert "import fcntl" not in source


def test_init_status_report_step_cycle(hub_home):
    init_process = run_shell(
        "--init", json.dumps({"raw_input": "hamid091",
                              "constraints": {"max_depth": 2}}),
        hub_home=hub_home,
    )
    assert init_process.returncode == 0, init_process.stderr
    initialized = json.loads(init_process.stdout)
    assert initialized["status"] == "initialized"
    target_id = initialized["target_id"]
    # The full toolchain is provisioned, so a username seed has ranked pivots.
    assert isinstance(initialized["candidate_actions"], list)
    assert isinstance(initialized["available_tools"], list)
    assert initialized["available_tools"]

    status_process = run_shell("--status", json.dumps({"target_id": target_id}),
                               hub_home=hub_home)
    assert status_process.returncode == 0, status_process.stderr
    status = json.loads(status_process.stdout)
    assert status["status"] == "ok"
    assert status["investigation"]["target_id"] == target_id

    report_process = run_shell("--report", json.dumps({"target_id": target_id}),
                               hub_home=hub_home)
    assert report_process.returncode == 0, report_process.stderr
    report = json.loads(report_process.stdout)
    assert report["status"] == "complete"
    assert report["report_md"].startswith("# Intelligence Dossier")


def test_step_with_invalid_action_returns_clean_error(hub_home):
    init_process = run_shell(
        "--init", json.dumps({"raw_input": "hamid091"}),
        hub_home=hub_home,
    )
    target_id = json.loads(init_process.stdout)["target_id"]
    step_process = run_shell(
        "--step", json.dumps({"target_id": target_id,
                              "selected_action_id": "act_999"}),
        hub_home=hub_home,
    )
    assert step_process.returncode == 0, step_process.stderr
    result = json.loads(step_process.stdout)
    assert result["status"] == "error"
    assert "invalid action_id" in result["errors"][0]


def test_unknown_command_errors(hub_home):
    process = run_shell(hub_home=hub_home)
    assert process.returncode == 1
    payload = json.loads(process.stdout)
    assert payload["status"] == "error"
