"""Provisioning tests — venv creation, installers, downloads, wrapper fallbacks."""

from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from hub.toolchain import provision
from hub.tools import locator


@pytest.fixture(autouse=True)
def isolated_layout(tmp_path, monkeypatch):
    bin_dir = tmp_path / "home" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(locator.MANAGED_BIN_ENV, str(bin_dir))
    monkeypatch.setenv(locator.MANAGED_VENV_ENV, str(tmp_path / "repo" / ".venv" / "Scripts"))
    monkeypatch.setattr(locator, "repo_root", lambda: tmp_path / "repo")
    locator.reset_cache()
    yield {"bin": bin_dir, "repo": tmp_path / "repo", "tmp": tmp_path}
    locator.reset_cache()


def _venv_python(repo: Path) -> Path:
    return repo / ".venv" / "Scripts" / "python.exe"


class TestVenv:
    def test_existing_venv_reused(self, isolated_layout):
        python = _venv_python(isolated_layout["repo"])
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_text("fake", encoding="utf-8")
        path, detail = provision.ensure_managed_venv("3.11")
        assert path == python
        assert "already present" in detail

    def test_extra_python_uses_suffixed_dir(self, isolated_layout, monkeypatch):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return 0, "created"

        monkeypatch.setattr(provision, "_run", fake_run)
        monkeypatch.setattr(provision, "UV", "uv")
        python = isolated_layout["repo"] / ".venv314" / "Scripts" / "python.exe"
        python.parent.mkdir(parents=True, exist_ok=True)
        python.write_text("fake", encoding="utf-8")
        path, detail = provision.ensure_managed_venv("3.14")
        assert path == python
        assert ".venv314" in detail

    def test_install_python_spec_prefers_uv(self, monkeypatch, tmp_path):
        commands = []
        monkeypatch.setattr(provision, "UV", "uv")
        monkeypatch.setattr(provision, "_run",
                            lambda command, **kwargs: commands.append(command) or (0, "ok"))
        ok, output = provision.install_python_spec(tmp_path / "python.exe", "holehe")
        assert ok is True
        assert commands[0][:3] == ["uv", "pip", "install"]
        assert "holehe" in commands[0]

    def test_install_python_spec_falls_back_to_pip(self, monkeypatch, tmp_path):
        commands = []
        monkeypatch.setattr(provision, "UV", None)
        monkeypatch.setattr(provision, "_run",
                            lambda command, **kwargs: commands.append(command) or (0, "ok"))
        ok, _ = provision.install_python_spec(tmp_path / "python.exe", "maigret")
        assert ok is True
        assert any("ensurepip" in command for command in commands)
        assert any("pip" in command and "maigret" in command for command in commands)


class TestWrapperFallback:
    def test_install_wrapper_creates_launcher(self, isolated_layout, monkeypatch):
        monkeypatch.setitem(provision.WRAPPER_TOOLS, "snscrape", {
            "module": "hub.toolchain.wrappers.snscrape",
            "display_name": "snscrape wrapper",
            "smoke_args": ["--version"],
        })
        report = provision.ProvisionReport(started_at="t")
        assert provision.install_wrapper("snscrape", report) is True
        descriptor = isolated_layout["bin"] / "snscrape.launcher.json"
        assert descriptor.exists()
        assert (isolated_layout["bin"] / "snscrape.py").exists()
        assert (isolated_layout["bin"] / "snscrape.cmd").exists()
        data = json.loads(descriptor.read_text(encoding="utf-8"))
        assert data["module"] == "hub.toolchain.wrappers.snscrape"
        assert report.actions[0]["action"] == "wrapper-installed"

    def test_install_wrapper_missing_implementation_reports(self, isolated_layout):
        report = provision.ProvisionReport(started_at="t")
        assert provision.install_wrapper("nope", report) is False
        assert report.actions[0]["action"] == "no-fallback"
        assert report.errors

    def test_ensure_tool_home_creates_dirs(self, isolated_layout):
        home = provision.ensure_tool_home("theharvester")
        assert home.is_dir()
        assert (home / ".theHarvester").is_dir()
        assert (home / ".local" / "share" / "theHarvester").is_dir()


class TestWslInstaller:
    def test_install_wsl_packages_command(self, monkeypatch):
        commands = []
        monkeypatch.setattr(locator, "wsl_available", lambda: True)
        monkeypatch.setattr(locator, "wsl_distro", lambda: "Ubuntu")
        monkeypatch.setattr(locator, "clear_wsl_cache", lambda: None)
        monkeypatch.setattr(provision, "_run",
                            lambda command, **kwargs: commands.append(command) or (0, "ok"))
        monkeypatch.setattr(provision.shutil, "which",
                            lambda name: "wsl.exe" if name in {"wsl.exe", "wsl"} else None)
        ok, _ = provision.install_wsl_packages(["hashcat", "hydra"])
        assert ok is True
        assert commands and "wsl.exe" == commands[0][0]
        script = commands[0][-1]
        assert "apt-get install" in script and "hashcat" in script and "hydra" in script

    def test_install_wsl_packages_without_bridge(self, monkeypatch):
        monkeypatch.setattr(locator, "wsl_available", lambda: False)
        ok, detail = provision.install_wsl_packages(["hashcat"])
        assert ok is False
        assert "WSL" in detail


class TestPhoneinfogaDownload:
    def test_downloads_and_extracts_release(self, isolated_layout, monkeypatch):
        asset_name = "phoneinfoga_Windows_x86_64.tar.gz" if os.name == "nt" \
            else "phoneinfoga_Linux_x86_64.tar.gz"
        archive_bytes = io.BytesIO()
        binary_name = "phoneinfoga.exe" if os.name == "nt" else "phoneinfoga"
        with tarfile.open(fileobj=archive_bytes, mode="w:gz") as tar:
            payload = b"#!/bin/sh\nexit 0\n"
            info = tarfile.TarInfo(binary_name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        archive_data = archive_bytes.getvalue()
        release = {
            "tag_name": "v9.9.9",
            "assets": [{"name": asset_name,
                        "browser_download_url": "https://example.invalid/dl"}],
        }

        class FakeResponse:
            def __init__(self, payload: bytes):
                self._payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return self._payload

        calls = []

        def fake_urlopen(request, timeout=60):
            calls.append(request)
            if len(calls) == 1:
                return FakeResponse(json.dumps(release).encode("utf-8"))
            return FakeResponse(archive_data)

        monkeypatch.setattr(provision.urllib.request, "urlopen", fake_urlopen)
        ok, detail = provision.download_phoneinfoga(isolated_layout["bin"])
        assert ok is True, detail
        assert (isolated_layout["bin"] / binary_name).exists()


class TestProvisionOrchestrator:
    def test_idempotent_when_everything_resolves(self, isolated_layout, monkeypatch):
        fake = locator.ResolvedTool(tool_id="x", available=True, source="path",
                                    argv_prefix=("x",))
        monkeypatch.setattr(locator, "resolve_tool", lambda *a, **k: fake)
        monkeypatch.setattr(locator, "ensure_managed_dirs", lambda: [isolated_layout["bin"]])
        monkeypatch.setattr(locator, "clear_wsl_cache", lambda: None)
        monkeypatch.setattr(provision, "_run",
                            lambda *a, **k: pytest.fail("provisioning should not run"))
        monkeypatch.setattr(provision, "install_wrapper",
                            lambda *a, **k: pytest.fail("no wrappers expected"))
        report = provision.provision_toolchain()
        assert report["available"] == report["total"]
        assert all(action["action"] == "already-available"
                   for action in report["actions"])
        assert report["errors"] == []
