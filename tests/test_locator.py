"""Toolchain locator tests — managed dirs, PATH, WSL bridge, launchers, cache."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from hub.tools import locator


@pytest.fixture(autouse=True)
def isolated_locator(tmp_path, monkeypatch):
    home = tmp_path / "managed_home"
    bin_dir = home / "bin"
    venv_bin = tmp_path / "repo" / ".venv" / ("Scripts" if os.name == "nt" else "bin")
    venv_bin.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(locator.MANAGED_BIN_ENV, str(bin_dir))
    monkeypatch.setenv(locator.MANAGED_VENV_ENV, str(venv_bin))
    monkeypatch.setenv(locator.WSL_ENV, "0")
    monkeypatch.setenv("AI_OSINT_HUB_DISK_CACHE", "0")
    monkeypatch.setattr(locator, "repo_root", lambda: tmp_path / "repo")
    locator.reset_cache()
    locator.clear_wsl_cache()
    yield {"home_bin": bin_dir, "venv_bin": venv_bin, "repo": tmp_path / "repo"}
    locator.reset_cache()
    locator.clear_wsl_cache()


def _executable_name(tool: str) -> str:
    return tool + (".exe" if os.name == "nt" else "")


def _touch_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    except OSError:
        pass
    return path


class TestManagedDirs:
    def test_home_bin_takes_priority_over_venv(self, isolated_locator):
        home_exe = _touch_executable(isolated_locator["home_bin"] / _executable_name("toolx"))
        venv_exe = _touch_executable(isolated_locator["venv_bin"] / _executable_name("toolx"))
        resolved = locator.resolve_tool("toolx", "toolx", force=True)
        assert resolved.available is True
        assert resolved.source == "managed-home"
        assert resolved.argv_prefix == (str(home_exe),)
        assert str(venv_exe) != resolved.argv_prefix[0]

    def test_venv_dir_found_when_home_bin_empty(self, isolated_locator):
        venv_exe = _touch_executable(isolated_locator["venv_bin"] / _executable_name("tooly"))
        resolved = locator.resolve_tool("tooly", "tooly", force=True)
        assert resolved.available
        assert resolved.source == "managed-venv"
        assert resolved.argv_prefix == (str(venv_exe),)

    def test_managed_dirs_include_extra_venvs(self, isolated_locator):
        extra = isolated_locator["repo"] / ".venv314" / ("Scripts" if os.name == "nt" else "bin")
        extra.mkdir(parents=True)
        dirs = [str(path) for path in locator.managed_bin_dirs()]
        assert str(extra) in dirs
        assert str(isolated_locator["home_bin"]) == dirs[0]

    def test_batch_wrapper_is_not_executed(self, isolated_locator):
        batch = isolated_locator["home_bin"] / "batchtool.cmd"
        batch.write_text("@echo off\n", encoding="utf-8")
        resolved = locator.resolve_tool("batchtool", "batchtool", force=True,
                                        allow_wrappers=False, allow_wsl=False)
        assert resolved.available is False


class TestHostPath:
    def test_which_fallback(self, isolated_locator, tmp_path, monkeypatch):
        fake = _touch_executable(tmp_path / "hostbin" / _executable_name("hosttool"))
        monkeypatch.setattr(locator.shutil, "which",
                            lambda name: str(fake) if name == "hosttool" else None)
        resolved = locator.resolve_tool("hosttool", "hosttool", force=True)
        assert resolved.available
        assert resolved.source == "path"
        assert resolved.argv_prefix == (str(fake),)

    def test_cmd_on_path_rejected(self, isolated_locator, tmp_path, monkeypatch):
        fake = tmp_path / "hostbin" / "scripttool.cmd"
        fake.parent.mkdir(parents=True)
        fake.write_text("@echo off\n", encoding="utf-8")
        monkeypatch.setattr(locator.shutil, "which",
                            lambda name: str(fake) if name == "scripttool" else None)
        resolved = locator.resolve_tool("scripttool", "scripttool", force=True)
        assert resolved.available is False
        assert "batch" in resolved.detail


class TestWrapperLauncher:
    def test_write_and_resolve_launcher(self, isolated_locator, monkeypatch):
        monkeypatch.setattr(locator, "_module_importable", lambda module: True)
        result = locator.write_wrapper_launcher(
            "wraptool", module="hub.toolchain.wrappers.wraptool",
            smoke_args=["--version"], display_name="Wrap Tool")
        assert Path(result["descriptor"]).exists()
        assert Path(result["python"]).exists()
        assert Path(result["windows_cmd"]).exists()
        descriptor = json.loads(Path(result["descriptor"]).read_text(encoding="utf-8"))
        assert descriptor["kind"] == "python-module"
        assert descriptor["module"] == "hub.toolchain.wrappers.wraptool"
        resolved = locator.resolve_tool("wraptool", "wraptool", force=True)
        assert resolved.available
        assert resolved.source == "python-wrapper"
        assert resolved.argv_prefix[1:] == ("-m", "hub.toolchain.wrappers.wraptool")
        assert resolved.env_extra.get("PYTHONPATH")

    def test_unsafe_launcher_module_refused(self, isolated_locator, monkeypatch):
        monkeypatch.setattr(locator, "_module_importable", lambda module: True)
        locator.home_bin().mkdir(parents=True, exist_ok=True)
        (locator.wrapper_descriptor_path("evil")).write_text(json.dumps({
            "kind": "python-module", "module": "os.system",
        }), encoding="utf-8")
        resolved = locator.resolve_tool("evil", "evil", force=True)
        assert resolved.available is False
        assert "refused" in resolved.detail

    def test_remove_launcher(self, isolated_locator, monkeypatch):
        monkeypatch.setattr(locator, "_module_importable", lambda module: True)
        locator.write_wrapper_launcher("gone", module="hub.toolchain.wrappers.gone")
        assert locator.resolve_tool("gone", "gone", force=True).available
        locator.remove_wrapper_launcher("gone")
        assert not locator.wrapper_descriptor_path("gone").exists()


class TestWslBridge:
    def test_resolve_wsl_argv_prefix(self, monkeypatch):
        monkeypatch.setattr(locator, "wsl_which", lambda binary, force=False: "/usr/bin/toolz")
        monkeypatch.setattr(locator, "wsl_distro", lambda: "Ubuntu")
        monkeypatch.setattr(locator.shutil, "which",
                            lambda name: "wsl.exe" if name in {"wsl.exe", "wsl"} else None)
        resolved = locator._resolve_wsl("toolz", "toolz")
        assert resolved is not None
        assert resolved.available
        assert resolved.source == "wsl"
        assert resolved.argv_prefix[:5] == ("wsl.exe", "-d", "Ubuntu", "--exec", "toolz")
        assert resolved.binary_path == "wsl://Ubuntu/usr/bin/toolz"

    def test_wsl_disabled_by_env(self, monkeypatch):
        monkeypatch.setenv(locator.WSL_ENV, "0")
        assert locator._wsl_exe() is None

    def test_wsl_which_uses_which_executable(self, monkeypatch):
        calls = []

        class FakeProcess:
            returncode = 0
            stdout = b"/usr/bin/toolz\n"

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return FakeProcess()

        monkeypatch.setattr(locator.subprocess, "run", fake_run)
        monkeypatch.setattr(locator, "_detect_wsl", lambda: {
            "checked": True, "exe": "wsl.exe", "distro": "Ubuntu", "probe": ""})
        monkeypatch.setattr(locator, "_WSL_CACHE", {})
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("AI_OSINT_HUB_DISK_CACHE", "0")
            path = locator.wsl_which("toolz", force=True)
        assert path == "/usr/bin/toolz"
        assert calls and calls[0][3:6] == ["--exec", "/usr/bin/which", "toolz"]


class TestDiskCache:
    def test_save_and_load(self, isolated_locator, monkeypatch):
        monkeypatch.setenv("AI_OSINT_HUB_DISK_CACHE", "1")
        data = {"wsl": {"distro": "Ubuntu", "checked_at": 1}, "wsl_which": {}}
        locator.save_disk_cache(data)
        loaded = locator.load_disk_cache()
        assert loaded["wsl"]["distro"] == "Ubuntu"

    def test_freshness(self):
        assert locator._fresh({"checked_at": __import__("time").time()}) is True
        assert locator._fresh({"checked_at": 1}) is False
        assert locator._fresh(None) is False


class TestChildEnv:
    def test_managed_dirs_prepended_to_path(self, isolated_locator):
        env = locator.enrich_child_env({"PATH": "C:\\existing"})
        parts = env["PATH"].split(os.pathsep)
        assert parts[0] == str(isolated_locator["home_bin"])
        assert parts[-1] == "C:\\existing"

    def test_resolved_env_merged(self, isolated_locator):
        resolved = locator.ResolvedTool(
            tool_id="t", available=True, source="python-wrapper",
            argv_prefix=("python", "-m", "x"),
            env_extra={"PYTHONPATH": "/repo"},
        )
        env = locator.enrich_child_env({"PATH": ""}, resolved)
        assert env["PYTHONPATH"] == "/repo"
