"""Pytest fixtures for AI OSINT Hub tests."""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_root() -> Path:
    return FIXTURES_DIR


@pytest.fixture()
def tmp_hub_home(tmp_path, monkeypatch):
    """Isolated AI_OSINT_HUB_HOME for store/service tests."""
    home = tmp_path / "hub_home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AI_OSINT_HUB_HOME", str(home))
    return home


@pytest.fixture()
def isolated_mock_registry():
    """Replace the global capability registry with mock capabilities, then restore."""
    from hub.tools import capabilities

    snapshot = dict(capabilities._REGISTRY)
    capabilities.reset_registry()

    def register(*capabilities_to_add):
        for capability in capabilities_to_add:
            capabilities.register(capability, replace=True)
        return capabilities_to_add

    yield register
    capabilities.reset_registry()
    for capability in snapshot.values():
        capabilities.register(capability, replace=True)


@pytest.fixture()
def store_factory(tmp_path):
    """Factory yielding isolated ERKGStore instances (closed on teardown)."""
    from hub.erkg.store import ERKGStore

    created = []

    def make(name: str = "erkg.sqlite3", *, investigation_id=None):
        store = ERKGStore(tmp_path / name, investigation_id=investigation_id)
        created.append(store)
        return store

    yield make
    for store in created:
        store.close()
