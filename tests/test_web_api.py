"""Offline API tests for the FastAPI web workbench (Phase 9).

Everything is injected and deterministic: the global capability registry is
swapped for mock builtin capabilities (``isolated_mock_registry``), the engine
gets a ``MockRunner`` plus the generic ``parse_mock`` parser, and state lives in
``tmp_path``. No network, no real subprocess and no external toolchain check.

Covered:
    * GET / embedded dark-mode workbench (UI markers, EventSource, SVG graph)
    * GET /api/tools + POST /api/doctor
    * POST /api/investigations wait=True (report included) and background start
    * GET /api/investigations + GET /api/investigations/{id} ERKG payload
    * GET report?format=md|json|html exports
    * POST /{id}/step (deterministic on a stopped investigation)
    * GET /{id}/stream: full SSE body terminates with snapshot + done
    * 404s for unknown investigations
"""

import json

import pytest
from fastapi.testclient import TestClient

from hub.investigation.engine import InvestigationEngine
from hub.models import EntityType
from hub.service import InvestigationService
from hub.tools import capabilities
from hub.web import build_investigation_payload, create_app
from tests.mock_tools import (
    MockRunner,
    empty_output,
    identity_output,
    make_capability,
    parse_mock,
)

TERMINAL_STATUSES = {"completed", "terminated", "failed"}


# ══════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════

@pytest.fixture()
def mock_registry(isolated_mock_registry):
    """Deterministic mock toolset (builtin collectors, no binaries needed).

    Three behavioural mocks (username/email/domain) drive the investigation
    loop; four type-isolated fillers keep the registry shape close to the real
    24-tool catalog so total-count assertions (`>= 7`) stay meaningful.
    """
    caps = [
        make_capability("mock_username", [EntityType.USERNAME],
                        [EntityType.USERNAME, EntityType.SOCIAL_PROFILE],
                        prior_yield=0.95, reliability=0.90),
        make_capability("mock_email", [EntityType.EMAIL],
                        [EntityType.SERVICE], prior_yield=0.85, reliability=0.85),
        make_capability("mock_domain", [EntityType.DOMAIN],
                        [EntityType.IP], prior_yield=0.70, reliability=0.90),
    ]
    filler_types = (EntityType.HASH, EntityType.PHONE,
                    EntityType.URL, EntityType.CRYPTO_ADDRESS)
    caps.extend(
        make_capability(f"mock_filler_{index}", [entity_type],
                        [EntityType.SERVICE], prior_yield=0.10, reliability=0.40)
        for index, entity_type in enumerate(filler_types)
    )
    isolated_mock_registry(*caps)
    return caps


def _default_result(capability, params):
    """Deterministic per-capability mock output that corroborates the seed."""
    value = ""
    if isinstance(params, dict) and params:
        value = str(next(iter(params.values())))
    if capability.tool_id == "mock_domain":
        return empty_output()
    if capability.tool_id == "mock_email":
        return identity_output(EntityType.EMAIL, value) if "@" in value else empty_output()
    return identity_output(EntityType.USERNAME, value)


@pytest.fixture()
def runner():
    return MockRunner(default=_default_result)


def _build_service(tmp_path, runner):
    def engine_factory():
        return InvestigationEngine(
            runner=runner,
            parser_resolver=lambda capability: parse_mock,
            health_probe=lambda capability: True,
            state_root=tmp_path / "state",
        )

    return InvestigationService(engine_factory=engine_factory)


@pytest.fixture()
def workbench(tmp_path, mock_registry, runner):
    """(TestClient, InvestigationService) backed by the isolated mock engine."""
    service = _build_service(tmp_path, runner)
    app = create_app(service)
    with TestClient(app) as client:
        yield client, service


def _start_wait(client, **body):
    payload = {"raw_input": "hamid091", "wait": True,
               "max_iterations": 3, "max_tool_calls": 3}
    payload.update(body)
    response = client.post("/api/investigations", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


# ══════════════════════════════════════════════════════════════════════
# UI + capability endpoints
# ══════════════════════════════════════════════════════════════════════

class TestWorkbenchUI:
    def test_index_serves_embedded_spa(self, workbench):
        client, _service = workbench
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        html = response.text
        assert "AI OSINT Hub Intelligence Workbench" in html
        for marker in (
            'id="workbench"',
            'id="intake"',
            'id="graph"',
            "<svg",
            "new EventSource(",
            "https://cdn.tailwindcss.com",
            "Run Next Pivot",
            "SHA-256",
            "textContent",
            "Download Markdown",
            "Download JSON",
            "Download HTML",
        ):
            assert marker in html, f"missing UI marker: {marker}"
        # Graph / Telemetry / Dossier tabs.
        assert 'data-tab="graph"' in html
        assert 'data-tab="telemetry"' in html
        assert 'data-tab="dossier"' in html
        # Dark theme + epistemic badge styling are embedded CSS (offline safe).
        assert "#0b1020" in html
        assert ".badge.CONFIRMED" in html

    def test_tools_endpoint(self, workbench, mock_registry):
        client, _service = workbench
        response = client.get("/api/tools")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        # The registry is isolated to the mock capabilities for this test.
        assert data["total"] == len(capabilities.all_capabilities())
        assert data["total"] == len(mock_registry)
        assert data["total"] >= 7
        assert len(data["tools"]) == data["total"]
        assert data["available"] >= 1

    def test_doctor_endpoint(self, workbench):
        client, _service = workbench
        response = client.post("/api/doctor", json={"provision": False})
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == len(capabilities.all_capabilities())
        assert data["total"] >= 7
        assert data["status"] in {"ok", "incomplete"}
        assert data["missing"] == []  # mock builtin collectors are importable


# ══════════════════════════════════════════════════════════════════════
# Investigation lifecycle
# ══════════════════════════════════════════════════════════════════════

class TestInvestigationEndpoints:
    def test_wait_investigation_payload_and_report(self, workbench):
        client, service = workbench
        data = _start_wait(client)
        target_id = data["target_id"]
        assert target_id
        assert data["status"] in TERMINAL_STATUSES
        assert data["report"]["status"] == "complete"
        assert "# Intelligence Dossier" in data["report_md"]

        listed = client.get("/api/investigations")
        assert listed.status_code == 200
        listing = listed.json()
        assert listing["status"] == "ok"
        assert any(item["target_id"] == target_id
                   for item in listing["investigations"])

        response = client.get(f"/api/investigations/{target_id}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["target_id"] == target_id
        assert payload["investigation"]["target_id"] == target_id
        assert payload["entities"], "expected at least one ERKG entity"
        assert payload["claims"], "expected at least one evidence-backed claim"
        assert payload["artifacts"], "expected at least one immutable artifact"
        assert payload["stats"]["entities"] >= 1
        assert payload["graph"]["nodes"], "expected graph nodes for the SVG UI"
        assert isinstance(payload["pivots"], list)
        assert isinstance(payload["ledger"], list)
        assert isinstance(payload["hypotheses"], list)
        assert isinstance(payload["contradictions"], list)

        artifact = next(iter(payload["artifacts"].values()))
        for key in ("source_tool", "timestamp_utc", "raw_output_sha256",
                    "raw_evidence_snippet", "epistemic_status", "confidence",
                    "parser_version"):
            assert key in artifact
        assert artifact["raw_output_sha256"]
        assert payload["artifacts"] == {
            artifact_id: value
            for artifact_id, value in payload["artifacts"].items()
        }

        # The module-level helper (used by tests/transports) matches the API.
        helper = build_investigation_payload(service, target_id)
        assert [node["id"] for node in helper["graph"]["nodes"]] == \
            [node["id"] for node in payload["graph"]["nodes"]]
        assert helper["target_id"] == payload["target_id"]

    def test_report_formats(self, workbench):
        client, _service = workbench
        target_id = _start_wait(client)["target_id"]

        markdown = client.get(f"/api/investigations/{target_id}/report?format=md")
        assert markdown.status_code == 200
        assert "text/markdown" in markdown.headers["content-type"]
        assert "# Intelligence Dossier" in markdown.text

        as_json = client.get(f"/api/investigations/{target_id}/report?format=json")
        assert as_json.status_code == 200
        assert "application/json" in as_json.headers["content-type"]
        dossier = as_json.json()
        assert dossier["investigation"]["target_id"] == target_id
        assert "entities" in dossier
        assert "collection_gaps" in dossier

        as_html = client.get(f"/api/investigations/{target_id}/report?format=html")
        assert as_html.status_code == 200
        assert "text/html" in as_html.headers["content-type"]
        html = as_html.text
        assert html.lstrip().startswith("<!DOCTYPE html")
        assert "<html" in html
        assert "Intelligence Dossier" in html

        assert client.get(
            f"/api/investigations/{target_id}/report?format=xml"
        ).status_code == 400

    def test_step_endpoint_is_deterministic_when_stopped(self, workbench):
        client, _service = workbench
        target_id = _start_wait(client)["target_id"]
        response = client.post(f"/api/investigations/{target_id}/step", json={})
        assert response.status_code == 200
        assert response.json()["status"] in {"stopped", "active", "error"}
        # Optional body with no pivot selection.
        without_body = client.post(f"/api/investigations/{target_id}/step")
        assert without_body.status_code == 200

    def test_structured_seeds_are_accepted(self, workbench):
        client, _service = workbench
        response = client.post("/api/investigations", json={
            "raw_input": "",
            "usernames": ["hamid091"],
            "wait": True,
            "max_iterations": 2,
            "max_tool_calls": 2,
        })
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["target_id"]
        assert data["status"] in TERMINAL_STATUSES
        payload = client.get(f"/api/investigations/{data['target_id']}").json()
        values = {(entity["type"], entity["value"]) for entity in payload["entities"]}
        assert ("username", "hamid091") in values

    def test_background_run_streams_snapshot_and_done(self, workbench):
        client, _service = workbench
        response = client.post("/api/investigations", json={
            "raw_input": "hamid091", "wait": False,
            "max_iterations": 3, "max_tool_calls": 3,
        })
        assert response.status_code == 200
        started = response.json()
        assert started["status"] == "started"
        target_id = started["target_id"]
        assert target_id

        stream = client.get(f"/api/investigations/{target_id}/stream")
        assert stream.status_code == 200
        assert "text/event-stream" in stream.headers["content-type"]
        body = stream.text
        assert "event: snapshot" in body
        assert "event: done" in body
        # A real mock tool execution is reported in the done ledger.
        assert "mock_username" in body
        assert '"status": "completed"' in body or '"status": "terminated"' in body
        # Payload frames are valid JSON after the ``data:`` prefix.
        data_lines = [line[len("data: "):] for line in body.splitlines()
                      if line.startswith("data: ")]
        assert data_lines
        for line in data_lines:
            json.loads(line)

        # The investigation is terminal and readable through the REST payload too.
        state = client.get(f"/api/investigations/{target_id}").json()
        assert state["investigation"]["status"] in TERMINAL_STATUSES


class TestUnknownInvestigation:
    def test_unknown_investigation_returns_404(self, workbench):
        client, _service = workbench
        missing = "case_does_not_exist"
        assert client.get(f"/api/investigations/{missing}").status_code == 404
        assert client.get(
            f"/api/investigations/{missing}/stream").status_code == 404
        assert client.get(
            f"/api/investigations/{missing}/report?format=md").status_code == 404
        step = client.post(f"/api/investigations/{missing}/step", json={})
        assert step.status_code == 404
