"""Tests for Gruvbox Material Light workbench, Cytoscape vendor asset, XSS/CSP & new endpoints."""

from __future__ import annotations

import io
import json
import re

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from hub.investigation.engine import InvestigationEngine
from hub.models import EntityType
from hub.reporting import build_dossier, render_html
from hub.security.redaction import clear_secrets
from hub.service import InvestigationService
from hub.web import WORKBENCH_HTML, create_app
from tests import support
from tests.mock_tools import MockRunner, empty_output, identity_output, make_capability, parse_mock


@pytest.fixture()
def mock_workbench(tmp_path, tmp_hub_home, isolated_mock_registry):
    caps = [
        make_capability("mock_u", [EntityType.USERNAME], [EntityType.SOCIAL_PROFILE], prior_yield=0.95),
        make_capability("mock_e", [EntityType.EMAIL], [EntityType.SERVICE], prior_yield=0.85),
        make_capability("mock_d", [EntityType.DOMAIN], [EntityType.IP], prior_yield=0.75),
    ]
    isolated_mock_registry(*caps)

    def run_fn(cap, params):
        if cap.tool_id == "mock_u":
            return identity_output(EntityType.SOCIAL_PROFILE, "https://github.com/alice")
        if cap.tool_id == "mock_e":
            return identity_output(EntityType.SERVICE, "github")
        return empty_output()

    def engine_factory():
        return InvestigationEngine(
            runner=MockRunner(default=run_fn),
            parser_resolver=lambda cap: parse_mock,
            health_probe=lambda cap: True,
            state_root=tmp_path / "state",
        )

    service = InvestigationService(engine_factory=engine_factory)
    app = create_app(service)
    with TestClient(app) as client:
        yield client, service


def test_gruvbox_material_light_default_no_glassmorphism_and_no_innerhtml():
    assert "#fbf1c7" in WORKBENCH_HTML
    assert "#3c3836" in WORKBENCH_HTML
    assert "#af3a03" in WORKBENCH_HTML
    assert "backdrop-filter" not in WORKBENCH_HTML.lower()
    assert "innerHTML" not in WORKBENCH_HTML
    assert "outerHTML" not in WORKBENCH_HTML
    assert "insertAdjacentHTML" not in WORKBENCH_HTML
    # First <script> is main workbench JS; Cytoscape loads deferred afterwards
    scripts = re.findall(r"<script\b[^>]*>", WORKBENCH_HTML, flags=re.IGNORECASE)
    assert len(scripts) >= 2
    assert "src=" not in scripts[0]
    assert "/static/vendor/cytoscape.min.js" in WORKBENCH_HTML


def test_cytoscape_vendor_asset_served(mock_workbench):
    client, _ = mock_workbench
    res = client.get("/static/vendor/cytoscape.min.js")
    assert res.status_code == 200
    assert "javascript" in res.headers.get("content-type", "").lower()
    assert len(res.content) > 50_000
    assert "cytoscape" in res.text.lower()


def test_new_analytics_timeline_diff_step_batch_endpoints(mock_workbench):
    client, _ = mock_workbench
    inv_a = client.post(
        "/api/investigations",
        json={
            "raw_input": "",
            "usernames": ["alice"],
            "emails": ["alice@example.org"],
            "wait": True,
            "max_iterations": 2,
            "max_tool_calls": 2,
        },
    ).json()
    id_a = inv_a["target_id"]

    inv_b = client.post(
        "/api/investigations",
        json={
            "raw_input": "",
            "usernames": ["alice"],
            "domains": ["example.org"],
            "wait": False,
            "max_iterations": 4,
            "max_tool_calls": 4,
        },
    ).json()
    id_b = inv_b["target_id"]

    # Wait-less investigation may run in background; test step-batch directly on a fresh case
    analytics = client.get(f"/api/investigations/{id_a}/analytics")
    assert analytics.status_code == 200
    a_json = analytics.json()
    assert a_json["status"] == "ok"
    assert "degree_centrality" in a_json
    assert "betweenness_centrality" in a_json

    timeline = client.get(f"/api/investigations/{id_a}/timeline")
    assert timeline.status_code == 200
    t_json = timeline.json()
    assert t_json["status"] == "ok"
    assert t_json["events"]

    diff = client.get(f"/api/investigations/{id_a}/diff/{id_b}")
    assert diff.status_code == 200
    d_json = diff.json()
    assert d_json["status"] == "ok"
    assert "summary" in d_json

    batch = client.post(f"/api/investigations/{id_a}/step-batch", json={"max_pivots": 2})
    assert batch.status_code == 200
    assert batch.json()["target_id"] == id_a


def test_ai_status_config_reflect_and_media_endpoints(mock_workbench, monkeypatch):
    client, _ = mock_workbench
    clear_secrets()
    try:
        secret = "sk-deepseek-web-secret-123456"
        st0 = client.get("/api/ai/status")
        assert st0.status_code == 200
        assert st0.json()["enabled"] is False

        upd = client.post(
            "/api/ai/config",
            json={"enabled": True, "provider": "deepseek", "api_key": secret},
        )
        assert upd.status_code == 200
        upd_json = upd.json()
        assert upd_json["provider"] == "deepseek"
        assert secret not in json.dumps(upd_json)

        st1 = client.get("/api/ai/status").json()
        assert secret not in json.dumps(st1)
        assert st1["credentials"]["deepseek"]["configured"] is True

        # Reset to disabled before reflect so reflect returns clean disabled status offline
        client.post("/api/ai/config", json={"enabled": False, "provider": "disabled"})

        inv = client.post(
            "/api/investigations",
            json={"raw_input": "alice99", "wait": True, "max_iterations": 1, "max_tool_calls": 1},
        ).json()
        tid = inv["target_id"]
        refl = client.post(f"/api/investigations/{tid}/reflect", json={})
        assert refl.status_code == 200
        assert refl.json()["status"] == "disabled"

        # SSRF block via /api/media/analyze
        ssrf = client.post("/api/media/analyze", json={"url": "http://169.254.169.254/latest/meta-data/", "use_vlm": False})
        assert ssrf.status_code == 200
        assert ssrf.json()["ok"] is False
        assert ssrf.json()["error_code"] == "SCOPE_BLOCKED"

        # Mocked PNG fetch via /api/media/analyze
        buf = io.BytesIO()
        Image.new("RGB", (32, 32), (120, 80, 40)).save(buf, format="PNG")
        png_bytes = buf.getvalue()
        real_client = httpx.AsyncClient

        def mock_factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(
                lambda req: httpx.Response(200, content=png_bytes, headers={"content-type": "image/png"})
            )
            return real_client(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", mock_factory)
        ok_media = client.post("/api/media/analyze", json={"url": "https://93.184.216.34/avatar.png", "use_vlm": False})
        assert ok_media.status_code == 200
        assert ok_media.json()["ok"] is True
        assert ok_media.json()["forensics"]["format"] == "PNG"
    finally:
        clear_secrets()


def test_html_dossier_gruvbox_csp_and_xss_escaping(store_factory, mock_workbench):
    client, service = mock_workbench
    xss_payload = '<script>alert("xss")</script><img src=x onerror=alert(1)>'

    # 1. Direct build_dossier + render_html with AI insight containing XSS & wrapper escape
    store = store_factory()
    support.bootstrap(store, "xss-inv", raw_input=xss_payload)
    ent = support.entity(store, EntityType.USERNAME, "alice")
    art = support.artifact(store, "sherlock", snippet=f"bio {xss_payload}")
    store.upsert_claim("xss-inv", ent.entity_id, "ASSOCIATED_WITH", object_literal=xss_payload,
                       artifact_id=art, source_tool="sherlock", snippet=xss_payload)
    store.add_ai_insight(
        "xss-inv",
        provider="ollama",
        model="gemma4",
        kind="reflection",
        summary=f"Insight {xss_payload}",
        cited_artifact_ids=[art],
        epistemic_provenance="AI_INFERRED",
    )
    dossier = build_dossier(store, "xss-inv", generated_at="2026-11-27T00:00:00+00:00")
    html = render_html(dossier)
    assert "#fbf1c7" in html
    assert "#3c3836" in html
    assert "#af3a03" in html
    assert "AI-Assisted Reflection" in html
    assert "AI_INFERRED" in html
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html

    # 2. HTTP /report?format=html serves CSP header blocking inline scripts
    resp_create = client.post(
        "/api/investigations",
        json={
            "raw_input": f"alice {xss_payload}",
            "usernames": ["alice"],
            "wait": True,
            "max_iterations": 1,
            "max_tool_calls": 1,
        },
    )
    assert resp_create.status_code == 200, resp_create.text
    created = resp_create.json()
    resp = client.get(f"/api/investigations/{created['target_id']}/report?format=html")
    assert resp.status_code == 200
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'none'" in csp
    assert "<script>alert" not in resp.text
