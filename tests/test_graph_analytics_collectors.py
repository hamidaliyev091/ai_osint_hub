"""Deterministic offline tests for ERKG analytics, parallel pivots, new collectors & MCP App."""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest

from hub.erkg.analytics import (
    analyze_graph,
    betweenness_centrality,
    build_timeline,
    connected_components,
    correlate_perceptual_hashes,
    degree_centrality,
    diff_investigations,
    find_bridges,
    label_propagation_communities,
    shortest_path,
)
from hub.investigation.engine import InvestigationEngine
from hub.models import (
    EdgeType,
    EntityType,
    ErrorCode,
    ExecutionRecord,
    ExecutionStatus,
    ScopeConfig,
    utc_now,
)
from hub.tools import capabilities
from hub.tools.builtin import asn_bgp_lookup, crtsh_lookup, favicon_hash
from hub.tools.builtin.favicon_hash import mmh3_x86_32, shodan_favicon_hash
from hub.tools.parsers import (
    asn_bgp_lookup as asn_parser,
    crtsh_lookup as crtsh_parser,
    favicon_hash as favicon_parser,
)
from tests import support
from tests.mock_tools import MockRunner, identity_output, make_capability, parse_mock


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _mock_httpx_client(monkeypatch, handler):
    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return _REAL_ASYNC_CLIENT(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


# ════════════════════════════════════════════════════════════════════════
# 1. Graph analytics: centrality, clusters, bridges, shortest path, hash correlation
# ════════════════════════════════════════════════════════════════════════

def test_centrality_clusters_bridges_and_shortest_path(store_factory):
    store = store_factory()
    support.bootstrap(store)
    # Build two triangles joined by a single bridge edge b1 -- b2:
    # {a1, a2, b1} -- {b2, c1, c2}
    a1 = support.entity(store, EntityType.USERNAME, "a1")
    a2 = support.entity(store, EntityType.EMAIL, "a2@example.com")
    b1 = support.entity(store, EntityType.DOMAIN, "b1.example.com")
    b2 = support.entity(store, EntityType.IP, "93.184.216.34")
    c1 = support.entity(store, EntityType.ASN, "AS15133")
    c2 = support.entity(store, EntityType.ORGANIZATION, "Edgecast")
    isolated = support.entity(store, EntityType.PHONE, "+14155550199")
    support.set_seeds(store, [a1.entity_id])

    support.claim(store, a1.entity_id, "ASSOCIATED_WITH", object_id=a2.entity_id, tools=("sherlock", "maigret"))
    support.claim(store, a2.entity_id, "ASSOCIATED_WITH", object_id=b1.entity_id, tools=("holehe",))
    support.claim(store, a1.entity_id, "ASSOCIATED_WITH", object_id=b1.entity_id, tools=("github_osint",))
    # Bridge edge b1 -> b2
    bridge_claim = support.claim(store, b1.entity_id, "RESOLVES_TO", object_id=b2.entity_id, tools=("dns_lookup", "tls_cert"))
    support.claim(store, b2.entity_id, "ASSOCIATED_WITH", object_id=c1.entity_id, tools=("asn_bgp_lookup",))
    support.claim(store, c1.entity_id, "REGISTERED_BY", object_id=c2.entity_id, tools=("asn_bgp_lookup",))
    support.claim(store, b2.entity_id, "ASSOCIATED_WITH", object_id=c2.entity_id, tools=("rdap_lookup",))

    graph = support.graph(store, [a1.entity_id])
    deg = degree_centrality(graph)
    betw = betweenness_centrality(graph)
    # b1 and b2 have highest betweenness because all cross-triangle paths cross (b1, b2)
    assert betw[b1.entity_id] > betw[a1.entity_id]
    assert betw[b2.entity_id] > betw[c1.entity_id]
    assert deg[b1.entity_id] > deg[isolated.entity_id]

    comps = connected_components(graph)
    assert len(comps) == 2
    assert len(comps[0]) == 6
    assert comps[1] == [isolated.entity_id]

    communities = label_propagation_communities(graph)
    assert len(communities) >= 2

    bridges = find_bridges(graph, communities=communities)
    assert b1.entity_id in bridges["bridge_entities"]
    assert b2.entity_id in bridges["bridge_entities"]
    assert any(
        {e["source"], e["target"]} == {b1.entity_id, b2.entity_id}
        for e in bridges["bridge_edges"]
    )

    sp = shortest_path(graph, a1.entity_id, c2.entity_id)
    assert sp["found"] is True
    assert sp["length"] == 3  # a1 -> b1 -> b2 -> c2
    assert sp["path"][0] == a1.entity_id
    assert sp["path"][-1] == c2.entity_id
    assert any(edge["claim_id"] == bridge_claim.claim_id and edge["artifact_ids"] for edge in sp["edges"])

    full = analyze_graph(graph, source_id=a1.entity_id, dest_id=c2.entity_id)
    assert full["summary"]["nodes"] == 7
    assert full["summary"]["components"] == 2
    assert full["shortest_path"]["found"] is True


def test_perceptual_hash_correlation(store_factory):
    store = store_factory()
    support.bootstrap(store)
    u1 = support.entity(
        store, EntityType.URL, "https://a.example/img1.png",
        metadata={"phash": "ff00ff00ff00ff00", "mmh3": "-123456"},
    )
    u2 = support.entity(
        store, EntityType.URL, "https://b.example/img2.png",
        metadata={"phash": "ff00ff00ff00ff03", "mmh3": "-123456"},  # Hamming distance 2
    )
    u3 = support.entity(
        store, EntityType.URL, "https://c.example/other.png",
        metadata={"phash": "00ff00ff00ff00ff", "mmh3": "999999"},
    )
    graph = support.graph(store, [u1.entity_id])
    clusters = correlate_perceptual_hashes(graph, max_hamming=6)
    assert len(clusters) == 1
    assert set(clusters[0]["entity_ids"]) == {u1.entity_id, u2.entity_id}
    assert u3.entity_id not in clusters[0]["entity_ids"]
    assert set(clusters[0]["hash_kinds"]) >= {"mmh3", "phash"}


# ════════════════════════════════════════════════════════════════════════
# 2. Timeline & Two-Case Diffing
# ════════════════════════════════════════════════════════════════════════

def test_timeline_and_two_case_diffing(store_factory):
    store = store_factory("a.sqlite3")
    support.bootstrap(store, "case-a", raw_input="example.com")
    e_dom = support.entity(store, EntityType.DOMAIN, "example.com", investigation_id="case-a")
    e_old = support.entity(store, EntityType.IP, "93.184.216.34", investigation_id="case-a")
    support.claim(store, e_dom.entity_id, "RESOLVES_TO", object_id=e_old.entity_id,
                  tools=("dns_lookup",), investigation_id="case-a")
    store.record_execution(ExecutionRecord(
        investigation_id="case-a", entity_id=e_dom.entity_id, tool_id="dns_lookup",
        param_hash="p1", status=ExecutionStatus.SUCCESS, run_at=utc_now(), duration_ms=12,
    ))
    store.add_ai_insight(
        "case-a", provider="ollama", model="gemma4", kind="reflection",
        summary="AI insight summary", epistemic_provenance="AI_INFERRED",
    )

    events = build_timeline(store, "case-a")
    event_types = {ev["event_type"] for ev in events}
    assert {"seed_intake", "artifact", "ledger_run", "entity_discovered", "ai_insight"}.issubset(event_types)
    timestamps = [ev["timestamp_utc"] for ev in events]
    assert timestamps == sorted(timestamps)

    # Case B adds a second corroborating source for e_dom, adds e_new, removes e_old, and adds a contradiction
    store_b = store_factory("b.sqlite3")
    support.bootstrap(store_b, "case-b", raw_input="example.com")
    e_dom_b = support.entity(store_b, EntityType.DOMAIN, "example.com", investigation_id="case-b")
    support.entity(store_b, EntityType.SUBDOMAIN, "api.example.com", investigation_id="case-b")
    support.claim(store_b, e_dom_b.entity_id, "IDENTIFIED_AS", object_literal="example.com",
                  tools=("dns_lookup", "tls_cert"), investigation_id="case-b")
    support.claim(store_b, e_dom_b.entity_id, "HAS_ATTRIBUTE:active", object_literal=True,
                  tools=("dns_lookup",), investigation_id="case-b")
    support.claim(store_b, e_dom_b.entity_id, "HAS_ATTRIBUTE:active", object_literal=False,
                  tools=("tls_cert",), investigation_id="case-b")

    diff = diff_investigations(store, "case-a", store_b, "case-b")
    assert diff["summary"]["added_count"] == 1
    assert diff["added_entities"][0]["value"] == "api.example.com"
    assert diff["summary"]["removed_count"] == 1
    assert diff["removed_entities"][0]["value"] == "93.184.216.34"
    assert diff["summary"]["new_contradictions_count"] >= 1
    assert diff["status_changes"]


# ════════════════════════════════════════════════════════════════════════
# 3. Bounded Parallel step_batch
# ════════════════════════════════════════════════════════════════════════

def test_bounded_parallel_step_batch(tmp_path, isolated_mock_registry):
    caps = [
        make_capability("mock_u1", [EntityType.USERNAME], [EntityType.SOCIAL_PROFILE], prior_yield=0.95),
        make_capability("mock_e1", [EntityType.EMAIL], [EntityType.SERVICE], prior_yield=0.90),
        make_capability("mock_d1", [EntityType.DOMAIN], [EntityType.IP], prior_yield=0.85),
    ]
    isolated_mock_registry(*caps)

    def run_fn(cap, params):
        if cap.tool_id == "mock_u1":
            return identity_output(EntityType.SOCIAL_PROFILE, "https://github.com/alice")
        if cap.tool_id == "mock_e1":
            return identity_output(EntityType.SERVICE, "github")
        return identity_output(EntityType.IP, "93.184.216.34")

    engine = InvestigationEngine(
        runner=MockRunner(default=run_fn),
        parser_resolver=lambda cap: parse_mock,
        health_probe=lambda cap: True,
        state_root=tmp_path / "state",
    )

    async def _run():
        created = await engine.create(
            "",
            overrides={
                "max_iterations": 10,
                "max_tool_calls": 10,
                "min_pivot_threshold": 0.05,
                "parallel_pivots": 3,
            },
            structured_seeds={
                "usernames": ["alice"],
                "emails": ["alice@example.org"],
                "domains": ["example.org"],
            },
        )
        return await engine.step_batch(created.target_id, max_pivots=3)

    wave = asyncio.run(_run())
    assert wave["wave_count"] == 3
    assert len(wave["executed"]) == 3
    assert wave["stats"]["iterations"] >= 3
    assert wave["stats"]["artifacts"] >= 3
    assert wave["stats"]["ledger"]["SUCCESS"] == 3


# ════════════════════════════════════════════════════════════════════════
# 4. New Passive Collectors: crtsh_lookup, asn_bgp_lookup, favicon_hash
# ════════════════════════════════════════════════════════════════════════

def test_crtsh_collector_success_rate_limit_timeout_and_parser(monkeypatch):
    def ok_handler(request: httpx.Request) -> httpx.Response:
        assert "crt.sh" in str(request.url)
        return httpx.Response(
            200,
            json=[
                {
                    "id": 1001,
                    "common_name": "api.example.com",
                    "name_value": "api.example.com\n*.dev.example.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "not_before": "2026-01-01",
                    "not_after": "2026-04-01",
                }
            ],
        )

    _mock_httpx_client(monkeypatch, ok_handler)
    res = asyncio.run(crtsh_lookup.collect({"domain": "example.com"}, timeout_sec=5, scope=ScopeConfig()))
    assert res.exit_code == 0 and res.error_code is None
    data = json.loads(res.stdout)
    assert "api.example.com" in data["subdomains"]
    assert "dev.example.com" in data["subdomains"]
    assert "Let's Encrypt" in data["issuer_orgs"]

    parsed = crtsh_parser.parse(res.stdout, "example.com")
    assert {e.value for e in parsed.entities if e.type == EntityType.SUBDOMAIN} == {
        "api.example.com", "dev.example.com"
    }
    assert any(e.type == EntityType.ORGANIZATION and e.value == "Let's Encrypt" for e in parsed.entities)

    # 429 -> RATE_LIMITED
    _mock_httpx_client(monkeypatch, lambda req: httpx.Response(429, text="rate limited"))
    rl = asyncio.run(crtsh_lookup.collect({"domain": "example.com"}, timeout_sec=5, scope=ScopeConfig()))
    assert rl.error_code == ErrorCode.RATE_LIMITED

    # 503 -> TIMEOUT
    _mock_httpx_client(monkeypatch, lambda req: httpx.Response(503, text="bad gateway"))
    gw = asyncio.run(crtsh_lookup.collect({"domain": "example.com"}, timeout_sec=5, scope=ScopeConfig()))
    assert gw.error_code == ErrorCode.TIMEOUT


def test_asn_bgp_collector_ripestat_bgpview_fallback_and_ssrf(monkeypatch):
    def ripestat_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "network-info" in url:
            return httpx.Response(200, json={"data": {"asns": ["13335"], "prefix": "1.1.1.0/24"}})
        if "as-overview" in url:
            return httpx.Response(200, json={"data": {"holder": "CLOUDFLARENET", "block": {"name": "ARIN"}}})
        if "whois" in url:
            return httpx.Response(200, json={"data": {"records": [[{"key": "country", "value": "US"}]], "authority": "ARIN"}})
        return httpx.Response(404)

    _mock_httpx_client(monkeypatch, ripestat_handler)
    res = asyncio.run(asn_bgp_lookup.collect({"ip": "1.1.1.1"}, timeout_sec=5, scope=ScopeConfig()))
    assert res.exit_code == 0 and res.error_code is None
    parsed = asn_parser.parse(res.stdout, "1.1.1.1")
    types = {e.type for e in parsed.entities}
    assert {EntityType.IP, EntityType.ASN, EntityType.ORGANIZATION, EntityType.LOCATION}.issubset(types)

    # BGPView fallback when RIPEstat returns 500
    def fallback_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "stat.ripe.net" in url:
            return httpx.Response(500)
        return httpx.Response(
            200,
            json={
                "data": {
                    "rir_allocation": {"rir_name": "RIPE", "country_code": "DE"},
                    "prefixes": [{"prefix": "93.184.216.0/24", "asn": {"asn": 15133, "name": "EDGECAST", "country_code": "US"}}],
                }
            },
        )

    _mock_httpx_client(monkeypatch, fallback_handler)
    fb = asyncio.run(asn_bgp_lookup.collect({"ip": "93.184.216.34"}, timeout_sec=5, scope=ScopeConfig()))
    assert fb.exit_code == 0
    assert json.loads(fb.stdout)["source"] == "bgpview"

    # SSRF block on loopback & metadata IP
    for blocked in ("127.0.0.1", "169.254.169.254", "10.0.0.1"):
        out = asyncio.run(asn_bgp_lookup.collect({"ip": blocked}, timeout_sec=5, scope=ScopeConfig()))
        assert out.exit_code != 0
        assert out.error_code == ErrorCode.SCOPE_BLOCKED


def test_favicon_hash_mmh3_exact_vector_fallback_and_ssrf(monkeypatch):
    # Canonical MurmurHash3_x86_32 test vectors (verified signed 32-bit ints):
    assert mmh3_x86_32(b"", seed=0) == 0
    assert mmh3_x86_32(b"hello", seed=0) == 613153351
    assert mmh3_x86_32(b"test", seed=0) == -1167338989
    assert mmh3_x86_32(b"The quick brown fox jumps over the lazy dog", seed=0) == 776992547
    sample_bytes = b"SYNTHETIC_FAVICON_BYTES_FOR_SHODAN_MMH3_TEST"
    encoded = base64.encodebytes(sample_bytes)
    expected_mmh3 = mmh3_x86_32(encoded, seed=0)
    assert isinstance(expected_mmh3, int)
    assert -0x80000000 <= expected_mmh3 <= 0x7FFFFFFF
    assert shodan_favicon_hash(sample_bytes) == expected_mmh3

    # Mock /favicon.ico 404 -> fallback to <link rel="icon" href="/assets/app.ico">
    def icon_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/favicon.ico"):
            return httpx.Response(404)
        if url == "https://93.184.216.34/":
            html = '<html><head><link rel="shortcut icon" href="/assets/app.ico"></head></html>'
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        if url == "https://93.184.216.34/assets/app.ico":
            return httpx.Response(200, content=sample_bytes, headers={"content-type": "image/x-icon"})
        return httpx.Response(404)

    _mock_httpx_client(monkeypatch, icon_handler)
    res = asyncio.run(favicon_hash.collect({"target": "93.184.216.34"}, timeout_sec=5, scope=ScopeConfig()))
    assert res.exit_code == 0 and res.error_code is None
    payload = json.loads(res.stdout)
    assert payload["found"] is True
    assert payload["mmh3"] == expected_mmh3
    assert payload["url"] == "https://93.184.216.34/assets/app.ico"

    parsed = favicon_parser.parse(res.stdout, "93.184.216.34")
    types = {e.type for e in parsed.entities}
    assert {EntityType.HASH, EntityType.SERVICE, EntityType.URL}.issubset(types)
    assert any(e.value == f"mmh3:{expected_mmh3}" for e in parsed.entities)

    # SSRF block on 127.0.0.1 and 169.254.169.254
    for blocked in ("127.0.0.1", "169.254.169.254"):
        blk = asyncio.run(favicon_hash.collect({"target": blocked}, timeout_sec=5, scope=ScopeConfig()))
        assert blk.error_code == ErrorCode.SCOPE_BLOCKED


# ════════════════════════════════════════════════════════════════════════
# 5. Registry 32 Tools & MCP Server Tools + ui:// App Resource
# ════════════════════════════════════════════════════════════════════════

def test_registry_has_32_tools_and_mcp_exposes_new_tools_and_ui_resource(tmp_hub_home):
    tool_ids = set(capabilities.list_tools())
    assert len(tool_ids) == 32
    assert {"crtsh_lookup", "asn_bgp_lookup", "favicon_hash", "media_forensics"}.issubset(tool_ids)

    import hub.mcp_server as server

    mcp_tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in mcp_tools}
    assert {"analytics", "timeline", "diff_cases", "ai_reflect", "open_workbench_view"}.issubset(names)

    # Empty {} launch works cleanly
    view = server.open_workbench_view()
    assert view["status"] == "ok"
    assert "investigations" in view

    # ui:// resource and SEP-1865 _meta check
    resources = asyncio.run(server.mcp.list_resources())
    ui_res = [r for r in resources if str(r.uri) == server.WORKBENCH_UI_URI]
    assert len(ui_res) == 1
    assert ui_res[0].mimeType == "text/html;profile=mcp-app"

    html = server.workbench_ui()
    assert "#fbf1c7" in html
    assert "#3c3836" in html
    assert "#af3a03" in html
    assert "innerHTML" not in html

    wb_tool = next(t for t in mcp_tools if t.name == "open_workbench_view")
    assert wb_tool.meta["ui"]["resourceUri"] == server.WORKBENCH_UI_URI
    assert "com.google.antigravity/ui" in wb_tool.meta
