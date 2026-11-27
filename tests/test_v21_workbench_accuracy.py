"""v2.1 offline accuracy, visual harvesting, simplified AI, and Workbench UI tests."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import sys
import types
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin

from hub.ai.config import load_ai_config, update_ai_config
from hub.ai.embeddings import embed_fastembed_texts, fastembed_availability
from hub.ai.models import AI_PRESETS_CATALOG, AIConfig, AIProviderKind
from hub.ai.reflection_runner import run_case_reflection
from hub.bundle import export_case_bundle, import_case_bundle
from hub.demo import DEMO_TARGET_ID, seed_demo_case
from hub.erkg.ingestion import EvidenceIngestor
from hub.erkg.resolution import (
    derive_entity_drafts,
    is_noreply_email,
    is_provider_infrastructure_domain,
)
from hub.erkg.store import ERKGStore
from hub.intake import MultiClueIntake, StructuredSeeds
from hub.investigation.engine import InvestigationEngine
from hub.investigation.pivot import PivotScorer
from hub.models import (
    EdgeType,
    Entity,
    EntityType,
    EpistemicStatus,
    EvidenceArtifact,
    ExecutionRecord,
    ExecutionStatus,
    InvestigationConfig,
    InvestigationState,
    RunStatus,
    ScopeConfig,
    is_functional_predicate,
    utc_now,
)
from hub.reporting import build_dossier, render_html, render_markdown
from hub.service import InvestigationService
from hub.toolchain.doctor import run_doctor
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate
from hub.tools.capabilities import export_cli_table_rows, reset_registry
from hub.tools.parsers import github_osint, maigret, phoneinfoga, sherlock
from hub.tools.visual_harvester import (
    MAX_VISUAL_BYTES,
    extract_visual_candidates,
    fetch_and_save_visual,
    validate_image_bytes,
)
from hub.web import WORKBENCH_HTML, create_app
from tests import support as support

INV = "inv-v21-test"


def _png_bytes(color: tuple[int, int, int] = (37, 99, 235), *, software: str = "") -> bytes:
    img = Image.new("RGB", (64, 64), color)
    for y in range(64):
        for x in range(64):
            if (x // 8 + y // 8) % 2 == 0:
                img.putpixel((x, y), (248, 250, 252))
    buf = io.BytesIO()
    if software:
        info = PngImagePlugin.PngInfo()
        info.add_text("Software", software)
        img.save(buf, format="PNG", pnginfo=info)
    else:
        img.save(buf, format="PNG")
    return buf.getvalue()


def _make_store(tmp_path: Path, target_id: str = INV) -> ERKGStore:
    store = ERKGStore(tmp_path / f"{target_id}.sqlite")
    now = utc_now()
    state = InvestigationState(
        target_id=target_id,
        raw_input="Hamid Aliyev",
        created_at=now,
        updated_at=now,
        config=InvestigationConfig(target_id=target_id, raw_input="Hamid Aliyev"),
    )
    store.create_investigation(state)
    return store


def _add_artifact(store: ERKGStore, tool: str = "github_osint", suffix: str = "1") -> str:
    art_id = f"art_{tool}_{suffix}"
    store.add_artifact(EvidenceArtifact(
        artifact_id=art_id,
        investigation_id=INV,
        source_tool=tool,
        invocation_params_hash=f"ph_{tool}_{suffix}",
        timestamp_utc=utc_now(),
        raw_evidence_snippet="fixture",
        raw_output_sha256=("b" * 60) + suffix.ljust(4, "0")[:4],
        parser_version="2.1.0",
        epistemic_status=EpistemicStatus.SINGLE_SOURCE_LEAD,
        confidence=0.80,
    ))
    return art_id


# ── 1-8. Real Live-Run OSINT Accuracy Fixes ────────────────────────────────────


class TestERKGAndParserAccuracyFixes:
    def test_has_email_multi_valued_and_noreply_tagging(self, tmp_path):
        assert is_functional_predicate("HAS_EMAIL") is False
        assert is_noreply_email("12345+alice@users.noreply.github.com") is True
        assert is_noreply_email("alice@example.org") is False

        store = _make_store(tmp_path)
        try:
            art1 = _add_artifact(store, "github_osint", "1")
            art2 = _add_artifact(store, "holehe", "2")
            subj = support.entity(store, EntityType.PERSON, "Hamid Aliyev", investigation_id=INV)
            c1 = store.upsert_claim(
                INV, subj.entity_id, "HAS_EMAIL",
                object_literal="alice.work@example.org",
                artifact_id=art1, source_tool="github_osint",
            )
            c2 = store.upsert_claim(
                INV, subj.entity_id, "HAS_EMAIL",
                object_literal="12345+alice@users.noreply.github.com",
                artifact_id=art2, source_tool="holehe",
            )
            assert store.list_contradictions(INV) == []
            assert store.get_claim(c1.claim_id).status != EpistemicStatus.CONTRADICTED
            assert store.get_claim(c2.claim_id).status != EpistemicStatus.CONTRADICTED

            clues = MultiClueIntake().extract(
                "",
                StructuredSeeds(
                    name="Alice Example",
                    emails=["12345+alice@users.noreply.github.com", "alice@gmail.com"],
                ),
            )
            extracted_usernames = {
                c.value for c in clues if c.entity_type == EntityType.USERNAME
            }
            # Noreply email must not promote email-derived username guesses
            assert "12345+alice" not in extracted_usernames
            assert "alice" in extracted_usernames
            noreply_clue = next(
                c for c in clues
                if c.entity_type == EntityType.EMAIL
                and c.value == "12345+alice@users.noreply.github.com"
            )
            assert noreply_clue.metadata.get("is_noreply") is True
            assert noreply_clue.metadata.get("provider_infrastructure") is True
            drafts, _ = derive_entity_drafts(
                EntityType.EMAIL,
                "12345+alice@users.noreply.github.com",
            )
            # Parenthetical domain must NEVER appear as both DOMAIN and SUBDOMAIN
            domain_types = [(d.entity_type, d.canonical_value, d.metadata) for d in drafts]
            assert any(
                t == EntityType.SUBDOMAIN
                and v == "users.noreply.github.com"
                and meta.get("provider_infrastructure") is True
                for t, v, meta in domain_types
            )
            assert not any(
                t == EntityType.DOMAIN and v == "users.noreply.github.com"
                for t, v, _ in domain_types
            )
        finally:
            store.close()

    def test_duplicate_person_unification_merges_seed_and_github_person(self, tmp_path):
        store = _make_store(tmp_path)
        try:
            art_seed = _add_artifact(store, "seed", "0")
            seed_person = support.entity(
                store,
                EntityType.PERSON,
                "Hamid Aliyev",
                investigation_id=INV,
                artifact_id=art_seed,
                metadata={"provenance": "USER_PROVIDED_SEED"},
            )
            support.set_seeds(store, [seed_person.entity_id], investigation_id=INV)

            ingestor = EvidenceIngestor(store)
            # Ingest seed username relation linking Hamid Aliyev -> handle `hamid091`
            art1 = _add_artifact(store, "seed", "1")
            ingestor.ingest(
                INV,
                ParseOutput(
                    entities=[
                        EntityCandidate(type=EntityType.USERNAME, value="hamid091", confidence=0.95),
                    ],
                    relations=[
                        RelationCandidate(
                            subject_type=EntityType.PERSON,
                            subject_value="Hamid Aliyev",
                            predicate=EdgeType.HAS_USERNAME,
                            object_type=EntityType.USERNAME,
                            object_value="hamid091",
                            confidence=0.95,
                        )
                    ],
                ),
                artifact_id=art1,
                tool_id="seed",
                accepted_types=[EntityType.PERSON, EntityType.USERNAME],
                timestamp=utc_now(),
            )
            # Now GitHub collector emits a differently named Person ("Hamid") sharing `hamid091`
            art2 = _add_artifact(store, "github_osint", "2")
            ingestor.ingest(
                INV,
                ParseOutput(
                    entities=[
                        EntityCandidate(type=EntityType.PERSON, value="Hamid", confidence=0.90),
                        EntityCandidate(type=EntityType.USERNAME, value="hamid091", confidence=0.95),
                        EntityCandidate(type=EntityType.REPOSITORY, value="github.com/hamid091/ai_osint_hub", confidence=0.95),
                    ],
                    relations=[
                        RelationCandidate(
                            subject_type=EntityType.PERSON,
                            subject_value="Hamid",
                            predicate=EdgeType.HAS_USERNAME,
                            object_type=EntityType.USERNAME,
                            object_value="hamid091",
                            confidence=0.95,
                        ),
                        RelationCandidate(
                            subject_type=EntityType.PERSON,
                            subject_value="Hamid",
                            predicate=EdgeType.OWNS,
                            object_type=EntityType.REPOSITORY,
                            object_value="github.com/hamid091/ai_osint_hub",
                            confidence=0.95,
                        ),
                    ],
                ),
                artifact_id=art2,
                tool_id="github_osint",
                accepted_types=[EntityType.PERSON, EntityType.USERNAME, EntityType.REPOSITORY],
                timestamp=utc_now(),
            )
            persons = store.list_entities(INV, types=[EntityType.PERSON])
            assert len(persons) == 1
            assert persons[0].entity_id == seed_person.entity_id
            claims = store.list_claims(INV)
            assert any(
                c.predicate == EdgeType.OWNS.value and c.subject_id == seed_person.entity_id
                for c in claims
            )
        finally:
            store.close()

    def test_github_osint_filters_bot_committers(self):
        payload = json.dumps({
            "query": {"username": "octocat"},
            "user": {"login": "octocat", "name": "The Octocat", "html_url": "https://github.com/octocat"},
            "users": [
                {"login": "web-flow", "name": "GitHub", "html_url": "https://github.com/web-flow"},
                {"login": "dependabot[bot]", "html_url": "https://github.com/apps/dependabot"},
                {"login": "github-actions[bot]", "html_url": "https://github.com/apps/github-actions"},
                {"login": "renovate[bot]", "html_url": "https://github.com/apps/renovate"},
            ],
            "emails": [
                {"email": "noreply@github.com", "name": "web-flow"},
                {"email": "octocat@example.org", "name": "The Octocat"},
            ],
            "repos": [],
        })
        out = github_osint.parse(payload, target="octocat")
        values_lower = {e.value.lower() for e in out.entities}
        for bot in ("web-flow", "dependabot[bot]", "github-actions[bot]", "renovate[bot]", "noreply@github.com"):
            assert bot not in values_lower
        assert "octocat@example.org" in values_lower

    def test_sherlock_and_maigret_reject_generic_paths_and_mismatches(self):
        sherlock_stdout = "\n".join([
            "[+] HuntingRu: https://hunting.ru/members",
            "[+] GenericLogin: https://example.org/login",
            "[+] MismatchSite: https://example.net/someoneelse",
            "[+] GitHub: https://github.com/alice_dev",
        ])
        s_out = sherlock.parse(sherlock_stdout, target="alice_dev")
        s_usernames = {e.value.lower() for e in s_out.entities if e.type == EntityType.USERNAME}
        s_profiles = {e.value.lower() for e in s_out.entities if e.type == EntityType.SOCIAL_PROFILE}
        assert "members" not in s_usernames
        assert "login" not in s_usernames
        assert "https://hunting.ru/members" not in s_profiles
        assert "https://example.org/login" not in s_profiles
        assert "https://example.net/someoneelse" not in s_profiles
        assert "https://github.com/alice_dev" in s_profiles

        maigret_json = json.dumps({
            "Hunting": {"url_user": "https://hunting.ru/members", "status": "Claimed"},
            "Forum": {"url_user": "https://forum.example.org/profile", "status": "Claimed"},
            "GitLab": {"url_user": "https://gitlab.com/alice_dev", "status": "Claimed"},
        })
        m_out = maigret.parse(maigret_json, target="alice_dev")
        m_profiles = {e.value.lower() for e in m_out.entities if e.type == EntityType.SOCIAL_PROFILE}
        assert "https://hunting.ru/members" not in m_profiles
        assert "https://forum.example.org/profile" not in m_profiles
        assert "https://gitlab.com/alice_dev" in m_profiles

    def test_freemail_provider_infrastructure_and_phoneinfoga_valid_flag(self):
        assert is_provider_infrastructure_domain("gmail.com") is True
        assert is_provider_infrastructure_domain("users.noreply.github.com") is True
        assert is_provider_infrastructure_domain("prosol.example") is False

        phone_stdout = "Country: AZ\nLocal: 050 555 01 99\nE164: +994505550199\nCarrier: Azercell\n"
        p_out = phoneinfoga.parse(phone_stdout, target="+994505550199")
        phone_ents = [e for e in p_out.entities if e.type == EntityType.PHONE]
        assert phone_ents and phone_ents[0].attributes.get("valid") is True

        invalid_stdout = "Valid: false\nE164: +1555000\n"
        p_bad = phoneinfoga.parse(invalid_stdout, target="+1555000")
        bad_ents = [e for e in p_bad.entities if e.type == EntityType.PHONE]
        assert bad_ents and bad_ents[0].attributes.get("valid") is False

    def test_duplicate_github_osint_handle_suppressed_and_hydra_blocked(self, tmp_path):
        store = _make_store(tmp_path)
        try:
            u_ent = support.entity(store, EntityType.USERNAME, "hamid091", investigation_id=INV)
            scorer = PivotScorer()
            ranking = scorer.rank(
                support.graph(store, [u_ent.entity_id], investigation_id=INV),
                store.list_hypotheses(INV),
                allowed_tool_ids=["github_osint", "sherlock"],
                executed_github_handles={"hamid091"},
            )
            assert not any(p.tool_id == "github_osint" for p in ranking.all_candidates)
        finally:
            store.close()

        reset_registry(reload_builtins=True)
        rows = {row["tool_id"]: row for row in export_cli_table_rows()}
        assert "hydra" in rows
        assert rows["hydra"]["policy_blocked"] is True
        assert rows["hydra"]["ui_status"] == "blocked"
        doc = run_doctor()
        assert doc["total"] == 32
        assert 0 <= doc["available"] <= 32
        hydra_check = next(t for t in doc["tools"] if t["tool_id"] == "hydra")
        assert hydra_check["policy_blocked"] is True
        assert hydra_check["ui_status"] == "blocked"


# ── 9. SSRF-Safe Visual Harvesting & Bundle Media ──────────────────────────────


class TestVisualHarvesterAndBundleMedia:
    def test_ssrf_and_payload_guards(self, tmp_path):
        # SVG and HTML must be rejected even if labelled as image
        ok_svg, reason_svg, _, _ = validate_image_bytes(
            b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
            content_type="image/svg+xml",
        )
        assert not ok_svg and "svg" in reason_svg.lower()

        ok_big, reason_big, _, _ = validate_image_bytes(b"x" * (MAX_VISUAL_BYTES + 1))
        assert not ok_big and "MAX_VISUAL_BYTES" in reason_big

        # Private / loopback URLs rejected by SSRF guard before any fetch
        called = {"count": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            called["count"] += 1
            return httpx.Response(200, content=_png_bytes(), headers={"content-type": "image/png"})

        res_loopback = asyncio.run(fetch_and_save_visual(
            "http://127.0.0.1/avatar.png",
            tmp_path / "media",
            transport=httpx.MockTransport(handler),
        ))
        res_metadata = asyncio.run(fetch_and_save_visual(
            "http://169.254.169.254/latest/meta-data",
            tmp_path / "media",
            transport=httpx.MockTransport(handler),
        ))
        assert res_loopback is None
        assert res_metadata is None
        assert called["count"] == 0

    def test_candidate_extraction_and_bundle_media_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_OSINT_HUB_HOME", str(tmp_path / "home"))
        gh_json = json.dumps({
            "target": "https://example.org",
            "user": {"login": "aurora", "avatar_url": "https://avatars.example.com/u/1.png"},
        })
        cands = extract_visual_candidates("github_osint", gh_json)
        assert any(c["url"] == "https://avatars.example.com/u/1.png" for c in cands)

        seed_demo_case(investigations_dir=tmp_path / "inv")
        bundle_path = tmp_path / "demo_v21.osintcase.zip"
        export_case_bundle(
            None,
            DEMO_TARGET_ID,
            bundle_path,
            investigations_dir=tmp_path / "inv",
        )
        imported_id = "case_demo_imported"
        # Export/import preserves media files cleanly
        restored = import_case_bundle(
            None,
            bundle_path,
            new_target_id=imported_id,
            overwrite=True,
            investigations_dir=tmp_path / "inv2",
        )
        assert restored["target_id"] == imported_id
        media_dir = tmp_path / "inv2" / imported_id / "media"
        assert (media_dir / "aurora_github.png").is_file()
        assert (media_dir / "aurora_gravatar.png").is_file()

        # Zip-Slip inside media/ must be rejected on import
        bad_zip = tmp_path / "bad_media.osintcase.zip"
        with zipfile.ZipFile(bundle_path, "r") as zin, zipfile.ZipFile(bad_zip, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("media/../../evil.png", b"not_safe")
        with pytest.raises(ValueError):
            import_case_bundle(None, bad_zip, investigations_dir=tmp_path / "inv3")


# ── 10. Simplified 4-Mode AI & [local-ai] Fallback ─────────────────────────────


class TestSimplifiedLocalAI:
    def test_four_modes_presets_and_fastembed_mocked(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_OSINT_HUB_HOME", str(tmp_path / "ai_home"))
        assert set(AI_PRESETS_CATALOG) == {
            "disabled", "cpu_light", "vram_8gb", "vram_16gb_plus", "cloud_byok"
        }
        default_cfg = load_ai_config()
        assert default_cfg.enabled is False
        assert default_cfg.mode == "off"

        local_cfg = update_ai_config({"mode": "local_embedded"})
        assert local_cfg["enabled"] is True
        assert local_cfg["provider"] == AIProviderKind.LOCAL_EMBEDDED.value
        assert local_cfg["mode"] == "local_embedded"

        # Deterministic None return when fastembed is absent/mocked out, without raising
        monkeypatch.setitem(sys.modules, "fastembed", None)
        avail = fastembed_availability()
        assert avail["available"] is False
        assert embed_fastembed_texts(["alice developer"]) is None

        # Fake fastembed module verifies real integration path when installed
        class _FakeTextEmbedding:
            def __init__(self, model_name: str = ""):
                self.model_name = model_name

            def embed(self, texts):
                for _ in texts:
                    yield [0.5, 0.5, 0.7071]

        fake_mod = types.ModuleType("fastembed")
        fake_mod.TextEmbedding = _FakeTextEmbedding
        monkeypatch.setitem(sys.modules, "fastembed", fake_mod)
        vecs = embed_fastembed_texts(["security researcher"])
        assert vecs is not None and len(vecs) == 1 and len(vecs[0]) == 3


# ── 11. Workbench v2.1 API, 4 Themes, Demo Media & Reporting ───────────────────


class TestWorkbenchV21UIAndReporting:
    def test_ui_themes_autofill_css_and_demo_endpoints(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_OSINT_HUB_HOME", str(tmp_path / "ui_home"))
        for marker in (
            "clean-light",
            "warm-paper",
            "midnight-slate",
            "gruvbox-dark",
            ":-webkit-autofill",
            "text-background-color",
            "data-tab=\"overview\"",
            "data-tab=\"visuals\"",
            "pickPrimaryNode",
        ):
            assert marker in WORKBENCH_HTML, f"Missing UI marker: {marker}"

        svc = InvestigationService(state_root=tmp_path / "ui_home" / "investigations")
        svc.seed_demo()
        app = create_app(service=svc)
        client = TestClient(app)

        ov = client.get(f"/api/investigations/{DEMO_TARGET_ID}/overview")
        assert ov.status_code == 200
        ov_data = ov.json()
        assert ov_data["status"] == "ok"
        assert ov_data["counts"]["accounts"] >= 1
        assert ov_data["counts"]["visuals"] >= 3

        vis = client.get(f"/api/investigations/{DEMO_TARGET_ID}/visuals")
        assert vis.status_code == 200
        vis_data = vis.json()
        assert vis_data["count"] >= 3
        assert vis_data["clusters"], "Expected cross-platform pHash match cluster in demo visuals"

        # Serve safe demo media + block traversal + set nosniff
        img_resp = client.get(f"/api/investigations/{DEMO_TARGET_ID}/media/aurora_github.png")
        assert img_resp.status_code == 200
        assert img_resp.headers.get("x-content-type-options") == "nosniff"
        bad_media = client.get(f"/api/investigations/{DEMO_TARGET_ID}/media/..%2F..%2Fsecrets.txt")
        assert bad_media.status_code in (400, 404)

        # Upload real PNG vs reject fake SVG upload
        up_ok = client.post(
            f"/api/investigations/{DEMO_TARGET_ID}/visuals/upload",
            files={"file": ("evidence.png", _png_bytes((220, 38, 38), software="PROSOL QA"), "image/png")},
            data={"source_label": "prosol_upload"},
        )
        assert up_ok.status_code == 200
        assert up_ok.json()["status"] == "ok"

        up_svg = client.post(
            f"/api/investigations/{DEMO_TARGET_ID}/visuals/upload",
            files={"file": ("xss.svg", b"<svg onload=alert(1)>", "image/svg+xml")},
        )
        assert up_svg.status_code == 400

        # Tools endpoint surfaces Hydra policy_blocked honestly
        tools_resp = client.get("/api/tools").json()
        hydra = next(t for t in tools_resp["tools"] if t["tool_id"] == "hydra")
        assert hydra["policy_blocked"] is True
        assert hydra["ui_status"] == "blocked"

        # Readable Entity coverage in Markdown + HTML dossier (never raw JSON dict)
        store = svc._open_store(DEMO_TARGET_ID)
        try:
            dossier = build_dossier(store, DEMO_TARGET_ID)
        finally:
            store.close()
        md = render_markdown(dossier)
        html = render_html(dossier)
        assert '{"' not in md.split("**Entity coverage:**")[1].splitlines()[0]
        assert "Entity coverage" in html

        # Traversal filename inside entity metadata must never yield an unsafe media URL
        store2 = svc._open_store(DEMO_TARGET_ID)
        try:
            art = store2.add_artifact(EvidenceArtifact(
                artifact_id="art_trav_test",
                investigation_id=DEMO_TARGET_ID,
                source_tool="visual_upload",
                invocation_params_hash="ph_trav",
                timestamp_utc=utc_now(),
                raw_evidence_snippet="trav",
                raw_output_sha256="c" * 64,
                parser_version="2.1.0",
            ))
            store2.insert_entity(
                DEMO_TARGET_ID,
                Entity(
                    entity_id="ent_trav_test",
                    investigation_id=DEMO_TARGET_ID,
                    type=EntityType.HASH,
                    canonical_value="d" * 64,
                    display_value="trav",
                    metadata={"media_asset": True, "filename": "../../../etc/passwd"},
                    first_seen=utc_now(),
                    last_seen=utc_now(),
                    created_by_artifact=art,
                ),
            )
        finally:
            store2.close()
        vis_after = client.get(f"/api/investigations/{DEMO_TARGET_ID}/visuals").json()
        trav_items = [it for it in vis_after["items"] if it["entity_id"] == "ent_trav_test"]
        assert trav_items and trav_items[0]["media_url"] == ""
