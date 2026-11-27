"""Deterministic offline synthetic demo case seeder (Aurora Meridian).

Populates a complete, 100% synthetic ERKG investigation (``case_demo_aurora``)
in under one second with zero network I/O so first-time users, tests, and
screenshots can explore the workbench immediately.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import struct
import zlib
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw

from hub.erkg.resolution import EntityResolver
from hub.erkg.store import ERKGStore, default_home
from hub.investigation.engine import InvestigationPaths
from hub.tools.builtin.media_forensics import compute_dhash, compute_phash
from hub.models import (
    PROVENANCE_AI_INFERRED,
    BudgetConfig,
    EntityType,
    EpistemicStatus,
    ErrorCode,
    EvidenceArtifact,
    ExecutionRecord,
    ExecutionStatus,
    Hypothesis,
    HypothesisStatus,
    HypothesisType,
    InvestigationConfig,
    InvestigationState,
    IterationRecord,
    Objective,
    RunStatus,
    ScopeConfig,
    canonical_json,
    param_hash,
    sha256_text,
    short_id,
)

DEMO_TARGET_ID = "case_demo_aurora"
DEMO_TITLE = "Aurora Meridian Supply-Chain Attribution"
_BASE_TS = "2026-11-20T09:00:00+00:00"


def _synthetic_png_bytes(width: int = 128, height: int = 128) -> bytes:
    """Create a deterministic, valid RGBA PNG in pure Python (no network)."""
    return _render_avatar_emblem_png(width=width, height=height)["bytes"]


def _render_avatar_emblem_png(
    *,
    width: int = 128,
    height: int = 128,
    variant: str = "avatar",
    exif_software: str = "GIMP 2.10 (Synthetic Lab)",
    exif_artist: str = "Elena Vance",
    exif_datetime: str = "2026:10:14 11:22:08",
) -> dict[str, Any]:
    """Generate a crisp 128x128 synthetic PNG via Pillow with optional EXIF + hashes."""
    if variant == "favicon":
        img = Image.new("RGB", (width, height), (15, 23, 42))
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((10, 10, width - 11, height - 11), radius=24, fill=(17, 24, 39), outline=(15, 118, 110), width=4)
        draw.ellipse((28, 28, width - 29, height - 29), fill=(15, 118, 110), outline=(181, 118, 20), width=4)
        draw.polygon([(width // 2, 36), (width - 38, height - 40), (38, height - 40)], fill=(248, 250, 252))
        draw.ellipse((width // 2 - 10, height // 2 - 2, width // 2 + 10, height // 2 + 18), fill=(175, 58, 3))
    else:
        img = Image.new("RGB", (width, height), (248, 250, 252))
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((8, 8, width - 9, height - 9), radius=22, fill=(251, 241, 199), outline=(175, 58, 3), width=4)
        draw.polygon(
            [(width // 2, 22), (width - 24, height // 2), (width // 2, height - 22), (24, height // 2)],
            fill=(175, 58, 3),
        )
        draw.ellipse((42, 42, width - 43, height - 43), fill=(15, 23, 42))
        draw.ellipse((54, 54, width - 55, height - 55), fill=(251, 241, 199))

    phash = compute_phash(img) or "a8f3c19e4b2d7055"
    dhash = compute_dhash(img) or "9c72e41855a3b01f"

    exif = img.getexif()
    if exif_software:
        exif[0x0131] = exif_software
    if exif_artist:
        exif[0x013B] = exif_artist
    if exif_datetime:
        exif[0x9003] = exif_datetime

    buf = io.BytesIO()
    img.save(buf, format="PNG", exif=exif)
    raw = buf.getvalue()
    return {
        "bytes": raw,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "width": width,
        "height": height,
        "phash": phash,
        "dhash": dhash,
    }


def _resolve_investigations_root(
    state_root: Path | str | None,
    investigations_dir: Path | str | None,
) -> Path:
    if investigations_dir is not None:
        return Path(investigations_dir).expanduser().resolve()
    if state_root is not None:
        sr = Path(state_root).expanduser().resolve()
        return sr if sr.name == "investigations" else (sr / "investigations")
    return (default_home() / "investigations").resolve()


def _write_raw(raw_dir: Path, filename: str, content: str | bytes) -> tuple[Path, str, int]:
    path = raw_dir / filename
    if isinstance(content, bytes):
        path.write_bytes(content)
        import hashlib

        digest = hashlib.sha256(content).hexdigest()
        size = len(content)
    else:
        path.write_text(content, encoding="utf-8")
        digest = sha256_text(content)
        size = len(content.encode("utf-8"))
    return path, digest, size


def seed_demo_case(
    state_root: Path | str | None = None,
    *,
    overwrite: bool = True,
    investigations_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Deterministically seed ``case_demo_aurora`` with 100% synthetic data."""
    inv_root = _resolve_investigations_root(state_root, investigations_dir)
    case_dir = inv_root / DEMO_TARGET_ID
    db_path = case_dir / "erkg.sqlite3"

    if db_path.exists() and not overwrite:
        store = ERKGStore(db_path, investigation_id=DEMO_TARGET_ID)
        try:
            stats = store.stats(DEMO_TARGET_ID)
        finally:
            store.close()
        return {
            "status": "ok",
            "target_id": DEMO_TARGET_ID,
            "title": DEMO_TITLE,
            "entity_count": stats.get("entities", 0),
            "claim_count": stats.get("claims", 0),
            "contradiction_count": stats.get("contradictions", 0),
            "synthetic": True,
            "already_existed": True,
            "state_path": str(case_dir),
        }

    if case_dir.exists():
        shutil.rmtree(case_dir)

    paths = InvestigationPaths(case_dir).ensure()
    media_dir = case_dir / "media"
    media_dir.mkdir(parents=True, exist_ok=True)

    gh_asset = _render_avatar_emblem_png(
        variant="avatar",
        exif_software="GIMP 2.10 (Synthetic Lab)",
        exif_artist="Elena Vance",
        exif_datetime="2026:10:14 11:22:08",
    )
    grav_asset = _render_avatar_emblem_png(
        variant="avatar",
        exif_software="Gravatar Mirror Cache (Synthetic)",
        exif_artist="Elena Vance",
        exif_datetime="2026:10:14 11:22:08",
    )
    fav_asset = _render_avatar_emblem_png(
        variant="favicon",
        exif_software="Aurora Meridian Badge Studio 2.1",
        exif_artist="Aurora Ops",
        exif_datetime="2026:11:02 15:40:00",
    )

    (media_dir / "aurora_github.png").write_bytes(gh_asset["bytes"])
    (media_dir / "aurora_gravatar.png").write_bytes(grav_asset["bytes"])
    (media_dir / "aurora_site_favicon.png").write_bytes(fav_asset["bytes"])

    png_bytes = gh_asset["bytes"]
    png_path, png_sha256, png_size = _write_raw(
        paths.raw, "011_evance_avatar.png", png_bytes
    )

    synthetic_outputs: dict[str, tuple[str, str, str]] = {
        "seed": (
            "000_seed.txt",
            "2026-11-20T09:00:00+00:00",
            f"Scenario: {DEMO_TITLE} (100% synthetic training/demo dataset)\n"
            "Subject: Elena Vance | Handles: evance-sec, aurora-ops\n"
            "Email: e.vance@aurora-meridian.example | Domain: aurora-meridian.example\n"
            "Infrastructure: git.aurora-meridian.example -> 198.51.100.42 (AS64501 Aurora Transit)\n",
        ),
        "sherlock": (
            "001_sherlock.txt",
            "2026-11-20T09:00:18+00:00",
            "[+] GitHub: https://github.com/evance-sec\n"
            "[+] GitLab: https://gitlab.com/evance-sec\n"
            "[*] Handle evance-sec verified on github (synthetic)\n",
        ),
        "maigret": (
            "002_maigret.json",
            "2026-11-20T09:00:36+00:00",
            json.dumps(
                {
                    "synthetic": True,
                    "sites": {
                        "GitHub": {
                            "username": "evance-sec",
                            "url_user": "https://github.com/evance-sec",
                            "status": {"is_claimed": True},
                        }
                    },
                    "associated_handles": ["aurora-ops"],
                },
                indent=2,
            ),
        ),
        "github_osint": (
            "003_github_osint.json",
            "2026-11-20T09:00:54+00:00",
            json.dumps(
                {
                    "synthetic": True,
                    "login": "evance-sec",
                    "name": "Elena Vance",
                    "email": "e.vance@aurora-meridian.example",
                    "company": "Aurora Meridian Logistics",
                    "location": "Toronto, CA",
                    "timezone": "UTC-05:00 (Toronto, CA)",
                    "avatar_url": "https://aurora-meridian.example/assets/evance-avatar.png",
                    "profile_url": "https://github.com/evance-sec",
                    "repositories": ["https://github.com/evance-sec/meridian-supply-audit"],
                    "avatar_phash": gh_asset["phash"],
                },
                indent=2,
            ),
        ),
        "holehe": (
            "004_holehe.txt",
            "2026-11-20T09:01:12+00:00",
            "[+] github.com (e.vance@aurora-meridian.example)\n"
            "[+] gitlab.com (e.vance@aurora-meridian.example)\n",
        ),
        "theharvester": (
            "005_theharvester.txt",
            "2026-11-20T09:01:30+00:00",
            "[*] Target: aurora-meridian.example (synthetic)\n"
            "[*] Emails found: e.vance@aurora-meridian.example\n"
            "[*] Hosts found: git.aurora-meridian.example:198.51.100.42\n"
            "[*] Registrant Org: Aurora Meridian Logistics\n",
        ),
        "pgp_keyserver": (
            "006_pgp_keyserver.txt",
            "2026-11-20T09:01:48+00:00",
            "pub   ed25519/0x4A91E8C0D2F7B104 2026-04-12 [SC]\n"
            "uid   Elena Vance (evance-sec) <e.vance@aurora-meridian.example>\n"
            "note  Declared keyserver timezone: UTC+00:00 (Reykjavik, IS)\n",
        ),
        "dns_lookup": (
            "007_dns_lookup.json",
            "2026-11-20T09:02:06+00:00",
            json.dumps(
                {
                    "synthetic": True,
                    "domain": "aurora-meridian.example",
                    "records": {
                        "A": {"git.aurora-meridian.example": ["198.51.100.42"]},
                        "MX": ["mx1.aurora-meridian.example"],
                        "TXT": ["v=spf1 ip4:198.51.100.42/32 -all"],
                    },
                    "asn": "AS64501",
                },
                indent=2,
            ),
        ),
        "crtsh_lookup": (
            "008_crtsh_lookup.json",
            "2026-11-20T09:02:24+00:00",
            json.dumps(
                {
                    "synthetic": True,
                    "common_name": "aurora-meridian.example",
                    "san": ["aurora-meridian.example", "git.aurora-meridian.example"],
                    "organization": "Aurora Meridian Logistics",
                    "observed_ip": "198.51.100.42",
                },
                indent=2,
            ),
        ),
        "rdap_lookup": (
            "009_rdap_lookup.json",
            "2026-11-20T09:02:42+00:00",
            json.dumps(
                {
                    "synthetic": True,
                    "domain": "aurora-meridian.example",
                    "registrant_org": "Aurora Meridian Logistics",
                    "nameservers": ["ns1.aurora-meridian.example"],
                    "ip_block": "198.51.100.0/24",
                    "ip": "198.51.100.42",
                    "asn": "AS64501",
                },
                indent=2,
            ),
        ),
        "asn_bgp_lookup": (
            "010_asn_bgp_lookup.json",
            "2026-11-20T09:03:00+00:00",
            json.dumps(
                {
                    "synthetic": True,
                    "asn": "AS64501",
                    "as_name": "AS64501 Aurora Transit",
                    "prefix": "198.51.100.0/24",
                    "ip": "198.51.100.42",
                },
                indent=2,
            ),
        ),
        "media_forensics": (
            "011_media_forensics.json",
            "2026-11-20T09:03:18+00:00",
            json.dumps(
                {
                    "synthetic": True,
                    "url": "https://aurora-meridian.example/assets/evance-avatar.png",
                    "local_artifact": "media/aurora_github.png",
                    "mime_type": "image/png",
                    "format": "PNG",
                    "dimensions": [128, 128],
                    "sha256": png_sha256,
                    "phash": gh_asset["phash"],
                    "dhash": gh_asset["dhash"],
                    "exif": {
                        "Software": "GIMP 2.10 (Synthetic Lab)",
                        "Artist": "Elena Vance",
                        "DateTimeOriginal": "2026:10:14 11:22:08",
                    },
                    "related_media": [
                        {
                            "local_file": "media/aurora_gravatar.png",
                            "platform": "gravatar",
                            "sha256": grav_asset["sha256"],
                            "phash": grav_asset["phash"],
                            "dhash": grav_asset["dhash"],
                        },
                        {
                            "local_file": "media/aurora_site_favicon.png",
                            "platform": "web",
                            "sha256": fav_asset["sha256"],
                            "phash": fav_asset["phash"],
                            "dhash": fav_asset["dhash"],
                        },
                    ],
                },
                indent=2,
            ),
        ),
    }

    store = ERKGStore(db_path, investigation_id=DEMO_TARGET_ID)
    try:
        with store.transaction():
            artifacts: dict[str, EvidenceArtifact] = {}
            for tool_id, (fname, ts, content) in synthetic_outputs.items():
                raw_path, digest, byte_len = _write_raw(paths.raw, fname, content)
                if tool_id == "media_forensics":
                    digest = png_sha256
                    byte_len = png_size
                art = EvidenceArtifact(
                    artifact_id=short_id("art", DEMO_TARGET_ID, tool_id, digest),
                    investigation_id=DEMO_TARGET_ID,
                    source_tool=tool_id,
                    invocation_params_hash=param_hash(tool_id, {"demo": DEMO_TARGET_ID}),
                    timestamp_utc=ts,
                    raw_evidence_snippet=content[:1200],
                    raw_output_sha256=digest,
                    parser_version="2.0.0",
                    epistemic_status=EpistemicStatus.SINGLE_SOURCE_LEAD,
                    confidence=0.85,
                    raw_output_path=str(raw_path),
                    stdout_bytes=byte_len,
                    truncated=False,
                )
                store.add_artifact(art)
                artifacts[tool_id] = art

            resolver = EntityResolver(store)
            person, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.PERSON,
                "Elena Vance",
                artifact_id=artifacts["seed"].artifact_id,
                timestamp=_BASE_TS,
                metadata={"role": "primary_subject", "synthetic": True},
            )
            handle_primary, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.USERNAME,
                "evance-sec",
                artifact_id=artifacts["seed"].artifact_id,
                timestamp=_BASE_TS,
                metadata={"role": "primary_handle", "synthetic": True},
            )
            handle_ops, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.USERNAME,
                "aurora-ops",
                artifact_id=artifacts["maigret"].artifact_id,
                timestamp="2026-11-20T09:00:36+00:00",
                metadata={"role": "ops_alias", "synthetic": True},
            )
            email, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.EMAIL,
                "e.vance@aurora-meridian.example",
                artifact_id=artifacts["seed"].artifact_id,
                timestamp=_BASE_TS,
                metadata={"role": "institutional_email", "synthetic": True},
            )
            domain, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.DOMAIN,
                "aurora-meridian.example",
                artifact_id=artifacts["seed"].artifact_id,
                timestamp=_BASE_TS,
                metadata={"role": "primary_domain", "synthetic": True},
            )
            subdomain, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.SUBDOMAIN,
                "git.aurora-meridian.example",
                artifact_id=artifacts["theharvester"].artifact_id,
                timestamp="2026-11-20T09:01:30+00:00",
                metadata={"role": "source_forge", "synthetic": True},
            )
            ip_ent, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.IP,
                "198.51.100.42",
                artifact_id=artifacts["dns_lookup"].artifact_id,
                timestamp="2026-11-20T09:02:06+00:00",
                metadata={"role": "forge_endpoint", "synthetic": True},
            )
            org, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.ORGANIZATION,
                "Aurora Meridian Logistics",
                artifact_id=artifacts["rdap_lookup"].artifact_id,
                timestamp="2026-11-20T09:02:42+00:00",
                metadata={"synthetic": True},
            )
            asn_ent, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.ASN,
                "AS64501",
                artifact_id=artifacts["asn_bgp_lookup"].artifact_id,
                timestamp="2026-11-20T09:03:00+00:00",
                aliases=["AS64501 Aurora Transit"],
                metadata={"as_name": "AS64501 Aurora Transit", "synthetic": True},
            )
            # Ensure display_value conveys full ASN name cleanly
            store._write(
                "UPDATE entities SET display_value=? WHERE entity_id=?",
                ("AS64501 Aurora Transit", asn_ent.entity_id),
            )
            profile, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.SOCIAL_PROFILE,
                "https://github.com/evance-sec",
                artifact_id=artifacts["sherlock"].artifact_id,
                timestamp="2026-11-20T09:00:18+00:00",
                metadata={"platform": "github", "synthetic": True},
            )
            repo, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.REPOSITORY,
                "github.com/evance-sec/meridian-supply-audit",
                artifact_id=artifacts["github_osint"].artifact_id,
                timestamp="2026-11-20T09:00:54+00:00",
                metadata={"url": "https://github.com/evance-sec/meridian-supply-audit", "synthetic": True},
            )
            service_gh, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.SERVICE,
                "github",
                artifact_id=artifacts["holehe"].artifact_id,
                timestamp="2026-11-20T09:01:12+00:00",
                metadata={"synthetic": True},
            )
            avatar_url, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.URL,
                "https://aurora-meridian.example/assets/evance-avatar.png",
                artifact_id=artifacts["media_forensics"].artifact_id,
                timestamp="2026-11-20T09:03:18+00:00",
                metadata={
                    "media_asset": True,
                    "media_kind": "image",
                    "platform": "github",
                    "source_label": "GitHub Avatar",
                    "source_tool": "media_forensics",
                    "media_file": "media/aurora_github.png",
                    "local_file": "media/aurora_github.png",
                    "filename": "aurora_github.png",
                    "content_type": "image/png",
                    "width": 128,
                    "height": 128,
                    "phash": gh_asset["phash"],
                    "dhash": gh_asset["dhash"],
                    "sha256": gh_asset["sha256"],
                    "exif": {
                        "Software": "GIMP 2.10 (Synthetic Lab)",
                        "Artist": "Elena Vance",
                        "DateTimeOriginal": "2026:10:14 11:22:08",
                    },
                    "synthetic": True,
                },
            )
            gravatar_url, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.URL,
                "https://www.gravatar.com/avatar/e8c4a1b2c3d4e5f60718293a4b5c6d7e?s=256&d=404",
                artifact_id=artifacts["media_forensics"].artifact_id,
                timestamp="2026-11-20T09:03:19+00:00",
                metadata={
                    "media_asset": True,
                    "media_kind": "image",
                    "platform": "gravatar",
                    "source_label": "Gravatar Avatar",
                    "source_tool": "media_forensics",
                    "media_file": "media/aurora_gravatar.png",
                    "local_file": "media/aurora_gravatar.png",
                    "filename": "aurora_gravatar.png",
                    "content_type": "image/png",
                    "width": 128,
                    "height": 128,
                    "phash": grav_asset["phash"],
                    "dhash": grav_asset["dhash"],
                    "sha256": grav_asset["sha256"],
                    "exif": {
                        "Software": "Gravatar Mirror Cache (Synthetic)",
                        "Artist": "Elena Vance",
                        "DateTimeOriginal": "2026:10:14 11:22:08",
                    },
                    "synthetic": True,
                },
            )
            favicon_url, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.URL,
                "https://aurora-meridian.example/favicon.png",
                artifact_id=artifacts["media_forensics"].artifact_id,
                timestamp="2026-11-20T09:03:20+00:00",
                metadata={
                    "media_asset": True,
                    "media_kind": "image",
                    "platform": "web",
                    "source_label": "Site Favicon / Conference Badge",
                    "source_tool": "media_forensics",
                    "media_file": "media/aurora_site_favicon.png",
                    "local_file": "media/aurora_site_favicon.png",
                    "filename": "aurora_site_favicon.png",
                    "content_type": "image/png",
                    "width": 128,
                    "height": 128,
                    "phash": fav_asset["phash"],
                    "dhash": fav_asset["dhash"],
                    "sha256": fav_asset["sha256"],
                    "exif": {
                        "Software": "Aurora Meridian Badge Studio 2.1",
                        "Artist": "Aurora Ops",
                        "DateTimeOriginal": "2026:11:02 15:40:00",
                    },
                    "synthetic": True,
                },
            )
            avatar_hash, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.HASH,
                png_sha256,
                artifact_id=artifacts["media_forensics"].artifact_id,
                timestamp="2026-11-20T09:03:18+00:00",
                metadata={"algorithm": "sha256", "phash": gh_asset["phash"], "synthetic": True},
            )
            location_ca, _ = resolver.resolve(
                DEMO_TARGET_ID,
                EntityType.LOCATION,
                "Toronto, CA",
                artifact_id=artifacts["github_osint"].artifact_id,
                timestamp="2026-11-20T09:00:54+00:00",
                metadata={"synthetic": True},
            )

            objectives = [
                Objective(
                    objective_id="obj_identity",
                    description=f"{DEMO_TITLE}: corroborate primary operator handles & email",
                    entity_id=person.entity_id,
                    required_status=EpistemicStatus.CONFIRMED,
                    achieved=True,
                    status=EpistemicStatus.CONFIRMED,
                ),
                Objective(
                    objective_id="obj_infra",
                    description="Attribute git.aurora-meridian.example infrastructure & ASN ownership",
                    entity_id=subdomain.entity_id,
                    required_status=EpistemicStatus.CONFIRMED,
                    achieved=True,
                    status=EpistemicStatus.CONFIRMED,
                ),
                Objective(
                    objective_id="obj_timezone",
                    description="Resolve timezone discrepancy across keyserver and forge metadata",
                    entity_id=person.entity_id,
                    required_status=EpistemicStatus.CORROBORATED,
                    achieved=False,
                    status=EpistemicStatus.CONTRADICTED,
                ),
            ]
            config = InvestigationConfig(
                target_id=DEMO_TARGET_ID,
                raw_input=f"{DEMO_TITLE}: Elena Vance (evance-sec, e.vance@aurora-meridian.example)",
                budgets=BudgetConfig(max_iterations=16, max_tool_calls=20, wall_clock_timeout_sec=600),
                scope=ScopeConfig(
                    allow_domains=["aurora-meridian.example"],
                    allow_active_recon=False,
                    allow_authorized_tools=False,
                ),
            )
            store.create_investigation(
                InvestigationState(
                    target_id=DEMO_TARGET_ID,
                    raw_input=config.raw_input,
                    created_at=_BASE_TS,
                    updated_at="2026-11-20T09:03:45+00:00",
                    status=RunStatus.COMPLETED,
                    config=config,
                    seed_entity_ids=[person.entity_id, handle_primary.entity_id, email.entity_id, domain.entity_id],
                    iteration_count=3,
                    tool_calls=12,
                    stop_reason="objectives_satisfied_with_open_contradiction_review",
                    objectives=objectives,
                )
            )

            def _add_corroborated(
                subj_id: str,
                pred: str,
                *,
                obj_id: str | None = None,
                obj_lit: Any = None,
                tools: tuple[str, ...],
                snippet: str,
            ) -> None:
                for t in tools:
                    art = artifacts[t]
                    if obj_id is not None:
                        store.upsert_claim(
                            DEMO_TARGET_ID,
                            subj_id,
                            pred,
                            object_id=obj_id,
                            artifact_id=art.artifact_id,
                            source_tool=t,
                            timestamp=art.timestamp_utc,
                            direct=True,
                            snippet=snippet,
                        )
                    else:
                        store.upsert_claim(
                            DEMO_TARGET_ID,
                            subj_id,
                            pred,
                            object_literal=obj_lit,
                            artifact_id=art.artifact_id,
                            source_tool=t,
                            timestamp=art.timestamp_utc,
                            direct=True,
                            snippet=snippet,
                        )

            # Corroborated CONFIRMED claims across 3 independent synthetic tools each
            _add_corroborated(
                person.entity_id,
                "HAS_USERNAME",
                obj_id=handle_primary.entity_id,
                tools=("github_osint", "pgp_keyserver", "sherlock"),
                snippet="Elena Vance attributed to handle evance-sec",
            )
            _add_corroborated(
                person.entity_id,
                "HAS_EMAIL",
                obj_id=email.entity_id,
                tools=("github_osint", "pgp_keyserver", "theharvester"),
                snippet="Elena Vance <e.vance@aurora-meridian.example>",
            )
            _add_corroborated(
                handle_primary.entity_id,
                "REGISTERED_ON",
                obj_id=service_gh.entity_id,
                tools=("sherlock", "maigret", "github_osint"),
                snippet="Account evance-sec active on GitHub",
            )
            _add_corroborated(
                profile.entity_id,
                "HAS_USERNAME",
                obj_id=handle_primary.entity_id,
                tools=("sherlock", "maigret", "github_osint"),
                snippet="https://github.com/evance-sec -> evance-sec",
            )
            _add_corroborated(
                email.entity_id,
                "ASSOCIATED_WITH",
                obj_id=domain.entity_id,
                tools=("theharvester", "holehe", "pgp_keyserver"),
                snippet="e.vance@aurora-meridian.example mail domain aurora-meridian.example",
            )
            _add_corroborated(
                subdomain.entity_id,
                "SUBDOMAIN_OF",
                obj_id=domain.entity_id,
                tools=("crtsh_lookup", "dns_lookup", "theharvester"),
                snippet="SAN & DNS confirm git.aurora-meridian.example under aurora-meridian.example",
            )
            _add_corroborated(
                subdomain.entity_id,
                "RESOLVES_TO",
                obj_id=ip_ent.entity_id,
                tools=("dns_lookup", "rdap_lookup", "crtsh_lookup"),
                snippet="git.aurora-meridian.example -> 198.51.100.42",
            )
            _add_corroborated(
                ip_ent.entity_id,
                "ASSOCIATED_WITH",
                obj_id=asn_ent.entity_id,
                tools=("asn_bgp_lookup", "rdap_lookup", "dns_lookup"),
                snippet="198.51.100.42 announced by AS64501 Aurora Transit",
            )
            _add_corroborated(
                domain.entity_id,
                "REGISTERED_BY",
                obj_id=org.entity_id,
                tools=("rdap_lookup", "crtsh_lookup", "theharvester"),
                snippet="aurora-meridian.example registered to Aurora Meridian Logistics",
            )

            # Single-source / direct links
            store.upsert_claim(
                DEMO_TARGET_ID,
                handle_primary.entity_id,
                "COMMITTED_TO",
                object_id=repo.entity_id,
                artifact_id=artifacts["github_osint"].artifact_id,
                source_tool="github_osint",
                timestamp=artifacts["github_osint"].timestamp_utc,
                direct=True,
                snippet="evance-sec maintains meridian-supply-audit",
            )
            store.upsert_claim(
                DEMO_TARGET_ID,
                person.entity_id,
                "LOCATED_IN",
                object_id=location_ca.entity_id,
                artifact_id=artifacts["github_osint"].artifact_id,
                source_tool="github_osint",
                timestamp=artifacts["github_osint"].timestamp_utc,
                direct=True,
                snippet="GitHub profile location: Toronto, CA",
            )
            store.upsert_claim(
                DEMO_TARGET_ID,
                person.entity_id,
                "OWNS",
                object_id=org.entity_id,
                artifact_id=artifacts["github_osint"].artifact_id,
                source_tool="github_osint",
                timestamp=artifacts["github_osint"].timestamp_utc,
                direct=True,
                snippet="Company field: Aurora Meridian Logistics",
            )
            store.upsert_claim(
                DEMO_TARGET_ID,
                profile.entity_id,
                "MENTIONED_IN",
                object_id=avatar_url.entity_id,
                artifact_id=artifacts["github_osint"].artifact_id,
                source_tool="github_osint",
                timestamp=artifacts["github_osint"].timestamp_utc,
                direct=True,
                snippet="Avatar URL linked on profile",
            )

            store.upsert_claim(
                DEMO_TARGET_ID,
                email.entity_id,
                "MENTIONED_IN",
                object_id=gravatar_url.entity_id,
                artifact_id=artifacts["media_forensics"].artifact_id,
                source_tool="media_forensics",
                timestamp="2026-11-20T09:03:19+00:00",
                direct=True,
                snippet="Gravatar profile avatar resolved for e.vance@aurora-meridian.example",
            )
            store.upsert_claim(
                DEMO_TARGET_ID,
                domain.entity_id,
                "MENTIONED_IN",
                object_id=favicon_url.entity_id,
                artifact_id=artifacts["media_forensics"].artifact_id,
                source_tool="media_forensics",
                timestamp="2026-11-20T09:03:20+00:00",
                direct=True,
                snippet="Site favicon & conference badge harvested from aurora-meridian.example",
            )

            # Media forensics + EXIF + perceptual hash claims on avatar image
            store.upsert_claim(
                DEMO_TARGET_ID,
                avatar_url.entity_id,
                "IDENTIFIED_AS",
                object_id=avatar_hash.entity_id,
                artifact_id=artifacts["media_forensics"].artifact_id,
                source_tool="media_forensics",
                timestamp=artifacts["media_forensics"].timestamp_utc,
                direct=True,
                snippet=f"SHA-256={png_sha256}",
            )
            for attr_key, attr_val in (
                ("phash", gh_asset["phash"]),
                ("dhash", gh_asset["dhash"]),
                ("sha256", png_sha256),
                ("local_file", "media/aurora_github.png"),
                ("exif_software", "GIMP 2.10 (Synthetic Lab)"),
                ("exif_artist", "Elena Vance"),
            ):
                store.upsert_claim(
                    DEMO_TARGET_ID,
                    avatar_url.entity_id,
                    f"HAS_ATTRIBUTE:{attr_key}",
                    object_literal=attr_val,
                    artifact_id=artifacts["media_forensics"].artifact_id,
                    source_tool="media_forensics",
                    timestamp=artifacts["media_forensics"].timestamp_utc,
                    direct=True,
                    snippet=f"{attr_key}={attr_val}",
                )
            for attr_key, attr_val in (
                ("phash", grav_asset["phash"]),
                ("dhash", grav_asset["dhash"]),
                ("sha256", grav_asset["sha256"]),
                ("local_file", "media/aurora_gravatar.png"),
                ("exif_software", "Gravatar Mirror Cache (Synthetic)"),
                ("exif_artist", "Elena Vance"),
            ):
                store.upsert_claim(
                    DEMO_TARGET_ID,
                    gravatar_url.entity_id,
                    f"HAS_ATTRIBUTE:{attr_key}",
                    object_literal=attr_val,
                    artifact_id=artifacts["media_forensics"].artifact_id,
                    source_tool="media_forensics",
                    timestamp="2026-11-20T09:03:19+00:00",
                    direct=True,
                    snippet=f"{attr_key}={attr_val}",
                )
            for attr_key, attr_val in (
                ("phash", fav_asset["phash"]),
                ("dhash", fav_asset["dhash"]),
                ("sha256", fav_asset["sha256"]),
                ("local_file", "media/aurora_site_favicon.png"),
                ("exif_software", "Aurora Meridian Badge Studio 2.1"),
                ("exif_artist", "Aurora Ops"),
            ):
                store.upsert_claim(
                    DEMO_TARGET_ID,
                    favicon_url.entity_id,
                    f"HAS_ATTRIBUTE:{attr_key}",
                    object_literal=attr_val,
                    artifact_id=artifacts["media_forensics"].artifact_id,
                    source_tool="media_forensics",
                    timestamp="2026-11-20T09:03:20+00:00",
                    direct=True,
                    snippet=f"{attr_key}={attr_val}",
                )
            # Second source sharing pHash so perceptual correlation lights up
            store.upsert_claim(
                DEMO_TARGET_ID,
                profile.entity_id,
                "HAS_ATTRIBUTE:phash",
                object_literal=gh_asset["phash"],
                artifact_id=artifacts["github_osint"].artifact_id,
                source_tool="github_osint",
                timestamp=artifacts["github_osint"].timestamp_utc,
                direct=True,
                snippet=f"avatar_phash={gh_asset['phash']}",
            )

            # Explicit CONTRADICTED functional claim (timezone conflict)
            store.upsert_claim(
                DEMO_TARGET_ID,
                person.entity_id,
                "HAS_ATTRIBUTE:timezone",
                object_literal="UTC-05:00 (Toronto, CA)",
                artifact_id=artifacts["github_osint"].artifact_id,
                source_tool="github_osint",
                timestamp=artifacts["github_osint"].timestamp_utc,
                direct=True,
                snippet="timezone=UTC-05:00 (Toronto, CA)",
            )
            store.upsert_claim(
                DEMO_TARGET_ID,
                person.entity_id,
                "HAS_ATTRIBUTE:timezone",
                object_literal="UTC+00:00 (Reykjavik, IS)",
                artifact_id=artifacts["pgp_keyserver"].artifact_id,
                source_tool="pgp_keyserver",
                timestamp=artifacts["pgp_keyserver"].timestamp_utc,
                direct=True,
                snippet="timezone=UTC+00:00 (Reykjavik, IS)",
            )

            # Execution ledger records (tool runs + 1 empty collection gap)
            ledger_specs = [
                (handle_primary.entity_id, "sherlock", ExecutionStatus.SUCCESS, None, 410),
                (handle_primary.entity_id, "maigret", ExecutionStatus.SUCCESS, None, 620),
                (handle_primary.entity_id, "github_osint", ExecutionStatus.SUCCESS, None, 285),
                (email.entity_id, "holehe", ExecutionStatus.SUCCESS, None, 340),
                (domain.entity_id, "theharvester", ExecutionStatus.SUCCESS, None, 510),
                (email.entity_id, "pgp_keyserver", ExecutionStatus.SUCCESS, None, 195),
                (domain.entity_id, "dns_lookup", ExecutionStatus.SUCCESS, None, 95),
                (domain.entity_id, "crtsh_lookup", ExecutionStatus.SUCCESS, None, 310),
                (domain.entity_id, "rdap_lookup", ExecutionStatus.SUCCESS, None, 240),
                (ip_ent.entity_id, "asn_bgp_lookup", ExecutionStatus.SUCCESS, None, 180),
                (avatar_url.entity_id, "media_forensics", ExecutionStatus.SUCCESS, None, 145),
            ]
            for eid, tool_id, st, err_code, dur in ledger_specs:
                art = artifacts[tool_id]
                store.record_execution(
                    ExecutionRecord(
                        investigation_id=DEMO_TARGET_ID,
                        entity_id=eid,
                        tool_id=tool_id,
                        param_hash=art.invocation_params_hash,
                        status=st,
                        error_code=err_code,
                        artifact_id=art.artifact_id,
                        run_at=art.timestamp_utc,
                        duration_ms=dur,
                        error_message="",
                    )
                )
            store.record_execution(
                ExecutionRecord(
                    investigation_id=DEMO_TARGET_ID,
                    entity_id=domain.entity_id,
                    tool_id="darkweb_ahmia",
                    param_hash=param_hash("darkweb_ahmia", {"domain": "aurora-meridian.example"}),
                    status=ExecutionStatus.EMPTY,
                    error_code=ErrorCode.EMPTY_RESULT,
                    artifact_id=None,
                    run_at="2026-11-20T09:03:28+00:00",
                    duration_ms=220,
                    error_message="",
                )
            )

            # Iteration records for timeline / telemetry completeness
            for idx, (ts, summary_note) in enumerate(
                (
                    ("2026-11-20T09:00:54+00:00", "Identity pivot across sherlock/maigret/github_osint"),
                    ("2026-11-20T09:02:24+00:00", "Email & infrastructure corroboration via holehe/dns/crtsh"),
                    ("2026-11-20T09:03:30+00:00", "ASN attribution, avatar forensics & contradiction logged"),
                ),
                start=1,
            ):
                store.record_iteration(
                    DEMO_TARGET_ID,
                    IterationRecord(
                        iteration=idx,
                        timestamp_utc=ts,
                        action={"summary": summary_note, "synthetic": True},
                        result={"status": "SUCCESS"},
                        new_claims=4,
                        duration_ms=250 * idx,
                    ),
                )

            # Hypotheses (open + supported)
            store.add_hypothesis(
                Hypothesis(
                    hypothesis_id="hyp_demo_corroborate_ops",
                    investigation_id=DEMO_TARGET_ID,
                    hypothesis_type=HypothesisType.IDENTITY_LINK,
                    question="Can independent commit logs or CI metadata corroborate aurora-ops attribution to Elena Vance?",
                    target_entity_id=handle_ops.entity_id,
                    proposed_tool_ids=["github_osint", "wayback_cdx"],
                    rationale="aurora-ops appeared alongside evance-sec in synthetic Maigret telemetry.",
                    status=HypothesisStatus.OPEN,
                    created_by="planner",
                    created_at="2026-11-20T09:00:40+00:00",
                    updated_at="2026-11-20T09:03:35+00:00",
                )
            )
            store.add_hypothesis(
                Hypothesis(
                    hypothesis_id="hyp_demo_resolve_tz",
                    investigation_id=DEMO_TARGET_ID,
                    hypothesis_type=HypothesisType.RESOLUTION,
                    question="Resolve conflicting timezone metadata (UTC-05:00 Toronto vs UTC+00:00 Reykjavik) on Elena Vance.",
                    target_entity_id=person.entity_id,
                    proposed_tool_ids=["github_osint", "pgp_keyserver"],
                    rationale="GitHub profile indicates Toronto (UTC-05:00) while PGP UID metadata lists Reykjavik (UTC+00:00).",
                    status=HypothesisStatus.OPEN,
                    created_by="planner",
                    created_at="2026-11-20T09:01:50+00:00",
                    updated_at="2026-11-20T09:03:35+00:00",
                )
            )
            store.add_hypothesis(
                Hypothesis(
                    hypothesis_id="hyp_demo_verify_asn",
                    investigation_id=DEMO_TARGET_ID,
                    hypothesis_type=HypothesisType.VERIFICATION,
                    question="Verify AS64501 Aurora Transit BGP origin for 198.51.100.42.",
                    target_entity_id=asn_ent.entity_id,
                    proposed_tool_ids=["asn_bgp_lookup", "rdap_lookup"],
                    rationale="Confirmed across asn_bgp_lookup, rdap_lookup, and dns_lookup.",
                    status=HypothesisStatus.SUPPORTED,
                    created_by="planner",
                    created_at="2026-11-20T09:02:10+00:00",
                    updated_at="2026-11-20T09:03:05+00:00",
                    closing_artifact_id=artifacts["asn_bgp_lookup"].artifact_id,
                    closing_note="Corroborated across 3 independent deterministic sources.",
                )
            )

            # AI_INFERRED synthesis claim (EpistemicStatus.HYPOTHESIS, non-promoting)
            # citing immutable artifact SHA-256 IDs
            cited_tools = ("github_osint", "media_forensics", "asn_bgp_lookup")
            cited_artifacts = [artifacts[t] for t in cited_tools]
            cited_sha_pairs = [
                f"{a.artifact_id} (sha256:{a.raw_output_sha256[:16]})"
                for a in cited_artifacts
            ]
            ai_claim_id = short_id(
                "claim", DEMO_TARGET_ID, person.entity_id, "ASSOCIATED_WITH", handle_ops.entity_id
            )
            ai_ts = "2026-11-20T09:03:40+00:00"
            store._write(
                """INSERT OR IGNORE INTO claims
                   (claim_id, investigation_id, subject_id, predicate, object_id, object_literal,
                    status, confidence, independent_sources_json, first_seen, updated_at, direct)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ai_claim_id,
                    DEMO_TARGET_ID,
                    person.entity_id,
                    "ASSOCIATED_WITH",
                    handle_ops.entity_id,
                    None,
                    EpistemicStatus.HYPOTHESIS.value,
                    0.35,
                    canonical_json([PROVENANCE_AI_INFERRED]),
                    ai_ts,
                    ai_ts,
                    0,
                ),
            )
            for art in cited_artifacts:
                store._write(
                    """INSERT OR IGNORE INTO claim_artifacts
                       (claim_id, artifact_id, source_tool, snippet, direct)
                       VALUES (?,?,?,?,?)""",
                    (
                        ai_claim_id,
                        art.artifact_id,
                        PROVENANCE_AI_INFERRED,
                        f"[{PROVENANCE_AI_INFERRED}] Advisory synthesis citing sha256:{art.raw_output_sha256}",
                        0,
                    ),
                )

            store.add_ai_insight(
                DEMO_TARGET_ID,
                insight_id="ins_demo_aurora_synthesis",
                iteration=3,
                provider="ollama",
                model="gemma4:e4b",
                kind="reflection",
                summary=(
                    f"[{PROVENANCE_AI_INFERRED}] Advisory synthesis: Elena Vance (evance-sec) "
                    "shares operational cadence and avatar perceptual hash (a8f3c19e4b2d7055) "
                    "with Aurora Meridian infrastructure (git.aurora-meridian.example / AS64501); "
                    "secondary handle aurora-ops remains a HYPOTHESIS pending commit-log "
                    "corroboration, and the UTC-05:00 vs UTC+00:00 timezone contradiction requires "
                    f"analyst review. Cited artifacts: {', '.join(cited_sha_pairs)}."
                ),
                payload={
                    "epistemic_provenance": PROVENANCE_AI_INFERRED,
                    "status": EpistemicStatus.HYPOTHESIS.value,
                    "cited_sha256": [a.raw_output_sha256 for a in cited_artifacts],
                    "synthetic": True,
                },
                cited_artifact_ids=[a.artifact_id for a in cited_artifacts],
                epistemic_provenance=PROVENANCE_AI_INFERRED,
                created_at=ai_ts,
            )

        stats = store.stats(DEMO_TARGET_ID)
    finally:
        store.close()

    return {
        "status": "ok",
        "target_id": DEMO_TARGET_ID,
        "title": DEMO_TITLE,
        "entity_count": stats.get("entities", 0),
        "claim_count": stats.get("claims", 0),
        "contradiction_count": stats.get("contradictions", 0),
        "artifact_count": stats.get("artifacts", 0),
        "synthetic": True,
        "state_path": str(case_dir),
    }


__all__ = ["DEMO_TARGET_ID", "DEMO_TITLE", "seed_demo_case"]
