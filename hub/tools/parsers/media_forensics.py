"""Deterministic parser for the builtin ``media_forensics`` collector.

Pure deterministic function (no network, no AI calls). Emits:
* ``HASH`` entity (with ``sha256``, ``phash``, ``dhash`` attributes)
* ``URL`` entity for the media URL
* ``LOCATION`` entity if GPS coordinates are present in EXIF
* ``PERSON`` / ``ORGANIZATION`` / ``USERNAME`` / ``EMAIL`` / ``DOMAIN``
  candidates extracted from sanitized EXIF/XMP/IPTC/OCR metadata
* VLM-derived candidates (if ``vlm_extraction`` is present) strictly marked with:
  ``direct=False``, ``confidence <= 0.45``,
  ``metadata={"provenance": "AI_INFERRED", "vlm_derived": True}``,
  ``attributes={"epistemic_provenance": "AI_INFERRED"}``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from hub.models import EdgeType, EntityType
from hub.security.quarantine import sanitize_visual_text
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse", "PARSER_VERSION"]

PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
_MAX_VLM_CONFIDENCE = 0.45

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_HANDLE_RE = re.compile(r"(?<![\w.])@([A-Za-z0-9_.\-]{2,32})\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,12}\b", re.IGNORECASE)


def parse(raw: str, target: str = "") -> ParseOutput:
    """Parse ``media_forensics`` collector JSON stdout; never raises."""
    try:
        return _parse(raw, target)
    except Exception as exc:  # noqa: BLE001
        return ParseOutput(
            warnings=[f"media_forensics parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _clean(value: Any, max_len: int = 240) -> str:
    return sanitize_visual_text(value, max_len=max_len)


def _parse(raw: str, target: str) -> ParseOutput:
    text = (raw or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(
            warnings=[f"invalid JSON from media_forensics: {exc}"],
            parser_version=PARSER_VERSION,
        )
    if not isinstance(data, dict):
        return ParseOutput(
            warnings=[f"unexpected media_forensics payload: {type(data).__name__}"],
            parser_version=PARSER_VERSION,
        )

    warnings: list[str] = [str(w) for w in (data.get("warnings") or []) if str(w).strip()]
    if data.get("injection_detected"):
        flags = ", ".join(str(f) for f in (data.get("visual_injection_flags") or []))
        warnings.append(f"visual prompt injection detected ({flags or 'flagged'})")

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str, bool]] = set()

    def add_entity(
        entity_type: EntityType,
        value: str,
        confidence: float,
        evidence: str,
        *,
        metadata: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
        direct: bool = True,
    ) -> bool:
        val = _clean(value, max_len=300)
        if not val:
            return False
        key = (entity_type.value, val.lower(), direct)
        if key in seen_entities:
            return False
        seen_entities.add(key)
        entities.append(
            EntityCandidate(
                type=entity_type,
                value=val,
                confidence=round(max(0.0, min(1.0, confidence)), 3),
                metadata=dict(metadata or {}),
                attributes=dict(attributes or {}),
                evidence=_clean(evidence, max_len=MAX_EVIDENCE),
                direct=direct,
            )
        )
        return True

    def add_relation(
        subject_type: EntityType,
        subject_value: str,
        predicate: EdgeType,
        object_type: EntityType,
        object_value: str,
        confidence: float,
        evidence: str,
        *,
        metadata: dict[str, Any] | None = None,
        direct: bool = True,
    ) -> None:
        s_val = _clean(subject_value, max_len=300)
        o_val = _clean(object_value, max_len=300)
        if not s_val or not o_val or s_val.lower() == o_val.lower():
            return
        relations.append(
            RelationCandidate(
                subject_type=subject_type,
                subject_value=s_val,
                predicate=predicate,
                object_type=object_type,
                object_value=o_val,
                confidence=round(max(0.0, min(1.0, confidence)), 3),
                metadata=dict(metadata or {}),
                evidence=_clean(evidence, max_len=MAX_EVIDENCE),
                direct=direct,
            )
        )

    url = _clean(data.get("url") or target, max_len=500)
    sha256 = _clean(data.get("sha256"), max_len=128).lower()
    phash = _clean(data.get("phash"), max_len=64).lower()
    dhash = _clean(data.get("dhash"), max_len=64).lower()
    content_type = _clean(data.get("content_type"), max_len=120)
    dims = data.get("dimensions") if isinstance(data.get("dimensions"), dict) else {}
    width = dims.get("width")
    height = dims.get("height")

    hash_attrs: dict[str, Any] = {"sha256": sha256}
    if phash:
        hash_attrs["phash"] = phash
    if dhash:
        hash_attrs["dhash"] = dhash
    if content_type:
        hash_attrs["content_type"] = content_type
    if width is not None and height is not None:
        hash_attrs["dimensions"] = f"{width}x{height}"

    if url:
        add_entity(
            EntityType.URL,
            url,
            0.90,
            f"Media artifact fetched from {url}",
            metadata={"provenance": "MEDIA_FORENSICS", "content_type": content_type},
            attributes=hash_attrs,
            direct=True,
        )

    if sha256:
        hash_evidence = f"Media SHA-256={sha256}" + (f" phash={phash}" if phash else "") + (f" dhash={dhash}" if dhash else "")
        add_entity(
            EntityType.HASH,
            sha256,
            0.95,
            hash_evidence,
            metadata={"provenance": "MEDIA_FORENSICS", "algorithm": "sha256"},
            attributes=hash_attrs,
            direct=True,
        )
        if url:
            add_relation(
                EntityType.URL,
                url,
                EdgeType.ASSOCIATED_WITH,
                EntityType.HASH,
                sha256,
                0.95,
                hash_evidence,
                direct=True,
            )

    subject_type = EntityType.URL if url else EntityType.HASH
    subject_val = url or sha256

    # Deterministic GPS location from EXIF
    gps = data.get("gps") if isinstance(data.get("gps"), dict) else None
    if gps and gps.get("lat") is not None and gps.get("lon") is not None:
        coords = _clean(gps.get("coords") or f"{gps['lat']}, {gps['lon']}", max_len=80)
        gps_evidence = f"EXIF GPS coordinates: {coords}"
        add_entity(
            EntityType.LOCATION,
            coords,
            0.85,
            gps_evidence,
            metadata={"provenance": "MEDIA_FORENSICS", "source": "exif_gps"},
            attributes={"latitude": gps["lat"], "longitude": gps["lon"], "gps_coords": coords},
            direct=True,
        )
        if subject_val:
            add_relation(
                subject_type,
                subject_val,
                EdgeType.LOCATED_IN,
                EntityType.LOCATION,
                coords,
                0.85,
                gps_evidence,
                direct=True,
            )

    # Deterministic EXIF / XMP / IPTC metadata entities
    exif = data.get("exif") if isinstance(data.get("exif"), dict) else {}
    xmp = data.get("xmp") if isinstance(data.get("xmp"), dict) else {}
    iptc = data.get("iptc") if isinstance(data.get("iptc"), dict) else {}
    png_text = data.get("png_text") if isinstance(data.get("png_text"), dict) else {}

    author_candidates = [
        ("exif", exif.get("author")),
        ("xmp", xmp.get("author")),
        ("iptc", iptc.get("author")),
        ("png_text", png_text.get("Author")),
    ]
    for src, raw_author in author_candidates:
        author = _clean(raw_author, max_len=120)
        if author:
            ev = f"Embedded {src} author/artist: {author}"
            add_entity(
                EntityType.PERSON,
                author,
                0.70,
                ev,
                metadata={"provenance": "MEDIA_FORENSICS", "source": src},
                direct=True,
            )
            if subject_val:
                add_relation(
                    subject_type,
                    subject_val,
                    EdgeType.ASSOCIATED_WITH,
                    EntityType.PERSON,
                    author,
                    0.70,
                    ev,
                    direct=True,
                )

    org_candidates = [
        ("exif.copyright", exif.get("copyright")),
        ("xmp.rights", xmp.get("copyright")),
        ("iptc.credit", iptc.get("credit")),
        ("iptc.source", iptc.get("source")),
        ("iptc.copyright", iptc.get("copyright")),
    ]
    for src, raw_org in org_candidates:
        org = _clean(raw_org, max_len=160)
        if org:
            ev = f"Embedded {src}: {org}"
            add_entity(
                EntityType.ORGANIZATION,
                org,
                0.65,
                ev,
                metadata={"provenance": "MEDIA_FORENSICS", "source": src},
                direct=True,
            )
            if subject_val:
                add_relation(
                    subject_type,
                    subject_val,
                    EdgeType.ASSOCIATED_WITH,
                    EntityType.ORGANIZATION,
                    org,
                    0.65,
                    ev,
                    direct=True,
                )

    for city_key in (iptc.get("city"), xmp.get("city")):
        city = _clean(city_key, max_len=120)
        if city:
            add_entity(
                EntityType.LOCATION,
                city,
                0.65,
                f"Embedded metadata location: {city}",
                metadata={"provenance": "MEDIA_FORENSICS"},
                direct=True,
            )

    # Extract emails, @handles, and domains deterministically from sanitized metadata + OCR
    ocr = data.get("ocr") if isinstance(data.get("ocr"), dict) else {}
    text_blobs: list[str] = []
    if ocr.get("text"):
        text_blobs.append(_clean(ocr.get("text"), max_len=2000))
    for mapping in (exif, xmp, iptc, png_text):
        for val in mapping.values():
            if isinstance(val, str) and val.strip():
                text_blobs.append(_clean(val, max_len=400))

    combined_text = "\n".join(text_blobs)
    for email in sorted(set(_EMAIL_RE.findall(combined_text)))[:15]:
        add_entity(
            EntityType.EMAIL,
            email.lower(),
            0.70,
            f"Deterministic media metadata/OCR email: {email.lower()}",
            metadata={"provenance": "MEDIA_FORENSICS"},
            direct=True,
        )
    for handle in sorted(set(_HANDLE_RE.findall(combined_text)))[:15]:
        add_entity(
            EntityType.USERNAME,
            handle,
            0.60,
            f"Deterministic media metadata/OCR handle: @{handle}",
            metadata={"provenance": "MEDIA_FORENSICS"},
            direct=True,
        )
    for dom in sorted(set(_DOMAIN_RE.findall(combined_text)))[:15]:
        low_dom = dom.lower()
        if any(low_dom.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp")):
            continue
        add_entity(
            EntityType.DOMAIN,
            low_dom,
            0.60,
            f"Deterministic media metadata/OCR domain: {low_dom}",
            metadata={"provenance": "MEDIA_FORENSICS"},
            direct=True,
        )

    # VLM-derived candidates: STRICT AI_INFERRED epistemic invariant
    vlm = data.get("vlm_extraction")
    if isinstance(vlm, dict):
        try:
            vlm_conf = min(_MAX_VLM_CONFIDENCE, max(0.05, float(vlm.get("confidence", 0.35))))
        except (TypeError, ValueError):
            vlm_conf = 0.35
        vlm_provider = _clean(vlm.get("provider"), max_len=40)
        vlm_model = _clean(vlm.get("model"), max_len=80)
        vlm_meta = {
            "provenance": "AI_INFERRED",
            "vlm_derived": True,
            "epistemic_provenance": "AI_INFERRED",
            "ai_provider": vlm_provider,
            "ai_model": vlm_model,
        }
        vlm_attrs = {
            "epistemic_provenance": "AI_INFERRED",
            "ai_provider": vlm_provider,
            "ai_model": vlm_model,
        }
        vlm_buckets: list[tuple[str, EntityType]] = [
            ("persons", EntityType.PERSON),
            ("organizations", EntityType.ORGANIZATION),
            ("usernames", EntityType.USERNAME),
            ("emails", EntityType.EMAIL),
            ("domains", EntityType.DOMAIN),
            ("locations", EntityType.LOCATION),
        ]
        for field_name, etype in vlm_buckets:
            items = vlm.get(field_name)
            if not isinstance(items, list):
                continue
            for raw_item in items[:15]:
                val = _clean(raw_item, max_len=200)
                if not val:
                    continue
                ev = f"VLM-inferred {etype.value} ({vlm_provider or 'vlm'}): {val}"
                added = add_entity(
                    etype,
                    val,
                    vlm_conf,
                    ev,
                    metadata=vlm_meta,
                    attributes=vlm_attrs,
                    direct=False,
                )
                if added and subject_val:
                    add_relation(
                        subject_type,
                        subject_val,
                        EdgeType.MENTIONED_IN if etype != EntityType.LOCATION else EdgeType.LOCATED_IN,
                        etype,
                        val,
                        vlm_conf,
                        ev,
                        metadata=vlm_meta,
                        direct=False,
                    )

    return ParseOutput(
        entities=entities,
        relations=relations,
        parser_version=PARSER_VERSION,
        warnings=warnings[:20],
    )
