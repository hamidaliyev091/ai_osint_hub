"""SSRF-safe automatic visual & avatar harvesting and image forensics.

Downloads candidate avatars, profile images, and favicons discovered during
OSINT tool execution using :func:`hub.tools.builtin._http.fetch_safe` and
:func:`hub.security.policy.assert_safe_host` (no private/loopback/link-local
addresses, manual redirect re-validation, strict MIME/magic validation, no SVG
scripts, <= 5 MB, <= 8s timeout).

Extracts SHA-256, dimensions, sanitized EXIF/XMP/IPTC/GPS metadata, 64-bit
dHash/pHash (compatible with :mod:`hub.erkg.analytics`), and optional CLIP
embeddings when ``[local-ai]`` (``fastembed``) is enabled.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from hub.erkg.ingestion import EvidenceIngestor
from hub.erkg.resolution import is_noreply_email, is_provider_infrastructure_domain, normalize_url
from hub.erkg.store import ERKGStore
from hub.models import (
    EdgeType,
    EntityType,
    EpistemicStatus,
    EvidenceArtifact,
    ScopeConfig,
    param_hash,
    short_id,
    utc_now,
)
from hub.security.policy import assert_safe_host
from hub.security.quarantine import sanitize_visual_text
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate
from hub.tools.builtin import _http
from hub.tools.builtin.media_forensics import _extract_exif_and_hashes

MAX_VISUAL_BYTES = 5 * 1024 * 1024
VISUAL_FETCH_TIMEOUT_SEC = 8
MAX_CANDIDATES_PER_RUN = 5

ALLOWED_IMAGE_MIME_TYPES = frozenset({
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/webp",
    "image/gif",
    "image/x-icon",
    "image/vnd.microsoft.icon",
})
ALLOWED_IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico"})
PIL_FORMAT_TO_EXT = {
    "PNG": ".png",
    "JPEG": ".jpg",
    "WEBP": ".webp",
    "GIF": ".gif",
    "ICO": ".ico",
}
PIL_FORMAT_TO_MIME = {
    "PNG": "image/png",
    "JPEG": "image/jpeg",
    "WEBP": "image/webp",
    "GIF": "image/gif",
    "ICO": "image/x-icon",
}

_OG_IMAGE_RE = re.compile(
    r"""<meta[^>]+(?:property|name)=["'](?:og:image|twitter:image)["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)
_OG_IMAGE_REV_RE = re.compile(
    r"""<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["'](?:og:image|twitter:image)["']""",
    re.IGNORECASE,
)
_LINK_ICON_RE = re.compile(
    r"""<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']""",
    re.IGNORECASE,
)
_LINK_ICON_REV_RE = re.compile(
    r"""<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*icon[^"']*["']""",
    re.IGNORECASE,
)
_JSON_IMAGE_KEYS = ("avatar_url", "thumbnailUrl", "thumbnail_url", "og_image", "twitter_image", "favicon_url")
_SAFE_SLUG_RE = re.compile(r"[^a-z0-9_-]+")


def _clean_slug(text: str, *, max_len: int = 32) -> str:
    slug = _SAFE_SLUG_RE.sub("_", str(text or "").strip().lower()).strip("_")
    return slug[:max_len] or "media"


def safe_media_filename(sha256: str, ext: str, slug: str = "") -> str:
    """Build a path-traversal-proof media filename inside ``<case_dir>/media``."""
    clean_ext = ext.lower() if ext.lower() in ALLOWED_IMAGE_EXTENSIONS else ".png"
    prefix = _clean_slug(slug, max_len=28)
    digest = re.sub(r"[^a-f0-9]", "", (sha256 or "").lower())[:16] or "00000000"
    return f"{prefix}_{digest}{clean_ext}"


def _looks_like_svg_or_html(data: bytes) -> bool:
    head = data[:512].lstrip().lower()
    return (
        head.startswith(b"<svg")
        or head.startswith(b"<?xml")
        or head.startswith(b"<!doctype")
        or head.startswith(b"<html")
        or b"<svg" in head[:256]
    )


def validate_image_bytes(
    data: bytes,
    *,
    content_type: str = "",
) -> tuple[bool, str, str, str]:
    """Validate image payload size, MIME type, magic bytes, and Pillow decode.

    Never accepts SVG, HTML, or script payloads.
    Returns ``(ok, reason, pil_format, ext)``.
    """
    if not data:
        return False, "empty image payload", "", ""
    if len(data) > MAX_VISUAL_BYTES:
        return False, f"image exceeds MAX_VISUAL_BYTES ({MAX_VISUAL_BYTES})", "", ""
    if _looks_like_svg_or_html(data):
        return False, "SVG/HTML markup rejected for visual safety", "", ""

    ct_base = str(content_type or "").split(";", 1)[0].strip().lower()
    if ct_base:
        if "svg" in ct_base or ct_base.startswith("text/"):
            return False, f"disallowed image content-type: {ct_base}", "", ""
        if ct_base != "application/octet-stream" and ct_base not in ALLOWED_IMAGE_MIME_TYPES:
            return False, f"unsupported image content-type: {ct_base}", "", ""

    try:
        from PIL import Image

        with Image.open(io.BytesIO(data)) as img:
            fmt = str(img.format or "").upper()
            width, height = int(img.width), int(img.height)
            if fmt not in PIL_FORMAT_TO_EXT:
                return False, f"disallowed image format: {fmt or 'unknown'}", "", ""
            if width <= 0 or height <= 0 or width > 16384 or height > 16384:
                return False, f"unreasonable image dimensions: {width}x{height}", "", ""
            img.load()
    except Exception as exc:  # noqa: BLE001
        return False, f"invalid or unsupported image data: {type(exc).__name__}", "", ""

    return True, "", fmt, PIL_FORMAT_TO_EXT[fmt]


def inspect_image_bytes(
    data: bytes,
    *,
    source_url: str = "",
    source_label: str = "media",
    content_type: str = "",
    compute_clip: bool = True,
) -> dict[str, Any]:
    """Validate image bytes and extract SHA-256, dimensions, EXIF/GPS, and pHash/dHash."""
    ok, reason, fmt, ext = validate_image_bytes(data, content_type=content_type)
    if not ok:
        raise ValueError(reason)

    sha256 = hashlib.sha256(data).hexdigest()
    flags: list[str] = []
    meta = _extract_exif_and_hashes(data, flags)
    mime = PIL_FORMAT_TO_MIME.get(fmt, "image/png")

    clip_vec: list[float] | None = None
    if compute_clip:
        try:
            from hub.ai.embeddings import embed_image_bytes

            clip_vec = embed_image_bytes(data)
        except Exception:  # noqa: BLE001
            clip_vec = None

    return {
        "sha256": sha256,
        "byte_length": len(data),
        "format": fmt,
        "ext": ext,
        "content_type": mime,
        "width": meta.get("width"),
        "height": meta.get("height"),
        "phash": meta.get("phash") or "",
        "dhash": meta.get("dhash") or "",
        "exif": meta.get("exif") or {},
        "xmp": meta.get("xmp") or {},
        "iptc": meta.get("iptc") or {},
        "png_text": meta.get("png_text") or {},
        "gps": meta.get("gps"),
        "has_gps": bool(meta.get("gps")),
        "visual_injection_flags": flags,
        "injection_detected": bool(flags),
        "source_url": sanitize_visual_text(source_url, max_len=500),
        "source_label": sanitize_visual_text(source_label, max_len=80) or "media",
        "clip_embedding_available": clip_vec is not None,
        "clip_embedding": clip_vec,
    }


def _is_candidate_image_url(url: str) -> bool:
    try:
        parts = urlsplit(str(url or "").strip())
    except ValueError:
        return False
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return False
    lower_path = (parts.path or "").lower()
    if lower_path.endswith((".svg", ".svgz")):
        return False
    return True


def _extract_json_candidates(
    obj: Any,
    out: list[dict[str, str]],
    *,
    tool_id: str,
    base_url: str = "",
) -> None:
    if isinstance(obj, dict):
        login = str(obj.get("login") or obj.get("preferredUsername") or "").strip()
        for key in _JSON_IMAGE_KEYS:
            val = obj.get(key)
            if isinstance(val, str) and val.strip():
                resolved = urljoin(base_url, val.strip()) if base_url else val.strip()
                if _is_candidate_image_url(resolved):
                    label = (
                        "github_avatar" if tool_id == "github_osint" and key == "avatar_url"
                        else "gravatar_avatar" if tool_id == "gravatar_lookup"
                        else "site_favicon" if key == "favicon_url"
                        else f"{tool_id}_{key}"
                    )
                    out.append({
                        "url": resolved,
                        "source_label": label,
                        "entity_hint": login,
                    })
        for child in obj.values():
            _extract_json_candidates(child, out, tool_id=tool_id, base_url=base_url)
    elif isinstance(obj, list):
        for item in obj[:50]:
            _extract_json_candidates(item, out, tool_id=tool_id, base_url=base_url)


def extract_visual_candidates(
    tool_id: str,
    stdout: str,
    parse_output: ParseOutput | None = None,
) -> list[dict[str, str]]:
    """Extract bounded candidate image URLs from structured/text OSINT results."""
    candidates: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    def push(url: str, source_label: str, entity_hint: str = "") -> None:
        clean = str(url or "").strip()
        if not _is_candidate_image_url(clean):
            return
        norm = normalize_url(clean)
        if not norm or norm in seen_urls:
            return
        seen_urls.add(norm)
        candidates.append({
            "url": clean,
            "source_label": source_label,
            "entity_hint": entity_hint,
        })

    text = (stdout or "").strip()
    base_url = ""
    if text:
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            raw_target = str(payload.get("target") or payload.get("url") or "").strip()
            if raw_target.startswith(("http://", "https://")):
                base_url = raw_target
            elif raw_target and "." in raw_target and "@" not in raw_target:
                base_url = f"https://{raw_target}"
            tmp: list[dict[str, str]] = []
            _extract_json_candidates(payload, tmp, tool_id=tool_id, base_url=base_url)
            for item in tmp:
                push(item["url"], item["source_label"], item.get("entity_hint", ""))
            if tool_id == "gravatar_lookup" and payload.get("md5"):
                md5 = str(payload["md5"]).strip().lower()
                email_hint = str(payload.get("email") or "").strip().lower()
                if re.fullmatch(r"[a-f0-9]{32}", md5) and payload.get("exists"):
                    push(
                        f"https://www.gravatar.com/avatar/{md5}?s=256&d=404",
                        "gravatar_avatar",
                        email_hint,
                    )

        for regex, label in (
            (_OG_IMAGE_RE, f"{tool_id}_og_image"),
            (_OG_IMAGE_REV_RE, f"{tool_id}_og_image"),
            (_LINK_ICON_RE, "site_favicon"),
            (_LINK_ICON_REV_RE, "site_favicon"),
        ):
            for match in regex.finditer(text[:200_000]):
                href = urljoin(base_url, match.group(1).strip()) if base_url else match.group(1).strip()
                push(href, label)

    if parse_output is not None:
        for ent in parse_output.entities:
            if ent.type == EntityType.EMAIL:
                addr = ent.value.strip().lower()
                if addr and "@" in addr and not is_noreply_email(addr) and not "[bot]" in addr:
                    md5 = hashlib.md5(addr.encode("utf-8")).hexdigest()
                    push(
                        f"https://www.gravatar.com/avatar/{md5}?s=256&d=404",
                        "gravatar_avatar",
                        addr,
                    )
            elif ent.type == EntityType.DOMAIN and tool_id in {"http_headers", "photon_crawler", "favicon_hash"}:
                dom = ent.value.strip().lower()
                if dom and not is_provider_infrastructure_domain(dom):
                    push(f"https://{dom}/favicon.ico", "site_favicon", dom)

    return candidates[:MAX_CANDIDATES_PER_RUN]


async def fetch_and_save_visual(
    url: str,
    media_dir: Path,
    *,
    source_label: str = "harvested",
    scope: ScopeConfig | None = None,
    timeout_sec: int = VISUAL_FETCH_TIMEOUT_SEC,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Optional[dict[str, Any]]:
    """SSRF-guarded download, validation, forensic inspection, and save to ``media_dir``."""
    if not _is_candidate_image_url(url):
        return None
    host = _http.extract_host(url)
    if scope is not None and scope.deny_domains:
        if any(host == d.lower() or host.endswith("." + d.lower()) for d in scope.deny_domains):
            return None

    eff_timeout = min(max(1, int(timeout_sec)), VISUAL_FETCH_TIMEOUT_SEC)
    client_kwargs: dict[str, Any] = {
        "timeout": _http.timeout_of(eff_timeout),
        "follow_redirects": False,
        "headers": {
            "User-Agent": _http.USER_AGENT,
            "Accept": "image/png,image/jpeg,image/webp,image/gif,image/x-icon,*/*;q=0.5",
        },
    }
    if transport is not None:
        client_kwargs["transport"] = transport

    async with httpx.AsyncClient(**client_kwargs) as client:
        fetched = await _http.fetch_safe(
            client,
            url,
            validate=assert_safe_host,
            max_bytes=MAX_VISUAL_BYTES,
        )
    if not fetched.ok or not (200 <= fetched.status_code < 300):
        return None
    if fetched.truncated or len(fetched.body) > MAX_VISUAL_BYTES:
        return None

    try:
        info = inspect_image_bytes(
            fetched.body,
            source_url=fetched.url or url,
            source_label=source_label,
            content_type=fetched.headers.get("content-type", ""),
        )
    except ValueError:
        return None

    media_dir.mkdir(parents=True, exist_ok=True)
    filename = safe_media_filename(info["sha256"], info["ext"], slug=source_label)
    dest = (media_dir / filename).resolve()
    if not dest.is_relative_to(media_dir.resolve()):
        return None
    tmp = dest.with_name(f".{filename}.tmp.{os.getpid()}")
    tmp.write_bytes(fetched.body)
    os.replace(tmp, dest)

    info["filename"] = filename
    info["media_file"] = f"media/{filename}"
    return info


async def harvest_from_tool_output(
    store: ERKGStore,
    target_id: str,
    media_dir: Path,
    *,
    tool_id: str,
    stdout: str,
    parse_output: ParseOutput | None = None,
    scope: ScopeConfig | None = None,
    timestamp: Optional[str] = None,
    max_images: int = MAX_CANDIDATES_PER_RUN,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, Any]]:
    """Harvest candidate images from a live tool run and record them in ERKG."""
    candidates = extract_visual_candidates(tool_id, stdout, parse_output)[:max_images]
    if not candidates:
        return []

    existing_urls = {
        e.canonical_value: e
        for e in store.list_entities(target_id, types=[EntityType.URL])
        if (e.metadata or {}).get("media_asset")
    }
    to_fetch = [
        cand for cand in candidates
        if normalize_url(cand["url"]) not in existing_urls
    ]
    if not to_fetch:
        return []

    results = await asyncio.gather(
        *(
            fetch_and_save_visual(
                cand["url"],
                media_dir,
                source_label=cand["source_label"],
                scope=scope,
                transport=transport,
            )
            for cand in to_fetch
        ),
        return_exceptions=True,
    )

    stamp = timestamp or utc_now()
    saved: list[dict[str, Any]] = []
    entity_candidates: list[EntityCandidate] = []
    relation_candidates: list[RelationCandidate] = []

    for cand, item in zip(to_fetch, results):
        if isinstance(item, BaseException) or item is None:
            continue
        saved.append(item)
        media_url = item["source_url"] or cand["url"]
        sha256 = item["sha256"]
        phash = item["phash"]
        dhash = item["dhash"]
        hash_attrs: dict[str, Any] = {"sha256": sha256}
        if phash:
            hash_attrs["phash"] = phash
        if dhash:
            hash_attrs["dhash"] = dhash

        meta = {
            "provenance": "MEDIA_FORENSICS",
            "media_asset": True,
            "kind": "MEDIA_ASSET",
            "media_file": item["media_file"],
            "filename": item["filename"],
            "source_tool": tool_id,
            "source_label": item["source_label"],
            "content_type": item["content_type"],
            "width": item["width"],
            "height": item["height"],
            "sha256": sha256,
            "phash": phash,
            "dhash": dhash,
            "exif": item["exif"],
            "gps": item["gps"],
            "has_gps": item["has_gps"],
            "injection_detected": item["injection_detected"],
            "visual_injection_flags": item["visual_injection_flags"],
            "clip_embedding_available": item["clip_embedding_available"],
        }
        if item.get("clip_embedding"):
            meta["clip_embedding"] = item["clip_embedding"]

        evidence = (
            f"Harvested visual {item['filename']} ({item['width']}x{item['height']}, "
            f"sha256={sha256[:12]}) from {media_url}"
        )
        entity_candidates.append(EntityCandidate(
            type=EntityType.URL,
            value=media_url,
            confidence=0.85,
            metadata=meta,
            attributes=hash_attrs,
            evidence=evidence,
            direct=True,
        ))
        entity_candidates.append(EntityCandidate(
            type=EntityType.HASH,
            value=sha256,
            confidence=0.90,
            metadata={
                "provenance": "MEDIA_FORENSICS",
                "algorithm": "sha256",
                "phash": phash,
                "dhash": dhash,
                "media_file": item["media_file"],
            },
            attributes=hash_attrs,
            evidence=evidence,
            direct=True,
        ))
        relation_candidates.append(RelationCandidate(
            subject_type=EntityType.URL,
            subject_value=media_url,
            predicate=EdgeType.ASSOCIATED_WITH,
            object_type=EntityType.HASH,
            object_value=sha256,
            confidence=0.90,
            evidence=evidence,
            direct=True,
        ))

        hint = cand.get("entity_hint") or ""
        if hint:
            hint_type = (
                EntityType.EMAIL if "@" in hint
                else EntityType.DOMAIN if "." in hint and tool_id in {"http_headers", "photon_crawler", "favicon_hash"}
                else EntityType.USERNAME
            )
            relation_candidates.append(RelationCandidate(
                subject_type=hint_type,
                subject_value=hint,
                predicate=EdgeType.ASSOCIATED_WITH,
                object_type=EntityType.URL,
                object_value=media_url,
                confidence=0.80,
                evidence=evidence,
                direct=True,
            ))

    if entity_candidates:
        harvest_output = ParseOutput(
            entities=entity_candidates,
            relations=relation_candidates,
            parser_version="visual_harvester-2.1.0",
        )
        raw_summary = json.dumps(
            [{k: v for k, v in item.items() if k != "clip_embedding"} for item in saved],
            sort_keys=True,
        )
        artifact = EvidenceArtifact(
            artifact_id=short_id("art", target_id, "visual_harvester", tool_id, stamp),
            investigation_id=target_id,
            source_tool="visual_harvester",
            invocation_params_hash=param_hash("visual_harvester", {"source_tool": tool_id}),
            timestamp_utc=stamp,
            raw_evidence_snippet=f"Harvested {len(saved)} verified visual(s) from {tool_id}",
            raw_output_sha256=hashlib.sha256(raw_summary.encode("utf-8")).hexdigest(),
            parser_version="2.1.0",
            epistemic_status=EpistemicStatus.SINGLE_SOURCE_LEAD,
            confidence=0.85,
            stdout_bytes=len(raw_summary.encode("utf-8")),
        )
        with store.transaction():
            store.add_artifact(artifact)
            EvidenceIngestor(store).ingest(
                target_id,
                harvest_output,
                artifact_id=artifact.artifact_id,
                tool_id="visual_harvester",
                accepted_types=[EntityType.URL, EntityType.HASH],
                timestamp=stamp,
            )
    return saved


__all__ = [
    "MAX_VISUAL_BYTES",
    "VISUAL_FETCH_TIMEOUT_SEC",
    "ALLOWED_IMAGE_MIME_TYPES",
    "ALLOWED_IMAGE_EXTENSIONS",
    "validate_image_bytes",
    "safe_media_filename",
    "inspect_image_bytes",
    "extract_visual_candidates",
    "fetch_and_save_visual",
    "harvest_from_tool_output",
]
