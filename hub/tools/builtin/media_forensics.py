"""Python-native vision & media forensics collector (SSRF-guarded).

Performs 100% offline deterministic media forensics by default:
* SSRF-safe bounded HTTP fetch via :func:`hub.tools.builtin._http.fetch_safe`
  (blocks private/loopback/metadata IPs, 10 MB max download cap).
* SHA-256 hash, content-type, and pixel dimensions.
* EXIF / XMP / IPTC metadata extraction (GPS lat/lon, camera make/model,
  software, author/artist, copyright, timestamps, descriptions).
* 64-bit perceptual hashes: ``dhash`` and ``phash`` (16-char hex).
* Optional shell-free local OCR via ``tesseract`` if installed on PATH.
* Optional quarantined VLM structured JSON extraction (downscaled <= 1024 px)
  ONLY when ``use_vlm=True`` / AI vision is enabled.

All extracted EXIF/XMP/IPTC/OCR/VLM strings are sanitized through
:func:`hub.security.quarantine.sanitize_visual_text` and scanned with
:func:`hub.security.quarantine.detect_visual_injection`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

from hub.models import ErrorCode, ScopeConfig
from hub.security.policy import host_in_scope
from hub.security.quarantine import (
    VISUAL_SECURITY_SYSTEM_PROMPT,
    detect_visual_injection,
    sanitize_visual_text,
    wrap_visual_untrusted,
)
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin import _http

__all__ = [
    "MAX_MEDIA_BYTES",
    "compute_dhash",
    "compute_phash",
    "extract_media_forensics",
    "collect",
]

MAX_MEDIA_BYTES = 10 * 1024 * 1024
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_MAX_VLM_DIM = 1024
_DOCTYPE_ENTITY_RE = re.compile(r"<!(?:DOCTYPE|ENTITY)\b[^>]*>", re.IGNORECASE)
_XMP_BLOCK_RE = re.compile(rb"<x:xmpmeta\b.*?</x:xmpmeta>|<rdf:RDF\b.*?</rdf:RDF>", re.DOTALL)

# Precomputed 32x8 cosine matrix for fast pure-Python 2D DCT-II (pHash)
_COS_32_8: list[list[float]] = [
    [math.cos(((2 * x + 1) * u * math.pi) / 64.0) for u in range(8)]
    for x in range(32)
]


def _ratio_to_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        denom = float(value.denominator)
        return float(value.numerator) / denom if denom else None
    if isinstance(value, (tuple, list)) and len(value) == 2:
        denom = float(value[1])
        return float(value[0]) / denom if denom else None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dms_to_decimal(dms: Any, ref: Any) -> float | None:
    if not isinstance(dms, (tuple, list)) or len(dms) < 3:
        return None
    deg = _ratio_to_float(dms[0])
    minutes = _ratio_to_float(dms[1])
    seconds = _ratio_to_float(dms[2])
    if deg is None or minutes is None or seconds is None:
        return None
    decimal = abs(deg) + (abs(minutes) / 60.0) + (abs(seconds) / 3600.0)
    ref_str = str(ref or "").strip().upper()
    if ref_str in {"S", "W"}:
        decimal = -decimal
    return round(decimal, 6)


def _record_text(
    raw_value: Any,
    flags: list[str],
    *,
    max_len: int = 500,
) -> str:
    if raw_value is None:
        return ""
    if isinstance(raw_value, bytes):
        raw_str = raw_value.decode("utf-8", errors="replace")
    else:
        raw_str = str(raw_value)
    if not raw_str.strip():
        return ""
    for hit in detect_visual_injection(raw_str):
        if hit not in flags:
            flags.append(hit)
    return sanitize_visual_text(raw_str, max_len=max_len)


def _compute_dhash_from_gray(pixels_9x8: list[int]) -> str:
    bits = 0
    for row in range(8):
        offset = row * 9
        for col in range(8):
            bits = (bits << 1) | (1 if pixels_9x8[offset + col] > pixels_9x8[offset + col + 1] else 0)
    return f"{bits:016x}"


def _compute_phash_from_gray(pixels_32x32: list[int]) -> str:
    # Separable 2D DCT-II: first along rows (32 -> 8), then columns (32 -> 8)
    row_dct = [[0.0] * 8 for _ in range(32)]
    for r in range(32):
        base = r * 32
        for u in range(8):
            acc = 0.0
            for x in range(32):
                acc += pixels_32x32[base + x] * _COS_32_8[x][u]
            row_dct[r][u] = acc

    coeffs: list[float] = []
    for v in range(8):
        for u in range(8):
            acc = 0.0
            for y in range(32):
                acc += row_dct[y][u] * _COS_32_8[y][v]
            coeffs.append(acc)

    # Exclude DC component coeffs[0] when computing median for brightness invariance
    ac = sorted(coeffs[1:])
    median = ac[len(ac) // 2] if ac else 0.0
    bits = 0
    for val in coeffs:
        bits = (bits << 1) | (1 if val > median else 0)
    return f"{bits:016x}"


def compute_dhash(image: Any) -> str | None:
    """Compute a 64-bit dHash (16-char lowercase hex) from a Pillow Image."""
    try:
        from PIL import Image

        resample = getattr(Image, "Resampling", Image).LANCZOS
        gray = image.convert("L").resize((9, 8), resample)
        pixels = list(gray.tobytes())
        if len(pixels) != 72:
            return None
        return _compute_dhash_from_gray(pixels)
    except Exception:  # noqa: BLE001
        return None


def compute_phash(image: Any) -> str | None:
    """Compute a 64-bit DCT pHash (16-char lowercase hex) from a Pillow Image."""
    try:
        from PIL import Image

        resample = getattr(Image, "Resampling", Image).LANCZOS
        gray = image.convert("L").resize((32, 32), resample)
        pixels = list(gray.tobytes())
        if len(pixels) != 1024:
            return None
        return _compute_phash_from_gray(pixels)
    except Exception:  # noqa: BLE001
        return None


def _sniff_dimensions_no_pil(data: bytes) -> tuple[str, int | None, int | None]:
    """Minimal header fallback for PNG/GIF/JPEG if Pillow is unavailable."""
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return "PNG", w, h
    if data[:6] in {b"GIF87a", b"GIF89a"} and len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        return "GIF", w, h
    if data.startswith(b"\xff\xd8"):
        return "JPEG", None, None
    return "", None, None


def _parse_xmp(raw_bytes: bytes, image_info: dict[str, Any], flags: list[str]) -> dict[str, Any]:
    xmp_chunks: list[str] = []
    info_xmp = image_info.get("XML:com.adobe.xmp") or image_info.get("xmp")
    if isinstance(info_xmp, bytes):
        xmp_chunks.append(info_xmp.decode("utf-8", errors="replace"))
    elif isinstance(info_xmp, str):
        xmp_chunks.append(info_xmp)
    if not xmp_chunks:
        for match in _XMP_BLOCK_RE.findall(raw_bytes[:512 * 1024]):
            xmp_chunks.append(match.decode("utf-8", errors="replace"))

    out: dict[str, Any] = {}
    for chunk in xmp_chunks[:2]:
        cleaned_xml = _DOCTYPE_ENTITY_RE.sub("", chunk).strip()
        if not cleaned_xml:
            continue
        try:
            root = ET.fromstring(cleaned_xml)
        except ET.ParseError:
            continue
        target_tags = {
            "creator": "author",
            "rights": "copyright",
            "description": "description",
            "title": "title",
            "creatortool": "software",
            "source": "source",
            "city": "city",
            "country": "country",
        }
        for elem in root.iter():
            local = elem.tag.rsplit("}", 1)[-1].lower()
            if local in target_tags and elem.text and elem.text.strip():
                key = target_tags[local]
                val = _record_text(elem.text, flags, max_len=400)
                if val and key not in out:
                    out[key] = val
            for attr_k, attr_v in elem.attrib.items():
                attr_local = attr_k.rsplit("}", 1)[-1].lower()
                if attr_local in target_tags and str(attr_v).strip():
                    key = target_tags[attr_local]
                    val = _record_text(attr_v, flags, max_len=400)
                    if val and key not in out:
                        out[key] = val
    return out


def _parse_iptc(image: Any, flags: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        from PIL import IptcImagePlugin

        iptc = IptcImagePlugin.getiptcinfo(image)
        if not isinstance(iptc, dict):
            return out
        field_map = {
            (2, 80): "author",
            (2, 90): "city",
            (2, 101): "country",
            (2, 110): "credit",
            (2, 115): "source",
            (2, 116): "copyright",
            (2, 120): "caption",
        }
        for key, label in field_map.items():
            raw = iptc.get(key)
            if isinstance(raw, list):
                raw = ", ".join(
                    item.decode("utf-8", errors="replace") if isinstance(item, bytes) else str(item)
                    for item in raw
                )
            val = _record_text(raw, flags, max_len=400)
            if val:
                out[label] = val
    except Exception:  # noqa: BLE001
        pass
    return out


def _extract_exif_and_hashes(
    raw_bytes: bytes,
    flags: list[str],
) -> dict[str, Any]:
    """Extract EXIF, XMP, IPTC, dimensions, dHash, and pHash deterministically."""
    result: dict[str, Any] = {
        "format": "",
        "width": None,
        "height": None,
        "dhash": None,
        "phash": None,
        "exif": {},
        "xmp": {},
        "iptc": {},
        "png_text": {},
        "gps": None,
        "warnings": [],
    }
    try:
        from PIL import ExifTags, Image
    except ImportError:
        fmt, w, h = _sniff_dimensions_no_pil(raw_bytes)
        result["format"] = fmt
        result["width"] = w
        result["height"] = h
        result["xmp"] = _parse_xmp(raw_bytes, {}, flags)
        result["warnings"].append("Pillow not installed; perceptual hashing and EXIF skipped")
        return result

    try:
        with Image.open(io.BytesIO(raw_bytes)) as img:
            result["format"] = str(img.format or "")
            result["width"] = int(img.width)
            result["height"] = int(img.height)
            result["dhash"] = compute_dhash(img)
            result["phash"] = compute_phash(img)
            info = dict(getattr(img, "info", {}) or {})

            # EXIF extraction
            exif_data: dict[str, Any] = {}
            gps_info: dict[str, Any] = {}
            exif = img.getexif()
            if exif:
                for tag_id, val in exif.items():
                    tag_name = str(ExifTags.TAGS.get(tag_id, tag_id))
                    if tag_name == "GPSInfo":
                        continue
                    cleaned = _record_text(val, flags, max_len=400)
                    if cleaned:
                        exif_data[tag_name] = cleaned

                # Sub-IFDs (ExifIFD 0x8769 and GPSInfo 0x8825)
                if hasattr(exif, "get_ifd"):
                    try:
                        exif_ifd = exif.get_ifd(0x8769)
                        for tag_id, val in (exif_ifd or {}).items():
                            tag_name = str(ExifTags.TAGS.get(tag_id, tag_id))
                            if tag_name in {
                                "DateTimeOriginal", "DateTimeDigitized",
                                "UserComment", "LensMake", "LensModel",
                                "BodySerialNumber", "CameraOwnerName",
                            }:
                                cleaned = _record_text(val, flags, max_len=400)
                                if cleaned:
                                    exif_data[tag_name] = cleaned
                    except Exception:  # noqa: BLE001
                        pass

                    try:
                        raw_gps = exif.get_ifd(0x8825)
                        if isinstance(raw_gps, dict) and raw_gps:
                            named_gps = {
                                str(ExifTags.GPSTAGS.get(k, k)): v
                                for k, v in raw_gps.items()
                            }
                            lat = _dms_to_decimal(
                                named_gps.get("GPSLatitude"),
                                named_gps.get("GPSLatitudeRef"),
                            )
                            lon = _dms_to_decimal(
                                named_gps.get("GPSLongitude"),
                                named_gps.get("GPSLongitudeRef"),
                            )
                            if lat is not None and lon is not None:
                                gps_info = {
                                    "lat": lat,
                                    "lon": lon,
                                    "coords": f"{lat:.5f}, {lon:.5f}",
                                }
                    except Exception:  # noqa: BLE001
                        pass

            # Normalize convenient summary keys on exif_data
            normalized_exif: dict[str, Any] = {}
            key_aliases = {
                "Make": "make",
                "Model": "model",
                "Software": "software",
                "Artist": "author",
                "CameraOwnerName": "author",
                "Copyright": "copyright",
                "DateTime": "datetime",
                "DateTimeOriginal": "datetime_original",
                "ImageDescription": "description",
                "UserComment": "user_comment",
            }
            for src_key, val in exif_data.items():
                dst = key_aliases.get(src_key, src_key)
                if dst not in normalized_exif:
                    normalized_exif[dst] = val

            result["exif"] = normalized_exif
            result["gps"] = gps_info or None
            result["xmp"] = _parse_xmp(raw_bytes, info, flags)
            result["iptc"] = _parse_iptc(img, flags)

            png_text: dict[str, str] = {}
            for k, v in info.items():
                if k in {"icc_profile", "photoshop", "exif", "xmp", "XML:com.adobe.xmp"}:
                    continue
                if isinstance(v, (str, bytes)):
                    cleaned = _record_text(v, flags, max_len=400)
                    if cleaned:
                        png_text[sanitize_visual_text(k, max_len=80)] = cleaned
            result["png_text"] = png_text
    except Exception as exc:  # noqa: BLE001
        result["warnings"].append(f"image decode warning: {type(exc).__name__}: {exc}")
    return result


def _run_local_ocr_sync(raw_bytes: bytes, timeout_sec: int) -> tuple[bool, str, str]:
    """Run local shell-free tesseract OCR if available; never raises."""
    tesseract = shutil.which("tesseract")
    if not tesseract:
        return False, "", ""
    tmp_path = ""
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="osint_ocr_", suffix=".img")
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw_bytes)
        proc = subprocess.run(
            [tesseract, tmp_path, "stdout"],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=max(2, min(15, int(timeout_sec))),
        )
        text = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
        err = "" if proc.returncode == 0 else (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        return True, text, err
    except subprocess.TimeoutExpired:
        return True, "", "tesseract OCR timed out"
    except Exception as exc:  # noqa: BLE001
        return True, "", f"tesseract OCR error: {type(exc).__name__}"
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _downscale_for_vlm(raw_bytes: bytes) -> tuple[str, str]:
    """Downscale image to <= 1024px max dimension and return ``(b64, mime)``."""
    try:
        from PIL import Image

        with Image.open(io.BytesIO(raw_bytes)) as img:
            work = img.convert("RGB")
            if max(work.width, work.height) > _MAX_VLM_DIM:
                resample = getattr(Image, "Resampling", Image).LANCZOS
                work.thumbnail((_MAX_VLM_DIM, _MAX_VLM_DIM), resample)
            buf = io.BytesIO()
            work.save(buf, format="JPEG", quality=85)
            return base64.b64encode(buf.getvalue()).decode("ascii"), "image/jpeg"
    except Exception:  # noqa: BLE001
        return base64.b64encode(raw_bytes).decode("ascii"), "image/jpeg"


async def _run_quarantined_vlm(
    raw_bytes: bytes,
    *,
    metadata_context: dict[str, Any],
    ocr_text: str,
    flags: list[str],
    transport: Any = None,
) -> tuple[str, dict[str, Any] | None, str]:
    """Run optional quarantined VLM extraction and sanitize all returned fields."""
    from hub.ai.config import load_ai_config
    from hub.ai.models import VisionExtractionResult
    from hub.ai.providers import chat_completion, parse_json_object

    config = load_ai_config()
    if not config.enabled or config.provider.value == "disabled":
        return "disabled", None, "AI provider is disabled"

    b64, mime = _downscale_for_vlm(raw_bytes)
    context_blob = json.dumps(
        {"metadata": metadata_context, "ocr_text": ocr_text[:1000]},
        ensure_ascii=False,
    )
    quarantined_ctx = wrap_visual_untrusted(context_blob, max_len=2500)
    user_prompt = (
        "Inspect the attached image and the quarantined metadata/OCR block below. "
        "Extract ONLY factual forensic observations into a single JSON object with keys: "
        "summary (string), visible_text (list[str]), persons (list[str]), "
        "organizations (list[str]), usernames (list[str]), emails (list[str]), "
        "domains (list[str]), locations (list[str]), injection_detected (list[str]), "
        "confidence (number <= 0.45).\n"
        f"{quarantined_ctx}"
    )

    resp = await chat_completion(
        config,
        system_prompt=VISUAL_SECURITY_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        images_b64=[b64],
        image_mime=mime,
        json_mode=True,
        max_tokens=min(config.max_tokens, 1024),
        transport=transport,
    )
    if not resp.ok:
        return resp.status or "unavailable", None, resp.error or "VLM unavailable"

    try:
        raw_obj = parse_json_object(resp.text)
        parsed = VisionExtractionResult.model_validate(
            {
                **raw_obj,
                "provider": resp.provider,
                "model": resp.model,
                "epistemic_provenance": "AI_INFERRED",
                "confidence": min(0.45, max(0.0, float(raw_obj.get("confidence", 0.35)))),
            }
        )
    except Exception as exc:  # noqa: BLE001
        return "error", None, f"Invalid VLM JSON response: {exc}"

    sanitized_payload = {
        "summary": _record_text(parsed.summary, flags, max_len=1000),
        "visible_text": [_record_text(x, flags, max_len=300) for x in parsed.visible_text[:20] if _record_text(x, flags, max_len=300)],
        "persons": [_record_text(x, flags, max_len=150) for x in parsed.persons[:15] if _record_text(x, flags, max_len=150)],
        "organizations": [_record_text(x, flags, max_len=150) for x in parsed.organizations[:15] if _record_text(x, flags, max_len=150)],
        "usernames": [_record_text(x, flags, max_len=100) for x in parsed.usernames[:15] if _record_text(x, flags, max_len=100)],
        "emails": [_record_text(x, flags, max_len=150) for x in parsed.emails[:15] if _record_text(x, flags, max_len=150)],
        "domains": [_record_text(x, flags, max_len=150) for x in parsed.domains[:15] if _record_text(x, flags, max_len=150)],
        "locations": [_record_text(x, flags, max_len=150) for x in parsed.locations[:15] if _record_text(x, flags, max_len=150)],
        "injection_detected": [
            sanitize_visual_text(x, max_len=100)
            for x in parsed.injection_detected[:15]
            if sanitize_visual_text(x, max_len=100)
        ],
        "provider": parsed.provider,
        "model": parsed.model,
        "epistemic_provenance": "AI_INFERRED",
        "confidence": round(min(0.45, parsed.confidence), 3),
    }
    for hit in sanitized_payload["injection_detected"]:
        if hit not in flags:
            flags.append(hit)
    return "ok", sanitized_payload, ""


async def extract_media_forensics(
    raw_bytes: bytes,
    *,
    url: str = "",
    content_type: str = "",
    timeout_sec: int = 20,
    use_vlm: bool = False,
    vlm_transport: Any = None,
) -> dict[str, Any]:
    """Run deterministic media forensics (+ optional quarantined VLM) on raw bytes."""
    flags: list[str] = []
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    meta = _extract_exif_and_hashes(raw_bytes, flags)

    ocr_available, ocr_raw, ocr_err = await asyncio.to_thread(
        _run_local_ocr_sync, raw_bytes, timeout_sec
    )
    ocr_clean = _record_text(ocr_raw, flags, max_len=2000) if ocr_raw else ""

    vlm_status = "skipped"
    vlm_result: dict[str, Any] | None = None
    vlm_error = ""
    if use_vlm:
        vlm_status, vlm_result, vlm_error = await _run_quarantined_vlm(
            raw_bytes,
            metadata_context={
                "exif": meta.get("exif") or {},
                "xmp": meta.get("xmp") or {},
                "iptc": meta.get("iptc") or {},
            },
            ocr_text=ocr_clean,
            flags=flags,
            transport=vlm_transport,
        )

    return {
        "url": url,
        "sha256": sha256,
        "byte_length": len(raw_bytes),
        "content_type": sanitize_visual_text(content_type or meta.get("format") or "", max_len=120),
        "format": meta.get("format") or "",
        "dimensions": {
            "width": meta.get("width"),
            "height": meta.get("height"),
        },
        "dhash": meta.get("dhash"),
        "phash": meta.get("phash"),
        "exif": meta.get("exif") or {},
        "xmp": meta.get("xmp") or {},
        "iptc": meta.get("iptc") or {},
        "png_text": meta.get("png_text") or {},
        "gps": meta.get("gps"),
        "ocr": {
            "available": ocr_available,
            "text": ocr_clean,
            "error": sanitize_visual_text(ocr_err, max_len=200),
        },
        "visual_injection_flags": flags,
        "injection_detected": bool(flags),
        "vlm_status": vlm_status,
        "vlm_extraction": vlm_result,
        "vlm_error": sanitize_visual_text(vlm_error, max_len=300),
        "warnings": list(meta.get("warnings") or []),
    }


async def collect(
    params: dict,
    *,
    timeout_sec: int,
    scope: ScopeConfig,
) -> BuiltinOutput:
    """Fetch a public media URL (SSRF-guarded) and emit forensic metadata JSON."""
    url = str((params or {}).get("url") or (params or {}).get("target") or "").strip()
    if not url:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: url",
            error_message="media_forensics requires a non-empty 'url'",
        )
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return BuiltinOutput(
            exit_code=2,
            stderr=f"invalid URL: {exc}",
            error_message=f"media_forensics received an invalid URL: {url!r}",
        )
    if parts.scheme.lower() not in _ALLOWED_SCHEMES or not parts.netloc:
        return BuiltinOutput(
            exit_code=-1,
            stderr=f"blocked non-http(s) URL: {url!r}",
            error_code=ErrorCode.SCOPE_BLOCKED,
            error_message=f"media_forensics only allows http(s) URLs: {url!r}",
        )

    host = _http.extract_host(url)
    if scope is not None:
        if any(host == d.lower() or host.endswith("." + d.lower()) for d in scope.deny_domains):
            return BuiltinOutput(
                exit_code=-1,
                stderr=f"denied domain: {host}",
                error_code=ErrorCode.SCOPE_BLOCKED,
                error_message=f"media_forensics blocked denied host {host!r}",
            )
        if scope.allow_domains and not host_in_scope(host, scope) and scope.allow_active_recon:
            # Passive URL analysis still respects explicit deny_domains; allow_domains
            # does not block passive URLs unless deny-listed (matching policy.py).
            pass

    use_vlm_param = (params or {}).get("use_vlm")
    if use_vlm_param is None:
        from hub.ai.config import load_ai_config

        cfg = load_ai_config()
        use_vlm = bool(cfg.enabled and cfg.vision_enabled)
    else:
        use_vlm = bool(use_vlm_param)

    async def _run() -> BuiltinOutput:
        client = _http.make_client(
            timeout_sec=timeout_sec,
            follow_redirects=False,
            headers={"Accept": "image/*,*/*;q=0.8"},
        )
        async with client:
            fetched = await _http.fetch_safe(client, url, max_bytes=MAX_MEDIA_BYTES)
        if not fetched.ok:
            return _http.failure_output("media_forensics fetch", fetched)
        if fetched.status_code in {403, 429}:
            msg = f"media_forensics rate-limited or forbidden (HTTP {fetched.status_code})"
            return BuiltinOutput(
                exit_code=1,
                stderr=msg,
                error_code=ErrorCode.RATE_LIMITED if fetched.status_code == 429 else ErrorCode.SPAWN_ERROR,
                error_message=msg,
            )
        if fetched.status_code >= 400:
            msg = f"media_forensics received HTTP {fetched.status_code}"
            return BuiltinOutput(
                exit_code=1,
                stderr=msg,
                error_code=ErrorCode.SPAWN_ERROR,
                error_message=msg,
            )

        payload = await extract_media_forensics(
            fetched.body,
            url=fetched.url or url,
            content_type=fetched.headers.get("content-type", ""),
            timeout_sec=timeout_sec,
            use_vlm=use_vlm,
        )
        if fetched.truncated:
            payload["warnings"].append(f"download truncated at {MAX_MEDIA_BYTES} bytes")
        if fetched.hops:
            payload["redirect_hops"] = fetched.hops
        return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)

    try:
        return await asyncio.wait_for(_run(), timeout=max(2, int(timeout_sec)))
    except (asyncio.TimeoutError, TimeoutError):
        msg = f"media_forensics timed out after {timeout_sec}s"
        return BuiltinOutput(
            exit_code=-1,
            stderr=msg,
            error_code=ErrorCode.TIMEOUT,
            error_message=msg,
        )
