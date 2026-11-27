"""Hybrid offline + online AI layer for AI OSINT Hub.

All AI capabilities are strictly opt-in (``enabled=False`` by default) so the
deterministic OSINT core runs with zero LLM dependencies.
"""

from __future__ import annotations

from typing import Any

from hub.ai.config import (
    ai_config_path,
    build_status_report,
    load_ai_config,
    save_ai_config,
    update_ai_config,
)
from hub.ai.embeddings import (
    correlate_texts,
    deterministic_text_similarity,
    embed_image_bytes,
    embed_texts,
    fastembed_availability,
)
from hub.ai.models import (
    AI_PRESETS_CATALOG,
    AIConfig,
    AIHardwarePreset,
    AIProviderKind,
    AIStatusReport,
    ReflectionProposal,
    VisionExtractionResult,
)
from hub.ai.providers import probe_local_endpoints_sync
from hub.ai.reflection_runner import run_case_reflection
from hub.models import ScopeConfig


def get_ai_status(*, probe_local: bool = False) -> dict[str, Any]:
    """Return secret-redacted AI configuration and optional local probe status."""
    config = load_ai_config()
    probes = probe_local_endpoints_sync(config) if probe_local else {}
    return build_status_report(config, local_probes=probes).model_dump(mode="json")


async def analyze_media_url(
    url: str,
    *,
    use_vlm: bool = False,
    scope: ScopeConfig | None = None,
    timeout_sec: int = 30,
) -> dict[str, Any]:
    """Run SSRF-guarded media forensics (+ optional VLM) on ``url``."""
    from hub.tools.builtin.media_forensics import collect
    from hub.tools.parsers.media_forensics import parse

    effective_scope = scope or ScopeConfig()
    output = await collect(
        {"url": url, "use_vlm": bool(use_vlm)},
        timeout_sec=timeout_sec,
        scope=effective_scope,
    )
    if output.exit_code != 0 or output.error_code is not None:
        return {
            "ok": False,
            "url": url,
            "error_code": output.error_code.value if output.error_code else "ERROR",
            "error": output.error_message or output.stderr or "Media forensics failed",
        }
    import json

    forensics = json.loads(output.stdout)
    parsed = parse(output.stdout, target=url)
    return {
        "ok": True,
        "url": forensics.get("url") or url,
        "forensics": forensics,
        "parsed": parsed.model_dump(mode="json"),
    }


__all__ = [
    "AIConfig",
    "AIHardwarePreset",
    "AI_PRESETS_CATALOG",
    "AIProviderKind",
    "AIStatusReport",
    "ReflectionProposal",
    "VisionExtractionResult",
    "ai_config_path",
    "load_ai_config",
    "save_ai_config",
    "get_ai_status",
    "update_ai_config",
    "run_case_reflection",
    "analyze_media_url",
    "embed_texts",
    "embed_image_bytes",
    "fastembed_availability",
    "correlate_texts",
    "deterministic_text_similarity",
]
