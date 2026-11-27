"""AI configuration management for ``hub.ai``.

Stores user-configured settings outside the repository at
``$AI_OSINT_HUB_HOME/ai_config.json`` (default ``~/.ai_osint_hub/ai_config.json``)
with 0600 permissions and atomic file replacement. Environment variables
override persisted values.

Security invariants:
* NEVER reads ``~/.dsh/.credentials.yaml``, ``~/.claude/.credentials.json``,
  or ``~/.codex/auth.json``.
* Registers all loaded API keys with :func:`hub.security.redaction.register_secret`.
* Never returns raw API keys from status or update helpers.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hub.ai.models import AIConfig, AIProviderKind, AIStatusReport
from hub.security.redaction import masked_preview, register_secret, unregister_secret

_LOCK = threading.RLock()
_REGISTERED_AI_SECRETS: dict[str, str] = {}

_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off"}

_ENV_SECRET_MAP = (
    ("GEMINI_API_KEY", "gemini_api_key", "ai_gemini"),
    ("DEEPSEEK_API_KEY", "deepseek_api_key", "ai_deepseek"),
    ("OPENAI_API_KEY", "openai_api_key", "ai_openai"),
)


def ai_config_path() -> Path:
    """Return ``$AI_OSINT_HUB_HOME/ai_config.json`` (outside repository)."""
    home = os.environ.get("AI_OSINT_HUB_HOME")
    base = Path(home).expanduser() if home else Path.home() / ".ai_osint_hub"
    return (base / "ai_config.json").resolve()


def _parse_bool(raw: Any) -> bool | None:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return None
    text = str(raw).strip().lower()
    if text in _BOOL_TRUE:
        return True
    if text in _BOOL_FALSE:
        return False
    return None


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    os.replace(tmp, path)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _read_config_file() -> dict[str, Any]:
    path = ai_config_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Support both flat config JSON and {"version": 1, "config": {...}}
    if isinstance(data.get("config"), dict):
        return dict(data["config"])
    return dict(data)


def _register_ai_secrets(config: AIConfig) -> None:
    """Register loaded AI secrets with redaction without clearing vault secrets."""
    with _LOCK:
        for field_name, label in (
            ("gemini_api_key", "ai_gemini"),
            ("deepseek_api_key", "ai_deepseek"),
            ("openai_api_key", "ai_openai"),
        ):
            new_val = (getattr(config, field_name, "") or "").strip()
            old_val = _REGISTERED_AI_SECRETS.get(field_name, "")
            if old_val and old_val != new_val:
                unregister_secret(old_val)
                _REGISTERED_AI_SECRETS.pop(field_name, None)
            if new_val:
                register_secret(new_val, label)
                _REGISTERED_AI_SECRETS[field_name] = new_val


def load_ai_config(*, register_secrets: bool = True) -> AIConfig:
    """Load AI configuration from ``ai_config.json`` with env overrides."""
    raw = _read_config_file()

    env_enabled = _parse_bool(os.environ.get("AI_OSINT_AI_ENABLED"))
    if env_enabled is not None:
        raw["enabled"] = env_enabled

    env_provider = (os.environ.get("AI_OSINT_AI_PROVIDER") or "").strip().lower()
    if env_provider:
        try:
            raw["provider"] = AIProviderKind(env_provider).value
        except ValueError:
            pass

    for env_key, field_name in (
        ("OLLAMA_HOST", "ollama_host"),
        ("LMSTUDIO_BASE_URL", "lmstudio_base_url"),
        ("OPENAI_BASE_URL", "openai_base_url"),
    ):
        val = (os.environ.get(env_key) or "").strip()
        if val:
            raw[field_name] = val

    for env_key, field_name, _ in _ENV_SECRET_MAP:
        val = (os.environ.get(env_key) or "").strip()
        if val:
            raw[field_name] = val

    # Validate safely; fall back to defaults if file is malformed.
    try:
        config = AIConfig.model_validate(raw)
    except Exception:  # noqa: BLE001
        config = AIConfig()

    if register_secrets:
        _register_ai_secrets(config)
    return config


def save_ai_config(config: AIConfig) -> AIConfig:
    """Persist ``AIConfig`` atomically with 0600 permissions."""
    payload = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "config": config.model_dump(mode="json"),
    }
    _atomic_write_json(ai_config_path(), payload)
    _register_ai_secrets(config)
    return config


def build_status_report(
    config: AIConfig,
    *,
    local_probes: dict[str, Any] | None = None,
) -> AIStatusReport:
    """Build a secret-redacted :class:`AIStatusReport` from ``config``."""
    active = bool(config.enabled and config.provider != AIProviderKind.DISABLED)
    return AIStatusReport(
        enabled=config.enabled,
        provider=config.provider,
        active=active,
        config_path=str(ai_config_path()),
        vision_enabled=config.vision_enabled,
        reflection_enabled=config.reflection_enabled,
        models={
            "ollama": config.ollama_model,
            "ollama_vision": config.ollama_vision_model,
            "ollama_embedding": config.ollama_embedding_model,
            "lmstudio": config.lmstudio_model,
            "gemini": config.gemini_model,
            "deepseek": config.deepseek_model,
            "openai_compat": config.openai_model,
        },
        endpoints={
            "ollama": config.ollama_host,
            "lmstudio": config.lmstudio_base_url,
            "gemini": config.gemini_base_url,
            "deepseek": config.deepseek_base_url,
            "openai_compat": config.openai_base_url,
        },
        credentials={
            "gemini": {
                "configured": bool(config.gemini_api_key.strip()),
                "masked": masked_preview(config.gemini_api_key),
            },
            "deepseek": {
                "configured": bool(config.deepseek_api_key.strip()),
                "masked": masked_preview(config.deepseek_api_key),
            },
            "openai_compat": {
                "configured": bool(config.openai_api_key.strip()),
                "masked": masked_preview(config.openai_api_key),
            },
        },
        local_probes=dict(local_probes or {}),
        hardware_profile={
            "target_vram_gb": 8,
            "target_ram_gb": 32,
            "ollama_num_ctx": config.ollama_num_ctx,
            "ollama_keep_alive": config.ollama_keep_alive,
        },
    )


def update_ai_config(data: dict[str, Any]) -> dict[str, Any]:
    """Update persisted AI settings and return the sanitized status dict."""
    if not isinstance(data, dict):
        raise ValueError("AI config update payload must be a JSON object")

    persisted = _read_config_file()
    updates = dict(data)

    if "enabled" in updates:
        parsed = _parse_bool(updates["enabled"])
        if parsed is not None:
            updates["enabled"] = parsed
    if "vision_enabled" in updates:
        parsed = _parse_bool(updates["vision_enabled"])
        if parsed is not None:
            updates["vision_enabled"] = parsed
    if "reflection_enabled" in updates:
        parsed = _parse_bool(updates["reflection_enabled"])
        if parsed is not None:
            updates["reflection_enabled"] = parsed

    if "provider" in updates and updates["provider"] is not None:
        updates["provider"] = AIProviderKind(str(updates["provider"]).strip().lower()).value

    allowed_fields = set(AIConfig.model_fields)
    for key, value in updates.items():
        if key not in allowed_fields:
            continue
        if key.endswith("_api_key"):
            text = str(value or "").strip()
            # Ignore empty/masked sentinel updates unless explicitly cleared with ""
            if value == "":
                persisted[key] = ""
            elif text and "…" not in text:
                persisted[key] = text
        elif value is not None:
            persisted[key] = value

    # If enabling with no provider yet, default to local Ollama offline profile.
    if persisted.get("enabled") and persisted.get("provider", "disabled") == "disabled":
        if "provider" not in updates:
            persisted["provider"] = AIProviderKind.OLLAMA.value

    new_config = AIConfig.model_validate(persisted)
    save_ai_config(new_config)
    effective = load_ai_config()
    return build_status_report(effective).model_dump(mode="json")


__all__ = [
    "ai_config_path",
    "load_ai_config",
    "save_ai_config",
    "build_status_report",
    "update_ai_config",
]
