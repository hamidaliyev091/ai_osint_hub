"""Provider credential vault, auth status and TheHarvester config sync.

Resolution order: environment variables override the local JSON vault at
``$AI_OSINT_HUB_HOME/credentials.json`` (default ``~/.ai_osint_hub``, deliberately
outside the repository). Raw secrets are registered with
:mod:`hub.security.redaction` on load and must never be written into SQLite,
evidence artifacts, CLI output or git-tracked files.

Providers:

* ``github``     — ``GITHUB_TOKEN`` (keyless runs remain allowed, 60 req/h)
* ``virustotal`` — ``VIRUSTOTAL_API_KEY``  (``x-apikey`` header)
* ``shodan``     — ``SHODAN_API_KEY``      (``key`` query param)
* ``censys``     — ``CENSYS_API_ID`` + ``CENSYS_API_SECRET`` (HTTP Basic) or
                   ``CENSYS_TOKEN`` (Bearer PAT)
* ``hunter``     — ``HUNTER_API_KEY``      (``api_key`` query param)
"""

from __future__ import annotations

import json
import os
import stat
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from hub.security.redaction import (
    clear_secrets,
    masked_preview,
    redact,
    register_secret,
)

# ── status constants ────────────────────────────────────────────────────
CONFIGURED = "CONFIGURED"
MISSING_KEY = "MISSING_KEY"
PARTIAL = "PARTIAL"
KEYLESS_LIMITED = "KEYLESS_LIMITED"
OPTIONAL_UNCONFIGURED = "OPTIONAL_UNCONFIGURED"
NOT_REQUIRED = "NOT_REQUIRED"

AUTH_READY_STATUSES = frozenset({CONFIGURED, KEYLESS_LIMITED, NOT_REQUIRED})
AUTH_BLOCKING_STATUSES = frozenset({MISSING_KEY, PARTIAL, OPTIONAL_UNCONFIGURED})

VAULT_VERSION = 1


@dataclass(frozen=True)
class CredentialField:
    env: tuple[str, ...]
    name: str
    label: str


@dataclass(frozen=True)
class ProviderSpec:
    provider: str
    label: str
    fields: tuple[CredentialField, ...]
    required: bool = True
    #: ``any`` (default): configured when all fields are present; ``any_required``
    #: is used by Censys (id+secret OR token).
    mode: str = "all"
    docs_url: str = ""
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


PROVIDERS: dict[str, ProviderSpec] = {
    "github": ProviderSpec(
        provider="github",
        label="GitHub",
        fields=(CredentialField(("GITHUB_TOKEN", "GH_TOKEN"), "token", "GitHub Token"),),
        required=False,
        docs_url="https://github.com/settings/tokens",
        notes="Keyless works at 60 req/h; token raises the REST limit to 5,000 req/h.",
    ),
    "virustotal": ProviderSpec(
        provider="virustotal",
        label="VirusTotal",
        fields=(CredentialField(("VIRUSTOTAL_API_KEY", "VT_API_KEY"),
                                "api_key", "VirusTotal API Key"),),
        docs_url="https://www.virustotal.com/gui/my-apikey",
    ),
    "shodan": ProviderSpec(
        provider="shodan",
        label="Shodan",
        fields=(CredentialField(("SHODAN_API_KEY", "SHODAN_KEY"),
                                "api_key", "Shodan API Key"),),
        docs_url="https://account.shodan.io/",
    ),
    "censys": ProviderSpec(
        provider="censys",
        label="Censys",
        fields=(
            CredentialField(("CENSYS_API_ID",), "api_id", "Censys API ID"),
            CredentialField(("CENSYS_API_SECRET",), "api_secret", "Censys API Secret"),
            CredentialField(("CENSYS_TOKEN", "CENSYS_API_TOKEN"), "token", "Censys PAT"),
        ),
        mode="any_required",
        docs_url="https://search.censys.io/account/api",
        notes="HTTP Basic with API ID + Secret, or a Bearer personal access token.",
    ),
    "hunter": ProviderSpec(
        provider="hunter",
        label="Hunter.io",
        fields=(CredentialField(("HUNTER_API_KEY", "HUNTERIO_API_KEY"),
                                "api_key", "Hunter.io API Key"),),
        docs_url="https://hunter.io/api-keys",
    ),
}

#: Tool id → credential provider (used by health checks and the pivot planner).
TOOL_PROVIDER: dict[str, str] = {
    "github_osint": "github",
    "virustotal_lookup": "virustotal",
    "shodan_lookup": "shodan",
    "censys_lookup": "censys",
    "hunter_lookup": "hunter",
}

_CACHE: dict[str, dict[str, str]] | None = None
_LOAD_LOCK = threading.RLock()


# ── paths / vault ──────────────────────────────────────────────────────
def vault_path() -> Path:
    """Credential vault path (respects ``AI_OSINT_HUB_HOME`` for tests)."""
    home = os.environ.get("AI_OSINT_HUB_HOME")
    base = Path(home).expanduser() if home else Path.home() / ".ai_osint_hub"
    return (base / "credentials.json").resolve()


def _read_vault() -> dict[str, dict[str, str]]:
    path = vault_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    providers = raw.get("providers") if isinstance(raw, dict) else None
    result: dict[str, dict[str, str]] = {}
    if isinstance(providers, dict):
        for provider, values in providers.items():
            if isinstance(values, dict):
                result[str(provider)] = {
                    str(key): str(value)
                    for key, value in values.items()
                    if value is not None and str(value).strip()
                }
    return result


def _env_values(spec: ProviderSpec) -> dict[str, str]:
    values: dict[str, str] = {}
    for field_spec in spec.fields:
        for env_name in field_spec.env:
            raw = os.environ.get(env_name)
            if raw and raw.strip():
                values[field_spec.name] = raw.strip()
                break
    return values


def _merge_values(vault: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for provider, spec in PROVIDERS.items():
        values = dict(vault.get(provider, {}))
        values.update(_env_values(spec))     # env wins over vault
        merged[provider] = {key: value for key, value in values.items()
                            if key in {f.name for f in spec.fields} and value}
    return merged


def _register_redaction(values: dict[str, dict[str, str]]) -> None:
    clear_secrets()
    for provider, provider_values in values.items():
        for secret in provider_values.values():
            register_secret(secret, provider)


def load_credentials(*, force: bool = False, sync_config: bool = False
                     ) -> dict[str, dict[str, str]]:
    """Load env + vault credentials, cache them and register redaction secrets."""
    global _CACHE
    with _LOAD_LOCK:
        if _CACHE is not None and not force:
            values = _CACHE
        else:
            values = _merge_values(_read_vault())
            _CACHE = values
        _register_redaction(values)
    if sync_config:
        try:
            sync_theharvester_config()
        except OSError:
            pass
    return values


def reload_credentials(*, sync_config: bool = False) -> dict[str, dict[str, str]]:
    return load_credentials(force=True, sync_config=sync_config)


def _values(provider: str) -> dict[str, str]:
    values = load_credentials()
    return dict(values.get(provider, {}))


# ── status ─────────────────────────────────────────────────────────────
def _provider_status(spec: ProviderSpec, values: dict[str, str]) -> dict[str, Any]:
    fields = {
        field_spec.name: {
            "label": field_spec.label,
            "configured": bool(values.get(field_spec.name)),
            "masked": masked_preview(values.get(field_spec.name)),
        }
        for field_spec in spec.fields
    }
    missing = [name for name, item in fields.items() if not item["configured"]]
    if spec.provider == "github":
        configured = bool(values.get("token"))
        auth_status = CONFIGURED if configured else KEYLESS_LIMITED
    elif spec.mode == "any_required":
        token_ok = bool(values.get("token"))
        basic_ok = bool(values.get("api_id") and values.get("api_secret"))
        configured = token_ok or basic_ok
        if configured:
            auth_status = CONFIGURED
        elif values:
            auth_status = PARTIAL
        else:
            auth_status = MISSING_KEY
        if token_ok:
            missing = []
        elif basic_ok:
            missing = []
        else:
            missing = [name for name in missing]
    else:
        configured = all(fields[f.name]["configured"] for f in spec.fields)
        auth_status = CONFIGURED if configured else MISSING_KEY
    return {
        "provider": spec.provider,
        "label": spec.label,
        "configured": configured,
        "auth_status": auth_status,
        "ready": auth_status in AUTH_READY_STATUSES,
        "fields": fields,
        "missing_fields": missing,
        "vault_path": str(vault_path()),
        "docs_url": spec.docs_url,
        "notes": spec.notes,
    }


def provider_status(provider: str) -> dict[str, Any]:
    spec = PROVIDERS[provider]
    return _provider_status(spec, _values(provider))


def all_provider_status() -> dict[str, dict[str, Any]]:
    load_credentials()
    return {provider: _provider_status(spec, _values(provider))
            for provider, spec in PROVIDERS.items()}


def auth_status_for_tool(tool_id: str) -> str:
    provider = TOOL_PROVIDER.get(tool_id)
    if not provider:
        return NOT_REQUIRED
    return str(provider_status(provider)["auth_status"])


def auth_ready_for_tool(tool_id: str) -> bool:
    status = auth_status_for_tool(tool_id)
    return status not in AUTH_BLOCKING_STATUSES


def auth_summary() -> dict[str, int]:
    statuses = all_provider_status()
    return {
        "configured": sum(1 for item in statuses.values() if item["configured"]),
        "missing": sum(1 for item in statuses.values()
                       if not item["configured"]
                       and item["auth_status"] != KEYLESS_LIMITED),
        "total": len(statuses),
    }


# ── secret access ──────────────────────────────────────────────────────
def get_secret(provider: str, field_name: str = "") -> str:
    """Return a raw secret (env or vault), or "" when unconfigured."""
    spec = PROVIDERS.get(provider)
    if spec is None:
        return ""
    values = _values(provider)
    if field_name:
        return values.get(field_name, "")
    # Default: first non-empty field in manifest order.
    for field_spec in spec.fields:
        value = values.get(field_spec.name)
        if value:
            return value
    return ""


def get_provider_values(provider: str) -> dict[str, str]:
    return _values(provider)


def masked_secret(provider: str, field_name: str = "") -> str:
    return masked_preview(get_secret(provider, field_name))


# ── updates ────────────────────────────────────────────────────────────
def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600 where supported
    except OSError:
        pass
    os.replace(tmp, path)


def save_provider(provider: str, values: dict[str, str], *,
                  sync_config: bool = True) -> dict[str, Any]:
    """Merge non-empty values into the vault, register redaction, sync config."""
    spec = PROVIDERS.get(provider)
    if spec is None:
        raise ValueError(f"unknown credential provider: {provider!r}")
    allowed = {field_spec.name for field_spec in spec.fields}
    cleaned = {key: str(value).strip()
               for key, value in values.items()
               if key in allowed and value is not None and str(value).strip()}
    if not cleaned:
        raise ValueError("no credential values supplied")
    vault = _read_vault()
    current = dict(vault.get(provider, {}))
    current.update(cleaned)
    vault[provider] = current
    payload = {
        "version": VAULT_VERSION,
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "providers": vault,
    }
    _atomic_write_json(vault_path(), payload)
    reload_credentials(sync_config=False)
    if sync_config:
        try:
            sync_theharvester_config()
        except OSError:
            pass
    _clear_health_cache()
    return provider_status(provider)


def configure_from_mapping(data: dict[str, Any], *,
                           sync_config: bool = True) -> dict[str, dict[str, Any]]:
    """Save credentials from the web/API/CLI field names and return statuses.

    Accepted field names (case-insensitive):
    ``github_token``, ``vitustotal_api_key``/``virustotal_api_key``,
    ``shodan_api_key``, ``censys_api_id``, ``censys_api_secret``,
    ``censys_token``, ``hunter_api_key``.
    """
    aliases = {
        "github": {"token": ("github_token", "github", "token")},
        "virustotal": {"api_key": ("virustotal_api_key", "virustotal",
                                   "virustotal_key", "api_key")},
        "shodan": {"api_key": ("shodan_api_key", "shodan", "shodan_key")},
        "censys": {
            "api_id": ("censys_api_id", "censys_id"),
            "api_secret": ("censys_api_secret", "censys_secret"),
            "token": ("censys_token", "censys_pat"),
        },
        "hunter": {"api_key": ("hunter_api_key", "hunter", "hunterio_api_key")},
    }
    lowered = {str(key).strip().lower(): value for key, value in (data or {}).items()}
    saved: dict[str, dict[str, Any]] = {}
    for provider, field_map in aliases.items():
        values: dict[str, str] = {}
        for field_name, names in field_map.items():
            for name in names:
                value = lowered.get(name)
                if value is not None and str(value).strip():
                    values[field_name] = str(value).strip()
                    break
        if values:
            saved[provider] = save_provider(provider, values,
                                            sync_config=False)
    if saved and sync_config:
        try:
            sync_theharvester_config()
        except OSError:
            pass
    return saved


def _clear_health_cache() -> None:
    try:
        from hub.tools import capabilities

        capabilities.clear_health_cache()
    except Exception:  # noqa: BLE001
        pass
    try:
        from hub.tools import cooldown

        cooldown.reset_cache()
    except Exception:  # noqa: BLE001
        pass


# ── TheHarvester config sync ───────────────────────────────────────────
def theharvester_config_path() -> Path:
    from hub.tools.capabilities import tool_home

    return tool_home("theharvester") / ".theHarvester" / "api-keys.yaml"


def sync_theharvester_config() -> Path:
    """Materialize api-keys.yaml for theHarvester inside its writable HOME."""
    import yaml

    path = theharvester_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, yaml.YAMLError):
            existing = {}
    apikeys = existing.setdefault("apikeys", {})
    if not isinstance(apikeys, dict):
        apikeys = {}
        existing["apikeys"] = apikeys
    mapping = {
        "github": {"key": ("github", "token")},
        "virustotal": {"key": ("virustotal", "api_key")},
        "shodan": {"key": ("shodan", "api_key")},
        "censys": {"id": ("censys", "api_id"), "secret": ("censys", "api_secret")},
        "hunter": {"key": ("hunter", "api_key")},
    }
    for harvester_name, field_map in mapping.items():
        section = apikeys.setdefault(harvester_name, {})
        if not isinstance(section, dict):
            section = {}
            apikeys[harvester_name] = section
        for yaml_field, (provider, field_name) in field_map.items():
            value = get_secret(provider, field_name)
            if value:
                section[yaml_field] = value
    tmp = path.with_suffix(".yaml.tmp")
    tmp.write_text(yaml.safe_dump(existing, sort_keys=False, allow_unicode=True),
                   encoding="utf-8")
    os.replace(tmp, path)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


def ensure_credentials() -> dict[str, dict[str, str]]:
    """Runtime hook: load credentials and make sure redaction is registered."""
    return load_credentials()


__all__ = [
    "CONFIGURED",
    "MISSING_KEY",
    "PARTIAL",
    "KEYLESS_LIMITED",
    "OPTIONAL_UNCONFIGURED",
    "NOT_REQUIRED",
    "AUTH_READY_STATUSES",
    "AUTH_BLOCKING_STATUSES",
    "PROVIDERS",
    "TOOL_PROVIDER",
    "vault_path",
    "load_credentials",
    "reload_credentials",
    "provider_status",
    "all_provider_status",
    "auth_status_for_tool",
    "auth_ready_for_tool",
    "auth_summary",
    "get_secret",
    "get_provider_values",
    "masked_secret",
    "save_provider",
    "configure_from_mapping",
    "sync_theharvester_config",
    "theharvester_config_path",
    "ensure_credentials",
]
