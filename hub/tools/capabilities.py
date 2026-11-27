"""Tool capability registry — the single source of truth for OSINT integrations.

Every integration declares a strict Pydantic :class:`ToolCapability` contract
(Spec 3). LLM tool-calling schemas, MCP tool definitions and CLI capability
tables are generated *from* this registry — never hand-maintained separately.

Capabilities are only ever executed through :mod:`hub.tools.runtime`, which
enforces scope policy, authorization gates and rate limits in deterministic
Python before any subprocess is spawned.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Any, Iterable, Optional

from hub.models import (
    EntityType,
    ExecutionMode,
    HealthStatus,
    InvocationSpec,
    ParameterSpec,
    ToolCapability,
    utc_now,
)
from pathlib import Path

from hub.tools import cooldown, locator
from hub.tools.base import load_parser

__all__ = [
    "ToolCapability",
    "register",
    "unregister",
    "get_tool",
    "require_tool",
    "list_tools",
    "all_capabilities",
    "for_entity",
    "validate_params",
    "build_argv",
    "build_params_for_entity",
    "health_check",
    "health_check_all",
    "available_tool_ids",
    "export_cli_table",
    "export_llm_tool_schemas",
    "export_mcp_tool_definitions",
    "export_cli_table_rows",
    "reset_registry",
    "tools_by_mode",
]

# ════════════════════════════════════════════════════════════════════════
# Registry store
# ════════════════════════════════════════════════════════════════════════

_REGISTRY: dict[str, ToolCapability] = {}
_HEALTH_CACHE: dict[str, HealthStatus] = {}

# Mapping of parameter format/name -> acceptable entity types for auto-pivot.
_FORMAT_TO_ENTITY: dict[str, set[EntityType]] = {
    "email": {EntityType.EMAIL},
    "hostname": {EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP},
    "domain": {EntityType.DOMAIN, EntityType.SUBDOMAIN},
    "ip": {EntityType.IP},
    "ipv4": {EntityType.IP},
    "url": {EntityType.URL},
    "phone": {EntityType.PHONE},
    "hash": {EntityType.HASH},
    "username": {EntityType.USERNAME},
    "service": {EntityType.SERVICE},
    "person": {EntityType.PERSON},
    "organization": {EntityType.ORGANIZATION},
    "asn": {EntityType.ASN},
    "repository": {EntityType.REPOSITORY},
    "crypto_address": {EntityType.CRYPTO_ADDRESS},
    "social_profile": {EntityType.SOCIAL_PROFILE},
}

_PARAM_NAME_TO_ENTITY: dict[str, EntityType] = {
    "email": EntityType.EMAIL,
    "domain": EntityType.DOMAIN,
    "hostname": EntityType.DOMAIN,
    "username": EntityType.USERNAME,
    "usernames": EntityType.USERNAME,
    "ip": EntityType.IP,
    "target": EntityType.DOMAIN,
    "phone": EntityType.PHONE,
    "hash": EntityType.HASH,
    "url": EntityType.URL,
    "service": EntityType.SERVICE,
    "person": EntityType.PERSON,
    "organization": EntityType.ORGANIZATION,
    "asn": EntityType.ASN,
    "repository": EntityType.REPOSITORY,
}


def register(capability: ToolCapability, *, replace: bool = False) -> ToolCapability:
    """Register a capability. Tests use this to inject deterministic mock tools."""
    key = capability.tool_id.strip().lower()
    if key in _REGISTRY and not replace:
        raise ValueError(f"tool already registered: {key}")
    _REGISTRY[key] = capability
    _HEALTH_CACHE.pop(key, None)
    return capability


def unregister(tool_id: str) -> None:
    _REGISTRY.pop(tool_id.strip().lower(), None)
    _HEALTH_CACHE.pop(tool_id.strip().lower(), None)


def reset_registry(*, reload_builtins: bool = False) -> None:
    """Clear the registry (tests). With reload_builtins=True re-installs defaults."""
    _REGISTRY.clear()
    _HEALTH_CACHE.clear()
    if reload_builtins:
        _install_default_registry()


def get_tool(name: str) -> Optional[ToolCapability]:
    if not name:
        return None
    key = str(name).strip().lower()
    cap = _REGISTRY.get(key)
    if cap is not None:
        return cap
    # tolerate legacy display name (theHarvester)
    for candidate in _REGISTRY.values():
        if candidate.display_name.lower() == key:
            return candidate
    return None


def require_tool(name: str) -> ToolCapability:
    cap = get_tool(name)
    if cap is None:
        raise KeyError(f"unknown tool: {name!r}")
    return cap


def list_tools(*, available_only: bool = False) -> list[str]:
    if not available_only:
        return sorted(_REGISTRY)
    available = available_tool_ids()
    return sorted(t for t in _REGISTRY if t in available)


def all_capabilities() -> list[ToolCapability]:
    return [cap for _, cap in sorted(_REGISTRY.items())]


def for_entity(entity_type: EntityType | str) -> list[ToolCapability]:
    """Return capabilities that accept the given entity type, best prior yield first."""
    try:
        etype = EntityType.coerce(entity_type)
    except ValueError:
        return []
    caps = [c for c in _REGISTRY.values() if etype in c.accepted_entity_types]
    caps.sort(key=lambda c: (-c.prior_yield, c.tool_id))
    return caps


# ════════════════════════════════════════════════════════════════════════
# Parameter building / validation
# ════════════════════════════════════════════════════════════════════════

def _expected_entity_types(param: ParameterSpec) -> set[EntityType]:
    fmt = (param.format or "").strip().lower()
    if fmt and fmt in _FORMAT_TO_ENTITY:
        return set(_FORMAT_TO_ENTITY[fmt])
    key = param.name.strip().lower()
    if key in _PARAM_NAME_TO_ENTITY:
        return {_PARAM_NAME_TO_ENTITY[key]}
    try:
        return {EntityType.coerce(key)}
    except ValueError:
        return set()


def tool_home(tool_id: str) -> Path:
    """Writable per-tool home directory (state/config for sandboxed children)."""
    from pathlib import Path

    override = os.environ.get("AI_OSINT_HUB_TOOL_HOME")
    if override:
        return Path(override).expanduser().resolve() / tool_id
    return (locator.repo_root() / ".toolhome" / tool_id).resolve()


def _trusted_placeholders(capability: ToolCapability) -> dict[str, str]:
    return {
        "tool_home": str(tool_home(capability.tool_id)),
        "repo_root": str(locator.repo_root()),
        "managed_bin": str(locator.home_bin()),
    }


def _expand_trusted_placeholders(capability: ToolCapability, value: str) -> str:
    text = str(value)
    for placeholder, replacement in _trusted_placeholders(capability).items():
        text = text.replace("{" + placeholder + "}", replacement)
    return text


def invocation_env(capability: ToolCapability) -> dict[str, str]:
    """Expand trusted manifest env with writable-path placeholders."""
    env: dict[str, str] = {}
    home = tool_home(capability.tool_id)
    for key, value in capability.invocation.env.items():
        env[str(key)] = _expand_trusted_placeholders(capability, str(value))
    if env:
        try:
            home.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    return env


def build_params_for_entity(capability: ToolCapability,
                            entity_type: EntityType | str,
                            entity_value: str,
                            extras: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    """Build a valid parameter dict for a target entity, or None if unsatisfiable.

    Required parameters must be fillable from the entity (or ``extras``).
    Optional parameters are filled only when they map to the entity's type.
    """
    etype = EntityType.coerce(entity_type)
    if etype is EntityType.PHONE:
        try:
            from hub.erkg.resolution import normalize_phone

            entity_value = normalize_phone(entity_value)
        except Exception:  # noqa: BLE001 - normalization must never block a pivot
            pass
    extras = extras or {}
    params: dict[str, Any] = {}
    for pname, pspec in capability.parameters.items():
        if pname in extras and extras[pname] is not None:
            params[pname] = extras[pname]
            continue
        expected = _expected_entity_types(pspec)
        if expected and etype in expected:
            if pspec.type == "array":
                params[pname] = [entity_value]
            elif pspec.type == "integer":
                try:
                    params[pname] = int(entity_value)
                except (TypeError, ValueError):
                    if pspec.required:
                        return None
                    continue
            else:
                params[pname] = entity_value
            continue
        if pspec.required:
            return None
    return params


def validate_params(capability: ToolCapability, params: dict[str, Any]) -> list[str]:
    """Validate a params dict against the manifest. Returns list of errors."""
    errors: list[str] = []
    if not isinstance(params, dict):
        return ["params must be an object"]
    for pname, pspec in capability.parameters.items():
        if pspec.required and pname not in params:
            errors.append(f"missing required parameter '{pname}'")
            continue
        if pname not in params:
            continue
        value = params[pname]
        if pspec.type == "array" and not isinstance(value, list):
            errors.append(f"parameter '{pname}' must be an array")
        elif pspec.type == "integer" and not isinstance(value, int):
            errors.append(f"parameter '{pname}' must be an integer")
        elif pspec.type == "boolean" and not isinstance(value, bool):
            errors.append(f"parameter '{pname}' must be a boolean")
        elif pspec.type == "string" and not isinstance(value, str):
            errors.append(f"parameter '{pname}' must be a string")
        if pspec.enum and value not in pspec.enum:
            errors.append(f"parameter '{pname}' must be one of {pspec.enum}")
    unknown = set(params) - set(capability.parameters)
    if unknown:
        errors.append(f"unknown parameters: {sorted(unknown)}")
    return errors


def build_argv(capability: ToolCapability, params: dict[str, Any]) -> list[str]:
    """Build the argument vector for a subprocess capability (shell=False)."""
    invocation = capability.invocation
    if invocation.kind != "binary" or not invocation.binary:
        raise ValueError(f"{capability.tool_id} is not a binary capability")
    argv: list[str] = [invocation.binary]
    argv.extend(invocation.prefix_args)
    for pname, pspec in capability.parameters.items():
        if pname not in params:
            continue
        value = params[pname]
        values = value if isinstance(value, list) else [value]
        flag = pspec.cli_flag if pspec.cli_flag is not None else invocation.cli_map.get(pname)
        if flag is None:
            for item in values:
                if not isinstance(item, (str, int)):
                    raise ValueError(f"parameter '{pname}' cannot be positional")
                argv.append(str(item))
        elif isinstance(value, bool):
            if value:
                argv.append(flag)
        else:
            for item in values:
                argv.extend([flag, str(item)])
    argv.extend(invocation.extra_flags)
    # Trusted writable-path placeholders are expanded for flags as well, so
    # sandboxed tools can be pointed at <repo>/.toolhome/<tool> directories.
    if any("{" in str(arg) and "}" in str(arg) for arg in argv):
        argv = [_expand_trusted_placeholders(capability, arg) for arg in argv]
        for index, arg in enumerate(argv[:-1]):
            if arg in ("--folderoutput", "--output-folder", "--output",
                       "-o", "--input"):
                try:
                    from pathlib import Path

                    Path(argv[index + 1]).expanduser().mkdir(parents=True,
                                                            exist_ok=True)
                except OSError:
                    pass
    return argv


# ════════════════════════════════════════════════════════════════════════
# Health checks
# ════════════════════════════════════════════════════════════════════════

def health_check(tool_id: str, *, force: bool = False) -> Optional[HealthStatus]:
    cap = get_tool(tool_id)
    if cap is None:
        return None
    key = cap.tool_id.lower()
    if not force and key in _HEALTH_CACHE:
        return _HEALTH_CACHE[key]
    status = _probe_health(cap)
    _HEALTH_CACHE[key] = status
    return status


def _provider_auth(provider: str) -> tuple[str, str]:
    """Credential status for an API provider (never contains raw secrets)."""
    try:
        from hub.credentials import provider_status
    except Exception:  # noqa: BLE001
        return "NOT_REQUIRED", ""
    info = provider_status(provider)
    detail = f"{info['label']}: {info['auth_status']}"
    missing = info.get("missing_fields") or []
    if missing and info["auth_status"] in {"MISSING_KEY", "PARTIAL"}:
        detail += f" (missing: {', '.join(missing)})"
    return str(info["auth_status"]), detail


def _optional_session_auth(cap: ToolCapability) -> tuple[str, str]:
    """ghunt/h8mail are skipped cleanly until their local session/config exists."""
    tool_id = cap.tool_id
    home = tool_home(tool_id)
    candidates: list[Path] = []
    if tool_id == "ghunt":
        candidates = [home / ".ghunt" / "creds.m",
                      home / "ghunt" / ".ghunt" / "creds.m"]
        configured_detail = "Google session loaded"
        missing_detail = ("no ghunt session (run 'ghunt login'); skipped until configured")
    elif tool_id == "h8mail":
        candidates = [home / "config.ini", home / ".h8mail" / "config.ini",
                      home / "h8mail" / "config.ini"]
        configured_detail = "breach config loaded"
        missing_detail = ("no h8mail config.ini; skipped until configured")
    else:
        return "NOT_REQUIRED", ""
    try:
        if any(path.is_file() for path in candidates):
            return "CONFIGURED", configured_detail
    except OSError:
        pass
    return "OPTIONAL_UNCONFIGURED", missing_detail


def capability_auth(cap: ToolCapability) -> tuple[str, str]:
    """Return (auth_status, auth_detail) for a capability without network calls."""
    if cap.auth_provider:
        return _provider_auth(cap.auth_provider)
    if cap.tool_id in {"ghunt", "h8mail"}:
        return _optional_session_auth(cap)
    return "NOT_REQUIRED", ""


def capability_auth_ready(cap: ToolCapability) -> bool:
    """Whether credentials/config allow this tool to run in the pivot planner."""
    status, _ = capability_auth(cap)
    return status not in {"MISSING_KEY", "PARTIAL", "OPTIONAL_UNCONFIGURED"}


def clear_health_cache() -> None:
    """Invalidate all cached health/auth statuses (credential updates)."""
    _HEALTH_CACHE.clear()


def _probe_health(cap: ToolCapability) -> HealthStatus:
    now = utc_now()
    invocation = cap.invocation
    auth_status, auth_detail = capability_auth(cap)
    if invocation.kind == "builtin":
        detail_parts = []
        available = True
        try:
            load_parser(cap.parser_ref)
        except Exception as exc:  # noqa: BLE001
            available = False
            detail_parts.append(f"parser unavailable: {type(exc).__name__}: {exc}")
        try:
            _load_builtin(invocation.builtin_ref)
        except Exception as exc:  # noqa: BLE001
            available = False
            detail_parts.append(f"collector unavailable: {type(exc).__name__}: {exc}")
        if available:
            detail_parts.append("python-native collector ready")
        if auth_detail:
            detail_parts.append(auth_detail)
        return HealthStatus(tool_id=cap.tool_id, available=available, kind="builtin",
                            detail="; ".join(detail_parts), checked_at=now,
                            resolver="builtin", auth_status=auth_status,
                            auth_detail=auth_detail)

    binary = invocation.binary or ""
    resolved = locator.resolve_tool(cap.tool_id, binary)
    notes: list[str] = [resolved.detail]
    missing_env = [name for name in invocation.api_key_envs if not os.environ.get(name)]
    if missing_env:
        notes.append(f"optional API keys not set: {', '.join(missing_env)}")
    if cap.execution_mode == ExecutionMode.INTRUSIVE_BLOCKED:
        notes.append("blocked by policy (INTRUSIVE_BLOCKED)")
    if getattr(cap, "invocation_verified", True) is False:
        notes.append("invocation flags unverified on this host")
    if auth_detail:
        notes.append(auth_detail)
    return HealthStatus(tool_id=cap.tool_id, available=resolved.available,
                        kind="binary", detail="; ".join(notes),
                        binary_path=resolved.location, checked_at=now,
                        resolver=resolved.source, auth_status=auth_status,
                        auth_detail=auth_detail)


def _load_builtin(builtin_ref: Optional[str]):
    if not builtin_ref:
        raise ImportError("no builtin_ref declared")
    module_path, _, func_name = builtin_ref.partition(":")
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, func_name)


def health_check_all(*, force: bool = False) -> list[HealthStatus]:
    statuses: list[HealthStatus] = []
    for cap in all_capabilities():
        status = health_check(cap.tool_id, force=force)
        if status is not None:
            statuses.append(status)
    return statuses


def available_tool_ids(*, force: bool = False) -> set[str]:
    """Tool ids that are executable *and* credential/auth ready for pivots."""
    available: set[str] = set()
    for cap in all_capabilities():
        if cap.execution_mode == ExecutionMode.INTRUSIVE_BLOCKED:
            continue
        status = health_check(cap.tool_id, force=force)
        if (status is not None and status.available
                and status.auth_ready
                and capability_auth_ready(cap)):
            available.add(cap.tool_id.lower())
    return available - cooldown.cooled_tool_ids()


# ════════════════════════════════════════════════════════════════════════
# Schema / catalog exporters (single source of truth)
# ════════════════════════════════════════════════════════════════════════

def export_llm_tool_schemas() -> list[dict[str, Any]]:
    """OpenAI/Anthropic-style tool-calling JSON schemas for every capability."""
    schemas = []
    for cap in all_capabilities():
        properties = {name: spec.json_schema() for name, spec in cap.parameters.items()}
        schemas.append({
            "name": cap.tool_id,
            "description": cap.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": [n for n, s in cap.parameters.items() if s.required],
                "additionalProperties": False,
            },
            "metadata": {
                "execution_mode": cap.execution_mode.value,
                "accepted_entity_types": [e.value for e in cap.accepted_entity_types],
                "produced_entity_types": [e.value for e in cap.produced_entity_types],
                "reliability": cap.reliability,
                "timeout_sec": cap.timeout_sec,
            },
        })
    return schemas


def export_mcp_tool_definitions() -> list[dict[str, Any]]:
    """MCP ``tools/list`` definitions generated from the same registry."""
    definitions = []
    for schema in export_llm_tool_schemas():
        definitions.append({
            "name": f"osint_run_{schema['name']}",
            "description": schema["description"],
            "inputSchema": schema["parameters"],
        })
    return definitions


def export_cli_table(*, force_health: bool = False) -> str:
    """Markdown capability table with live health status (used by ``tools``)."""
    header = (
        "| Tool | Mode | Accepts | Produces | Reliability | Rate | Resolver | Auth | Status |\n"
        "|------|------|---------|----------|-------------|------|----------|------|--------|"
    )
    rows = [header]
    for cap in all_capabilities():
        status = health_check(cap.tool_id, force=force_health)
        if cap.invocation.kind == "builtin":
            source = "python-native"
        else:
            source = (status.resolver if status and status.resolver
                      else (cap.invocation.binary or "?"))
        avail = "✅ AVAILABLE" if status and status.available else "❌ MISSING"
        auth = status.auth_status if status else "NOT_REQUIRED"
        rows.append(
            f"| {cap.tool_id} | {cap.execution_mode.value} | "
            f"{', '.join(e.value for e in cap.accepted_entity_types)} | "
            f"{', '.join(e.value for e in cap.produced_entity_types)} | "
            f"{cap.reliability:.2f} | {cap.rate_limit_rps:g} rps | {source} | {auth} | {avail} |"
        )
    return "\n".join(rows)


def export_cli_table_rows(*, force_health: bool = False) -> list[dict[str, Any]]:
    rows = []
    for cap in all_capabilities():
        status = health_check(cap.tool_id, force=force_health)
        avail = bool(status and status.available)
        auth_status = status.auth_status if status else "NOT_REQUIRED"
        policy_blocked = cap.execution_mode == ExecutionMode.INTRUSIVE_BLOCKED
        if policy_blocked:
            ui_status = "blocked"
        elif not avail:
            ui_status = "missing"
        elif auth_status in {"MISSING_KEY", "PARTIAL"}:
            ui_status = "needs_key"
        else:
            ui_status = "ready"
        rows.append({
            "tool_id": cap.tool_id,
            "display_name": cap.display_name,
            "mode": cap.execution_mode.value,
            "accepted": [e.value for e in cap.accepted_entity_types],
            "produced": [e.value for e in cap.produced_entity_types],
            "reliability": cap.reliability,
            "timeout_sec": cap.timeout_sec,
            "rate_limit_rps": cap.rate_limit_rps,
            "available": avail,
            "resolver": status.resolver if status else "",
            "binary_path": status.binary_path if status else "",
            "health_detail": status.detail if status else "",
            "auth_status": auth_status,
            "auth_detail": status.auth_detail if status else "",
            "auth_ready": bool(status and status.auth_ready) if status else True,
            "requires_env": list(cap.invocation.api_key_envs),
            "authorization_required": cap.authorization_required,
            "policy_blocked": policy_blocked,
            "ui_status": ui_status,
        })
    return rows


# ════════════════════════════════════════════════════════════════════════
# Default registry installation
# ════════════════════════════════════════════════════════════════════════

def _param(name: str, *, type_: str = "string", required: bool = True,
           description: str = "", format_: str = "", cli_flag: Optional[str] = None,
           positional: bool = False, items_type: str = "string") -> ParameterSpec:
    return ParameterSpec(
        name=name, type=type_, required=required, description=description,
        format=format_, cli_flag=cli_flag, positional=positional, items_type=items_type,
    )


def _legacy(parser: str) -> str:
    return f"hub.tools.parsers.{parser}:parse"


def _cap(**fields: Any) -> ToolCapability:
    fields.setdefault("parser_version", "2.0.0")
    return ToolCapability(**fields)


def _install_default_registry() -> None:
    # ── Passive OSINT binaries (Spec 3) ──────────────────────────────
    register(_cap(
        tool_id="holehe", display_name="Holehe Email-to-Service Mapper",
        description="Check whether an email address is registered on 120+ online services.",
        accepted_entity_types=[EntityType.EMAIL],
        produced_entity_types=[EntityType.SERVICE, EntityType.USERNAME],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"email": _param("email", format_="email", description="Email address")},
        timeout_sec=120, rate_limit_rps=1.0, reliability=0.85, prior_yield=0.85,
        invocation=InvocationSpec(kind="binary", binary="holehe", cli_map={"email": None},
                                  extra_flags=["--no-color"]),
        parser_ref=_legacy("holehe"),
        notes="Invocation verified against holehe CLI docs.",
    ))
    register(_cap(
        tool_id="maigret", display_name="Maigret Username Search",
        description="Search a username across 2500+ social platforms and report claimed profiles.",
        accepted_entity_types=[EntityType.USERNAME],
        produced_entity_types=[EntityType.SERVICE, EntityType.SOCIAL_PROFILE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"username": _param("username", format_="username", description="Username handle")},
        timeout_sec=900, rate_limit_rps=0.2, reliability=0.80, prior_yield=0.75,
        invocation=InvocationSpec(
            kind="binary", binary="maigret", cli_map={"username": None},
            extra_flags=["--top-sites", "50", "--no-color", "--no-progressbar",
                         "--no-autoupdate", "--no-recursion",
                         "--folderoutput", "{tool_home}/reports"],
            # maigret writes ~/.maigret (sandboxed venv cannot write user home)
            # and colorama crashes on cp1252 when found IDs contain non-Latin
            # characters unless UTF-8 stdio is forced.
            env={"USERPROFILE": "{tool_home}", "HOME": "{tool_home}",
                 "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
                 "NO_COLOR": "1"},
            tolerate_nonzero_with_stdout=True,
        ),
        parser_ref=_legacy("maigret"),
        invocation_verified=True,
        notes=("argv verified on maigret 0.6.6: maigret <username> --top-sites 50 "
               "--no-color --no-progressbar --no-autoupdate; MAIGRET_HOME redirected "
               "to {tool_home}. Live run returns 6 accounts for 'torvalds'."),
    ))
    register(_cap(
        tool_id="h8mail", display_name="h8mail Breach Lookup",
        description="Check an email address against local breach indices for credential exposure.",
        accepted_entity_types=[EntityType.EMAIL],
        produced_entity_types=[EntityType.BREACH_RECORD, EntityType.EMAIL],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"email": _param("email", format_="email", cli_flag="-t",
                                    description="Target email")},
        timeout_sec=120, rate_limit_rps=0.5, reliability=0.80, prior_yield=0.55,
        invocation=InvocationSpec(
            kind="binary", binary="h8mail", cli_map={"email": "-t"},
            env={"USERPROFILE": "{tool_home}", "HOME": "{tool_home}"},
        ),
        parser_ref=_legacy("h8mail"),
        invocation_verified=True,
        notes=("argv verified on h8mail 2.5.6: h8mail -t <email>; full breach lookup "
               "needs optional local breach indexes/API keys (empty result is real). "
               "OPTIONAL_UNCONFIGURED until <tool_home>/config.ini exists, so pivots "
               "skip it cleanly."),
    ))
    register(_cap(
        tool_id="theharvester", display_name="theHarvester OSINT Harvester",
        description="Harvest emails, subdomains, hosts and URLs from public sources for a domain.",
        accepted_entity_types=[EntityType.DOMAIN],
        produced_entity_types=[EntityType.EMAIL, EntityType.DOMAIN, EntityType.SUBDOMAIN,
                               EntityType.IP, EntityType.URL],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={
            "domain": _param("domain", format_="domain", cli_flag="-d",
                            description="Target domain"),
        },
        timeout_sec=300, rate_limit_rps=0.2, reliability=0.75, prior_yield=0.80,
        invocation=InvocationSpec(
            kind="binary", binary="theHarvester",
            cli_map={"domain": "-d"},
            # crtsh is a keyless, reliable certificate-transparency source; `-q`
            # suppresses missing-API-key noise. Config is redirected to a
            # workspace-writable tool home so the sandboxed managed venv can
            # create its SQLite stash/config files.
            extra_flags=["-b", "crtsh", "-q"],
            api_key_envs=["GOOGLE_API_KEY", "GOOGLE_CX"],
            env={"USERPROFILE": "{tool_home}", "HOME": "{tool_home}"},
        ),
        parser_ref=_legacy("theharvester"),
        invocation_verified=True,
        notes=("argv verified on theHarvester 4.11.1 (Python 3.14 managed venv): "
               "theHarvester -d <domain> -b crtsh -q. Config/state redirected via "
               "USERPROFILE={tool_home}. Optional API keys unlock more sources."),
    ))
    register(_cap(
        tool_id="sherlock", display_name="Sherlock Username Search",
        description="Search a username across ~400 social platforms using the Sherlock CLI.",
        accepted_entity_types=[EntityType.USERNAME],
        produced_entity_types=[EntityType.SOCIAL_PROFILE, EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"username": _param("username", format_="username")},
        timeout_sec=180, rate_limit_rps=0.5, reliability=0.80, prior_yield=0.70,
        invocation=InvocationSpec(kind="binary", binary="sherlock", cli_map={"username": None},
                                  extra_flags=["--no-color", "--print-found"]),
        parser_ref=_legacy("sherlock"),
        invocation_verified=False, notes="Binary absent on this host.",
    ))
    register(_cap(
        tool_id="ghunt", display_name="GHunt Google Account OSINT",
        description="Extract Google account artefacts (YouTube, Maps, Photos) from a Gmail address.",
        accepted_entity_types=[EntityType.EMAIL],
        produced_entity_types=[EntityType.SOCIAL_PROFILE, EntityType.USERNAME, EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"email": _param("email", format_="email")},
        timeout_sec=180, rate_limit_rps=0.2, reliability=0.85, prior_yield=0.65,
        invocation=InvocationSpec(
            kind="binary", binary="ghunt", cli_map={"email": None},
            prefix_args=["email"],
            env={"USERPROFILE": "{tool_home}", "HOME": "{tool_home}"},
        ),
        parser_ref=_legacy("ghunt"),
        invocation_verified=True,
        notes=("OPTIONAL_UNCONFIGURED until a Google session exists at "
               "<tool_home>/.ghunt/creds.m (run 'ghunt login' with HOME/tool_home); "
               "pivots skip it cleanly when unauthenticated."),
    ))
    register(_cap(
        tool_id="phoneinfoga", display_name="Phoneinfoga Phone Intelligence",
        description="Phone number intelligence: carrier, location and linked services.",
        accepted_entity_types=[EntityType.PHONE],
        produced_entity_types=[EntityType.ORGANIZATION, EntityType.LOCATION, EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"phone": _param("phone", format_="phone", cli_flag="-n")},
        timeout_sec=120, rate_limit_rps=0.5, reliability=0.75, prior_yield=0.60,
        invocation=InvocationSpec(kind="binary", binary="phoneinfoga", cli_map={"phone": "-n"},
                                  prefix_args=["scan"]),
        parser_ref=_legacy("phoneinfoga"),
        invocation_verified=False, notes="Binary absent on this host.",
    ))
    register(_cap(
        tool_id="snscrape", display_name="Native Social/Dev Profile Probe",
        description=("Python-native public profile probe (GitLab, Reddit, Keybase, "
                     "HackerNews, Lichess, Chess.com, Dev.to, Mastodon, Medium) — "
                     "replaces the broken upstream snscrape Twitter/X CLI."),
        accepted_entity_types=[EntityType.USERNAME],
        produced_entity_types=[EntityType.SOCIAL_PROFILE, EntityType.URL],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"username": _param("username", format_="username")},
        timeout_sec=45, rate_limit_rps=0.5, reliability=0.65, prior_yield=0.60,
        invocation=InvocationSpec(
            kind="builtin", builtin_ref="hub.tools.builtin.snscrape:collect"),
        parser_ref=_legacy("snscrape"),
        invocation_verified=True,
        notes=("Zero-auth httpx probes of public platform APIs; always exits 0 "
               "and emits JSONL matching the snscrape parser. Upstream snscrape "
               "CLI is no longer invoked (Twitter/X guest tokens removed → exit 2)."),
    ))
    # ── Active reconnaissance ───────────────────────────────────────
    register(_cap(
        tool_id="nmap", display_name="Nmap Network Scanner",
        description="Scan hosts for open ports and service banners (XML output).",
        accepted_entity_types=[EntityType.IP, EntityType.DOMAIN, EntityType.SUBDOMAIN],
        produced_entity_types=[EntityType.IP, EntityType.PORT, EntityType.SERVICE],
        execution_mode=ExecutionMode.ACTIVE_RECON,
        parameters={"target": _param("target", format_="hostname", description="Host or IP")},
        timeout_sec=300, rate_limit_rps=0.1, reliability=0.95, prior_yield=0.70,
        invocation=InvocationSpec(kind="binary", binary="nmap", cli_map={"target": None},
                                  extra_flags=["-oX", "-", "-sV", "--top-ports", "100", "-T4"]),
        parser_ref=_legacy("nmap"),
        notes="argv verified: nmap -oX - -sV --top-ports 100 -T4 <target>.",
    ))
    register(_cap(
        tool_id="amass", display_name="Amass Subdomain Enumerator",
        description="Passive DNS enumeration for subdomains of a domain.",
        accepted_entity_types=[EntityType.DOMAIN],
        produced_entity_types=[EntityType.SUBDOMAIN, EntityType.IP],
        execution_mode=ExecutionMode.ACTIVE_RECON,
        parameters={"domain": _param("domain", format_="domain", cli_flag="-d")},
        timeout_sec=300, rate_limit_rps=0.1, reliability=0.85, prior_yield=0.55,
        invocation=InvocationSpec(kind="binary", binary="amass", cli_map={"domain": "-d"},
                                  prefix_args=["enum", "-passive"],
                                  extra_flags=["-timeout", "2"]),
        parser_ref=_legacy("amass"),
        invocation_verified=True,
        notes=("argv verified on amass v4.2.0: amass enum -passive -d <domain> -timeout 2. "
               "Default stdout is the OAM graph text format, parsed deterministically. "
               "Passive enumeration took ~128s for example.com; timeout is a collection gap."),
    ))
    register(_cap(
        tool_id="gobuster", display_name="Gobuster Directory Buster",
        description="Enumerate web directories/files against an in-scope URL.",
        accepted_entity_types=[EntityType.URL, EntityType.DOMAIN],
        produced_entity_types=[EntityType.URL],
        execution_mode=ExecutionMode.ACTIVE_RECON,
        parameters={
            "url": _param("url", format_="url", cli_flag="-u"),
            "wordlist": _param("wordlist", required=False, cli_flag="-w",
                               description="Path to wordlist (required for execution)"),
        },
        timeout_sec=300, rate_limit_rps=0.1, reliability=0.70, prior_yield=0.35,
        invocation=InvocationSpec(kind="binary", binary="gobuster", cli_map={"url": "-u", "wordlist": "-w"},
                                  prefix_args=["dir"]),
        parser_ref=_legacy("gobuster"),
        invocation_verified=False, notes="Requires an explicit wordlist parameter.",
    ))
    register(_cap(
        tool_id="whatweb", display_name="WhatWeb Technology Fingerprinter",
        description="Fingerprint CMS/frameworks/server software on a web host.",
        accepted_entity_types=[EntityType.DOMAIN, EntityType.URL],
        produced_entity_types=[EntityType.SERVICE, EntityType.URL],
        execution_mode=ExecutionMode.ACTIVE_RECON,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=120, rate_limit_rps=0.2, reliability=0.80, prior_yield=0.50,
        invocation=InvocationSpec(kind="binary", binary="whatweb", cli_map={"target": None},
                                  extra_flags=["--color=never"]),
        parser_ref=_legacy("whatweb"),
        invocation_verified=True,
        notes=("argv verified: whatweb --color=never <target>; resolved via WSL2 "
               "bridge when the Windows host has no native binary."),
    ))
    # ── Credential tooling (gated) ──────────────────────────────────
    register(_cap(
        tool_id="hashcat", display_name="Hashcat Offline Cracker",
        description="Offline password-hash cracking (wordlist/rule/mask attacks).",
        accepted_entity_types=[EntityType.HASH],
        produced_entity_types=[EntityType.CREDENTIAL],
        execution_mode=ExecutionMode.ACTIVE_RECON,
        parameters={"hash": _param("hash", format_="hash", description="Hash file or hash string")},
        timeout_sec=600, rate_limit_rps=0.1, reliability=0.90, prior_yield=0.40,
        invocation=InvocationSpec(kind="binary", binary="hashcat", cli_map={"hash": None}),
        parser_ref=_legacy("hashcat"),
        authorization_required=True, invocation_verified=False,
        notes="Requires explicit authorization (allow_authorized_tools); offline only.",
    ))
    register(_cap(
        tool_id="hydra", display_name="Hydra Online Brute-Force",
        description="Online credential brute-force against network services.",
        accepted_entity_types=[EntityType.SERVICE],
        produced_entity_types=[EntityType.CREDENTIAL],
        execution_mode=ExecutionMode.INTRUSIVE_BLOCKED,
        parameters={
            "service": _param("service", format_="service"),
            "username": _param("username", required=False, cli_flag="-l"),
            "password": _param("password", required=False, cli_flag="-p"),
        },
        timeout_sec=300, rate_limit_rps=0.05, reliability=0.50, prior_yield=0.20,
        invocation=InvocationSpec(kind="binary", binary="hydra", cli_map={"service": None,
                                                                          "username": "-l",
                                                                          "password": "-p"}),
        parser_ref=_legacy("hydra"),
        authorization_required=True, invocation_verified=False,
        notes="BLOCKED by policy: INTRUSIVE_BLOCKED never spawns a subprocess.",
    ))
    # ── Python-native passive collectors (always available) ─────────
    register(_cap(
        tool_id="dns_lookup", display_name="Builtin DNS Resolver",
        description="Resolve A/AAAA records for a domain using the host resolver (no third party).",
        accepted_entity_types=[EntityType.DOMAIN, EntityType.SUBDOMAIN],
        produced_entity_types=[EntityType.IP],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=15, rate_limit_rps=2.0, reliability=0.90, prior_yield=0.50,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.dns_lookup:collect"),
        parser_ref="hub.tools.parsers.dns_lookup:parse",
        notes="Python-native; works with no external binaries.",
    ))
    register(_cap(
        tool_id="http_headers", display_name="Builtin HTTP Header Collector",
        description="Fetch public HTTP response headers from an in-scope host (SSRF-guarded).",
        accepted_entity_types=[EntityType.DOMAIN, EntityType.URL],
        produced_entity_types=[EntityType.URL, EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=20, rate_limit_rps=1.0, reliability=0.80, prior_yield=0.45,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.http_headers:collect"),
        parser_ref="hub.tools.parsers.http_headers:parse",
        notes="Python-native; blocks private/loopback/metadata addresses.",
    ))
    register(_cap(
        tool_id="tls_cert", display_name="Builtin TLS Certificate Collector",
        description="Read the peer TLS certificate from an in-scope host: SANs, issuer, validity.",
        accepted_entity_types=[EntityType.DOMAIN, EntityType.SUBDOMAIN],
        produced_entity_types=[EntityType.SUBDOMAIN, EntityType.ORGANIZATION],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=15, rate_limit_rps=1.0, reliability=0.90, prior_yield=0.50,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.tls_cert:collect"),
        parser_ref="hub.tools.parsers.tls_cert:parse",
        notes="Python-native; no third-party API.",
    ))

    # ══════════════════════════════════════════════════════════════
    # Phase 7 native passive expansion — 7 zero-auth python collectors
    # (real public queries via httpx; SSRF-guarded; no keys/cookies)
    # ══════════════════════════════════════════════════════════════
    register(_cap(
        tool_id="photon_crawler", display_name="Builtin Photon-Style Crawler",
        description=("Fast passive crawl of a public site: root page, robots.txt and "
                     "sitemap.xml; extracts links, emails, subdomains, social profiles, "
                     "JS endpoints and cloud storage buckets."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.URL],
        produced_entity_types=[EntityType.URL, EntityType.EMAIL, EntityType.SUBDOMAIN,
                               EntityType.SOCIAL_PROFILE, EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=45, rate_limit_rps=1.0, reliability=0.65, prior_yield=0.60,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.photon_crawler:collect"),
        parser_ref="hub.tools.parsers.photon_crawler:parse",
        notes="Python-native; manual SSRF-safe redirect handling.",
    ))
    register(_cap(
        tool_id="github_osint", display_name="GitHub Public API OSINT",
        description=("Zero-auth GitHub REST lookups: profile, public repos and public "
                     "events to pivot username/email to person, org, location, blog, "
                     "repositories and commit-author emails."),
        accepted_entity_types=[EntityType.USERNAME, EntityType.EMAIL],
        produced_entity_types=[EntityType.SOCIAL_PROFILE, EntityType.PERSON,
                               EntityType.ORGANIZATION, EntityType.LOCATION,
                               EntityType.URL, EntityType.EMAIL, EntityType.REPOSITORY],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={
            "username": _param("username", format_="username", required=False),
            "email": _param("email", format_="email", required=False),
        },
        timeout_sec=60, rate_limit_rps=0.5, reliability=0.80, prior_yield=0.75,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.github_osint:collect"),
        parser_ref="hub.tools.parsers.github_osint:parse",
        auth_provider="github",
        notes=("Public GitHub API; GITHUB_TOKEN raises the REST limit to 5,000 req/h, "
               "otherwise KEYLESS_LIMITED (60 req/h)."),
    ))
    register(_cap(
        tool_id="virustotal_lookup", display_name="VirusTotal v3 Lookup",
        description=("VirusTotal API v3 passive DNS: subdomains, resolutions, ASN/owner, "
                     "reputation verdicts for domains/IPs."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.IP],
        produced_entity_types=[EntityType.SUBDOMAIN, EntityType.IP,
                               EntityType.ORGANIZATION, EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=45, rate_limit_rps=0.25, reliability=0.85, prior_yield=0.70,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.virustotal_lookup:collect"),
        parser_ref="hub.tools.parsers.virustotal_lookup:parse",
        auth_provider="virustotal",
        notes="Requires VIRUSTOTAL_API_KEY; skipped by the pivot planner when MISSING_KEY.",
    ))
    register(_cap(
        tool_id="shodan_lookup", display_name="Shodan Host/DNS Lookup",
        description=("Shodan API: open ports, service banners, hostnames/subdomains and "
                     "ISP/ASN organization for IPs/domains."),
        accepted_entity_types=[EntityType.IP, EntityType.DOMAIN],
        produced_entity_types=[EntityType.IP, EntityType.PORT, EntityType.SERVICE,
                               EntityType.SUBDOMAIN, EntityType.ORGANIZATION],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=45, rate_limit_rps=0.25, reliability=0.80, prior_yield=0.70,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.shodan_lookup:collect"),
        parser_ref="hub.tools.parsers.shodan_lookup:parse",
        auth_provider="shodan",
        notes="Requires SHODAN_API_KEY; skipped by the pivot planner when MISSING_KEY.",
    ))
    register(_cap(
        tool_id="censys_lookup", display_name="Censys Host/Certificate Lookup",
        description=("Censys Search API v2: host services/banners, TLS SAN subdomains and "
                     "autonomous-system metadata."),
        accepted_entity_types=[EntityType.IP, EntityType.DOMAIN],
        produced_entity_types=[EntityType.IP, EntityType.PORT, EntityType.SERVICE,
                               EntityType.SUBDOMAIN, EntityType.ORGANIZATION],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=60, rate_limit_rps=0.25, reliability=0.80, prior_yield=0.65,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.censys_lookup:collect"),
        parser_ref="hub.tools.parsers.censys_lookup:parse",
        auth_provider="censys",
        notes=("Requires CENSYS_API_ID + CENSYS_API_SECRET (Basic) or CENSYS_TOKEN "
               "(Bearer); skipped when PARTIAL/MISSING_KEY."),
    ))
    register(_cap(
        tool_id="hunter_lookup", display_name="Hunter.io Email Intelligence",
        description=("Hunter.io v2 domain search + email verifier: indexed emails, "
                     "employee names/roles, deliverability confidence."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.EMAIL],
        produced_entity_types=[EntityType.EMAIL, EntityType.PERSON,
                               EntityType.ORGANIZATION, EntityType.SOCIAL_PROFILE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={
            "domain": _param("domain", format_="domain", required=False),
            "email": _param("email", format_="email", required=False),
        },
        timeout_sec=30, rate_limit_rps=0.5, reliability=0.80, prior_yield=0.60,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.hunter_lookup:collect"),
        parser_ref="hub.tools.parsers.hunter_lookup:parse",
        auth_provider="hunter",
        notes="Requires HUNTER_API_KEY; skipped by the pivot planner when MISSING_KEY.",
    ))
    register(_cap(
        tool_id="gravatar_lookup", display_name="Gravatar Profile Lookup",
        description=("Gravatar profile JSON by email hash: display name, preferred "
                     "username, linked accounts, profile/avatar URLs."),
        accepted_entity_types=[EntityType.EMAIL],
        produced_entity_types=[EntityType.SOCIAL_PROFILE, EntityType.USERNAME,
                               EntityType.PERSON, EntityType.URL],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"email": _param("email", format_="email")},
        timeout_sec=20, rate_limit_rps=2.0, reliability=0.75, prior_yield=0.50,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.gravatar_lookup:collect"),
        parser_ref="hub.tools.parsers.gravatar_lookup:parse",
        notes="Public Gravatar JSON endpoints; 404 means no profile (valid empty result).",
    ))
    register(_cap(
        tool_id="pgp_keyserver", display_name="PGP Keyserver Lookup",
        description=("OpenPGP keyserver index lookup (keys.openpgp.org / "
                     "keyserver.ubuntu.com) for UIDs, real names and bound emails."),
        accepted_entity_types=[EntityType.EMAIL, EntityType.USERNAME],
        produced_entity_types=[EntityType.EMAIL, EntityType.PERSON],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={
            "email": _param("email", format_="email", required=False),
            "username": _param("username", format_="username", required=False),
        },
        timeout_sec=30, rate_limit_rps=1.0, reliability=0.80, prior_yield=0.45,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.pgp_keyserver:collect"),
        parser_ref="hub.tools.parsers.pgp_keyserver:parse",
        notes="HKP machine-readable index; no key material imported.",
    ))
    register(_cap(
        tool_id="rdap_lookup", display_name="RDAP WHOIS Lookup",
        description=("Modern public RDAP JSON for domains/IPs: registrar/registrant "
                     "organizations, contact emails, nameservers, registration dates."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.IP],
        produced_entity_types=[EntityType.ORGANIZATION, EntityType.EMAIL,
                               EntityType.DOMAIN],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=30, rate_limit_rps=1.0, reliability=0.85, prior_yield=0.50,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.rdap_lookup:collect"),
        parser_ref="hub.tools.parsers.rdap_lookup:parse",
        notes="Queries rdap.org; input target is validated, only rdap.org is fetched.",
    ))
    register(_cap(
        tool_id="wayback_cdx", display_name="Wayback Machine CDX",
        description=("Archive.org CDX API: historical archived URLs and subdomains for "
                     "a domain/URL (collapsed, 200-status, bounded)."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.URL],
        produced_entity_types=[EntityType.URL, EntityType.SUBDOMAIN],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname")},
        timeout_sec=45, rate_limit_rps=0.5, reliability=0.80, prior_yield=0.55,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.wayback_cdx:collect"),
        parser_ref="hub.tools.parsers.wayback_cdx:parse",
        notes="web.archive.org CDX API; bounded to 100 collapsed URLs.",
    ))
    register(_cap(
        tool_id="darkweb_ahmia", display_name="Ahmia Dark-Web Index",
        description=("Ahmia's clearnet search index: .onion mentions, hidden-service "
                     "titles/URLs — no Tor daemon required."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.EMAIL, EntityType.USERNAME],
        produced_entity_types=[EntityType.URL, EntityType.SERVICE],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={
            "domain": _param("domain", format_="domain", required=False),
            "email": _param("email", format_="email", required=False),
            "username": _param("username", format_="username", required=False),
        },
        timeout_sec=45, rate_limit_rps=0.5, reliability=0.50, prior_yield=0.40,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.darkweb_ahmia:collect"),
        parser_ref="hub.tools.parsers.darkweb_ahmia:parse",
        notes="Ahmia clearnet index; may rate-limit (surfaced as collection failure).",
    ))

    # ══════════════════════════════════════════════════════════════
    # Phase 18 expansion — 3 zero-auth passive collectors + media_forensics
    # ══════════════════════════════════════════════════════════════
    register(_cap(
        tool_id="crtsh_lookup", display_name="crt.sh Certificate Transparency",
        description=("Query crt.sh public Certificate Transparency logs for a domain: "
                     "discovers historical subdomains, SANs and certificate issuer orgs."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.SUBDOMAIN],
        produced_entity_types=[EntityType.SUBDOMAIN, EntityType.DOMAIN, EntityType.ORGANIZATION],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"domain": _param("domain", format_="domain",
                                     description="Target domain for CT lookup")},
        timeout_sec=30, rate_limit_rps=0.5, reliability=0.85, prior_yield=0.70,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.crtsh_lookup:collect"),
        parser_ref="hub.tools.parsers.crtsh_lookup:parse",
        notes="Queries crt.sh JSON endpoint; handles 429/502/503/timeout gracefully.",
    ))
    register(_cap(
        tool_id="asn_bgp_lookup", display_name="ASN / BGP Network Lookup",
        description=("Query RIPEstat / BGPView public JSON for IP or ASN routing metadata: "
                     "ASNs, BGP prefixes, RIR, country location and holder organization."),
        accepted_entity_types=[EntityType.IP, EntityType.ASN],
        produced_entity_types=[EntityType.ASN, EntityType.ORGANIZATION,
                               EntityType.LOCATION, EntityType.IP],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={
            "ip": _param("ip", format_="ip", required=False,
                         description="Public IPv4/IPv6 address"),
            "asn": _param("asn", format_="asn", required=False,
                          description="Autonomous System Number (e.g. AS13335)"),
        },
        timeout_sec=30, rate_limit_rps=1.0, reliability=0.85, prior_yield=0.65,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.asn_bgp_lookup:collect"),
        parser_ref="hub.tools.parsers.asn_bgp_lookup:parse",
        notes="RIPEstat + BGPView public JSON; SSRF-guarded against private IPs.",
    ))
    register(_cap(
        tool_id="favicon_hash", display_name="Favicon MurmurHash3 Fingerprinter",
        description=("Fetch /favicon.ico (or <link rel=icon> fallback) via SSRF-safe HTTP "
                     "and compute Shodan-compatible 32-bit signed MurmurHash3 + SHA-256."),
        accepted_entity_types=[EntityType.DOMAIN, EntityType.URL],
        produced_entity_types=[EntityType.HASH, EntityType.SERVICE, EntityType.URL],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={"target": _param("target", format_="hostname",
                                     description="Target domain or URL")},
        timeout_sec=25, rate_limit_rps=1.0, reliability=0.85, prior_yield=0.55,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.favicon_hash:collect"),
        parser_ref="hub.tools.parsers.favicon_hash:parse",
        notes="Python-native pure-Python mmh3; manual SSRF-safe redirect handling.",
    ))
    register(_cap(
        tool_id="media_forensics", display_name="Media Forensics & Perceptual Hash",
        description=("SSRF-safe media download and forensic inspection: SHA-256, EXIF/XMP/IPTC "
                     "metadata, GPS coordinates, 64-bit dHash/pHash, optional OCR and quarantined VLM."),
        accepted_entity_types=[EntityType.URL],
        produced_entity_types=[EntityType.HASH, EntityType.LOCATION, EntityType.PERSON,
                               EntityType.ORGANIZATION, EntityType.USERNAME,
                               EntityType.EMAIL, EntityType.DOMAIN],
        execution_mode=ExecutionMode.PASSIVE,
        parameters={
            "url": _param("url", format_="url", required=False,
                          description="Public image/media URL to inspect"),
            "use_vlm": _param("use_vlm", type_="boolean", required=False,
                              description="Enable optional quarantined VLM extraction"),
        },
        timeout_sec=60, rate_limit_rps=0.5, reliability=0.80, prior_yield=0.50,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="hub.tools.builtin.media_forensics:collect"),
        parser_ref="hub.tools.parsers.media_forensics:parse",
        notes="SSRF-guarded media forensics; VLM outputs carry AI_INFERRED provenance.",
    ))


def tools_by_mode(mode: ExecutionMode | str) -> list[str]:
    """List tool ids in an execution mode (computed live from the registry)."""
    if isinstance(mode, str):
        mode = ExecutionMode(mode)
    return sorted(c.tool_id for c in _REGISTRY.values() if c.execution_mode == mode)


_install_default_registry()
