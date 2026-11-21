"""Code-enforced collection scope policy — deterministic, no LLM involved.

This module is the single authority on *whether a capability may run* and on
*which hosts a network-facing collector may touch*. It is called by
:class:`hub.tools.runtime.ToolRuntime` before any subprocess is spawned and by
the Python-native collectors before any socket is opened, so a prompt-injected
plan can never widen its own blast radius.

Rules (evaluated in this order):
  1. ``INTRUSIVE_BLOCKED`` capabilities are denied unless intrusive execution is
     explicitly enabled.
  2. ``authorization_required`` capabilities are denied unless authorized tools
     are explicitly enabled.
  3. ``ACTIVE_RECON`` is denied when the scope disables active reconnaissance.
  4. Deny-listed domains/entities always win (all execution modes).
  5. Literal private/loopback/link-local/multicast/reserved IP targets are
     denied when ``scope.block_private_addresses`` is set.
  6. ``ACTIVE_RECON`` host targets must match ``allow_domains`` (equal or
     subdomain) or be an IP listed in ``allow_ips``.
  7. ``ACTIVE_RECON`` target entities must match ``allow_entities``.
  8. Otherwise allowed.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from hub.models import EntityType, ErrorCode, ExecutionMode, ScopeConfig, ToolCapability
from hub.tools.base import infer_value_type

__all__ = [
    "PolicyDecision",
    "extract_targets",
    "check_capability",
    "is_public_ip",
    "host_in_scope",
    "assert_safe_host",
]

# Parameter formats / names that carry a network location target.
_HOST_FORMATS = {"hostname", "domain", "ip", "ipv4", "ipv6", "url"}
_HOST_PARAM_NAMES = {
    "target", "targets", "host", "hosts", "hostname", "domain", "domains",
    "url", "urls", "ip", "address",
}


class PolicyDecision(BaseModel):
    """Outcome of one deterministic pre-spawn policy evaluation."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    error_code: Optional[ErrorCode] = None
    reason: str = ""


# ════════════════════════════════════════════════════════════════════════
# Host / IP helpers
# ════════════════════════════════════════════════════════════════════════

def _as_ip(value: Any) -> Optional[ipaddress._BaseAddress]:
    """Parse an IP literal; return None for non-address values."""
    text = str(value or "").strip().strip("[]")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _normalise_host(value: Any) -> str:
    """Normalise a URL/host/``host:port`` value into a bare lowercase hostname."""
    text = str(value or "").strip().strip("\"'")
    if not text:
        return ""
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return ""
    elif text.startswith("["):  # bracketed IPv6 literal
        end = text.find("]")
        text = text[1:end] if end > 0 else text[1:]
    elif text.count(":") == 1:
        head, _, tail = text.rpartition(":")
        if tail.isdigit():
            text = head
    text = text.strip().strip("[]").strip().lower().rstrip(".")
    if not text or "/" in text or "@" in text or any(char.isspace() for char in text):
        return ""
    return text


def _normalise_domain_entry(entry: Any) -> str:
    """Normalise an allow/deny domain entry, tolerating wildcard prefixes."""
    text = str(entry or "").strip().lower()
    if text.startswith("*."):
        text = text[2:]
    return _normalise_host(text)


def _host_matches_domain(host: str, domain: str) -> bool:
    return bool(host) and bool(domain) and (host == domain or host.endswith("." + domain))


def is_public_ip(value: Any) -> bool:
    """True only for globally routable unicast addresses.

    Rejects loopback, private (RFC1918 / ULA), link-local (incl. cloud metadata
    169.254.169.254), multicast, reserved, unspecified and non-global ranges.
    """
    address = _as_ip(value)
    if address is None:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return is_public_ip(str(address.ipv4_mapped))
    if (address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_reserved or address.is_unspecified):
        return False
    return address.is_global


def assert_safe_host(host: str) -> tuple[bool, str]:
    """Resolve every A/AAAA record for ``host``; safe only if all are public.

    This is the SSRF guard used by network collectors. DNS failures fail closed.
    """
    normalised = _normalise_host(host)
    if not normalised:
        return False, f"invalid or empty host: {host!r}"
    address = _as_ip(normalised)
    if address is not None:
        if is_public_ip(normalised):
            return True, f"public IP address {normalised}"
        return False, f"blocked non-public IP address {normalised}"
    try:
        infos = socket.getaddrinfo(normalised, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        return False, f"DNS resolution failed for {normalised}: {exc}"
    addresses = sorted({str(info[4][0]) for info in infos if info and info[4]})
    if not addresses:
        return False, f"no addresses resolved for {normalised}"
    blocked = [value for value in addresses if not is_public_ip(value)]
    if blocked:
        return False, (f"host {normalised} resolves to non-public address(es): "
                       f"{', '.join(blocked[:5])}")
    return True, f"host {normalised} resolves to public address(es): {', '.join(addresses[:5])}"


# ════════════════════════════════════════════════════════════════════════
# Target extraction
# ════════════════════════════════════════════════════════════════════════

def extract_targets(capability: ToolCapability, params: dict[str, Any]) -> list[str]:
    """Return the network-location targets (hosts/IPs) declared by ``params``.

    Only parameters whose format/name denotes a host are considered; URLs are
    reduced to their hostname. Order-preserving, de-duplicated.
    """
    targets: list[str] = []
    values: dict[str, Any] = params if isinstance(params, dict) else {}
    for name, spec in capability.parameters.items():
        if name not in values or values[name] is None:
            continue
        hostish = ((spec.format or "").strip().lower() in _HOST_FORMATS
                   or name.strip().lower() in _HOST_PARAM_NAMES)
        if not hostish:
            continue
        raw_values = values[name] if isinstance(values[name], (list, tuple)) else [values[name]]
        for raw_value in raw_values:
            host = _normalise_host(raw_value)
            if host and host not in targets:
                targets.append(host)
    return targets


def _param_entity_types(name: str, spec: Any) -> set[EntityType]:
    types: set[EntityType] = set()
    for candidate in (getattr(spec, "format", "") or "", name):
        text = str(candidate or "").strip()
        if not text:
            continue
        try:
            types.add(EntityType.coerce(text))
        except ValueError:
            continue
    return types


def _entity_values(capability: ToolCapability,
                   params: dict[str, Any]) -> list[tuple[str, set[EntityType]]]:
    """All scalar parameter values plus the entity types they may represent."""
    collected: list[tuple[str, set[EntityType]]] = []
    values: dict[str, Any] = params if isinstance(params, dict) else {}
    for name, spec in capability.parameters.items():
        if name not in values or values[name] is None:
            continue
        raw_values = values[name] if isinstance(values[name], (list, tuple)) else [values[name]]
        for raw_value in raw_values:
            if isinstance(raw_value, bool) or raw_value is None:
                continue
            text = str(raw_value).strip()
            if not text:
                continue
            types = _param_entity_types(name, spec)
            try:
                types.add(infer_value_type(text))
            except (ValueError, TypeError):
                pass
            collected.append((text, types))
    return collected


def _entity_entry_matches(entry: Any, value: str, types: set[EntityType]) -> bool:
    """Match one allow/deny entry against a value (``value`` or ``type:value``)."""
    text = str(entry or "").strip()
    if not text:
        return False
    candidate = value.strip().lower()
    prefix, separator, rest = text.partition(":")
    if separator:
        try:
            entry_type: Optional[EntityType] = EntityType.coerce(prefix)
        except ValueError:
            entry_type = None
        if entry_type is not None:
            if rest.strip().lower() != candidate:
                return False
            return entry_type in types
    return text.lower() == candidate


def _entity_hosts(values: list[tuple[str, set[EntityType]]]) -> list[str]:
    """Derive hostnames from entity values (emails, URLs, domains)."""
    hosts: list[str] = []
    for value, types in values:
        host = ""
        if EntityType.EMAIL in types and "@" in value:
            host = _normalise_host(value.rsplit("@", 1)[-1])
        elif types & {EntityType.URL, EntityType.DOMAIN, EntityType.SUBDOMAIN}:
            host = _normalise_host(value)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


# ════════════════════════════════════════════════════════════════════════
# Scope matching
# ════════════════════════════════════════════════════════════════════════

def _host_denied(host: str, scope: ScopeConfig) -> bool:
    normalised = _normalise_host(host)
    if not normalised:
        return False
    for entry in scope.deny_domains:
        denied = _normalise_domain_entry(entry)
        if not denied:
            continue
        if _as_ip(denied) is not None:
            if normalised == denied:
                return True
        elif _host_matches_domain(normalised, denied):
            return True
    return False


def _host_allowed(host: str, scope: ScopeConfig) -> bool:
    """Allow-list check (allow_domains / allow_ips) for one host."""
    normalised = _normalise_host(host)
    if not normalised:
        return False
    if _as_ip(normalised) is not None:
        allow_ips = {str(entry).strip().lower() for entry in scope.allow_ips if str(entry).strip()}
        return normalised in allow_ips
    allow_domains = [entry for entry in
                     (_normalise_domain_entry(item) for item in scope.allow_domains) if entry]
    return any(_host_matches_domain(normalised, domain) for domain in allow_domains)


def host_in_scope(host: str, scope: ScopeConfig) -> bool:
    """True when ``host`` passes deny lists, private-IP blocking and allow lists."""
    normalised = _normalise_host(host)
    if not normalised:
        return False
    if _host_denied(normalised, scope):
        return False
    if _as_ip(normalised) is not None:
        if scope.block_private_addresses and not is_public_ip(normalised):
            return False
        if scope.allow_domains or scope.allow_ips:
            return normalised in {
                str(entry).strip().lower() for entry in scope.allow_ips if str(entry).strip()
            }
        return True
    if scope.allow_domains:
        return _host_allowed(normalised, scope)
    return True


# ════════════════════════════════════════════════════════════════════════
# Capability gate
# ════════════════════════════════════════════════════════════════════════

def _deny(error_code: ErrorCode, reason: str) -> PolicyDecision:
    return PolicyDecision(allowed=False, error_code=error_code, reason=reason)


def _target_entity_groups(
    capability: ToolCapability, params: dict[str, Any]
) -> list[list[tuple[str, set[EntityType]]]]:
    """Entity-allowlist candidates grouped per target parameter value.

    Each host-ish parameter value yields alternative representations (raw and
    normalised host) so an allow-list entry may use either form. When the
    capability has no host-ish parameter, every scalar value forms one group.
    """
    groups: list[list[tuple[str, set[EntityType]]]] = []
    values: dict[str, Any] = params if isinstance(params, dict) else {}
    for name, spec in capability.parameters.items():
        if name not in values or values[name] is None:
            continue
        hostish = ((spec.format or "").strip().lower() in _HOST_FORMATS
                   or name.strip().lower() in _HOST_PARAM_NAMES)
        if not hostish:
            continue
        raw_values = values[name] if isinstance(values[name], (list, tuple)) else [values[name]]
        for raw_value in raw_values:
            text = str(raw_value).strip()
            if not text:
                continue
            alternatives: list[tuple[str, set[EntityType]]] = []
            raw_types = _param_entity_types(name, spec)
            try:
                raw_types.add(infer_value_type(text))
            except (ValueError, TypeError):
                pass
            alternatives.append((text, raw_types))
            host = _normalise_host(text)
            if host and host != text.lower():
                host_types: set[EntityType] = set()
                try:
                    host_types.add(infer_value_type(host))
                except (ValueError, TypeError):
                    pass
                alternatives.append((host, host_types))
            groups.append(alternatives)
    if groups:
        return groups
    fallback = _entity_values(capability, params)
    return [fallback] if fallback else []


def check_capability(
    capability: ToolCapability,
    params: dict[str, Any],
    scope: ScopeConfig,
    *,
    allow_authorized_tools: bool | None = None,
    allow_intrusive: bool | None = None,
) -> PolicyDecision:
    """Deterministic pre-spawn gate for one capability invocation.

    ``allow_authorized_tools`` / ``allow_intrusive`` override the corresponding
    ``ScopeConfig`` flags when not ``None``. Intrusive execution requires an
    explicit ``True`` — a ``False`` override always wins.
    """
    mode = capability.execution_mode

    # 1. Intrusive capabilities: explicit opt-in only, checked before anything else.
    intrusive_enabled = scope.allow_intrusive if allow_intrusive is None else bool(allow_intrusive)
    if mode == ExecutionMode.INTRUSIVE_BLOCKED and not intrusive_enabled:
        return _deny(
            ErrorCode.INTRUSIVE_BLOCKED,
            f"{capability.tool_id}: intrusive capabilities are blocked by policy",
        )

    # 2. Authorized tooling (offline cracking etc.): explicit opt-in.
    authorized = (scope.allow_authorized_tools if allow_authorized_tools is None
                  else bool(allow_authorized_tools))
    if capability.authorization_required and not authorized:
        return _deny(
            ErrorCode.AUTHORIZATION_REQUIRED,
            f"{capability.tool_id}: explicit authorization is required "
            f"(allow_authorized_tools is disabled)",
        )

    # 3. Active reconnaissance kill switch.
    if mode == ExecutionMode.ACTIVE_RECON and not scope.allow_active_recon:
        return _deny(
            ErrorCode.SCOPE_BLOCKED,
            f"{capability.tool_id}: active reconnaissance is disabled by scope",
        )

    targets = extract_targets(capability, params)
    entity_values = _entity_values(capability, params)

    # 4. Deny lists always win, in every execution mode.
    for host in [*targets, *_entity_hosts(entity_values)]:
        if _host_denied(host, scope):
            return _deny(
                ErrorCode.SCOPE_BLOCKED,
                f"{capability.tool_id}: target host {host!r} is deny-listed",
            )
    for value, types in entity_values:
        for entry in scope.deny_entities:
            if _entity_entry_matches(entry, value, types):
                return _deny(
                    ErrorCode.SCOPE_BLOCKED,
                    f"{capability.tool_id}: entity {value!r} is deny-listed",
                )

    # 5. Literal private / loopback / link-local / metadata IP targets.
    if scope.block_private_addresses:
        for host in targets:
            if _as_ip(host) is not None and not is_public_ip(host):
                return _deny(
                    ErrorCode.SCOPE_BLOCKED,
                    f"{capability.tool_id}: target {host!r} is a non-public IP address",
                )

    # 6. Active reconnaissance host allow-list.
    if mode == ExecutionMode.ACTIVE_RECON:
        if scope.allow_domains:
            if not targets:
                return _deny(
                    ErrorCode.SCOPE_BLOCKED,
                    f"{capability.tool_id}: active reconnaissance requires an in-scope host target",
                )
            for host in targets:
                if not _host_allowed(host, scope):
                    return _deny(
                        ErrorCode.SCOPE_BLOCKED,
                        f"{capability.tool_id}: target host {host!r} is outside "
                        f"allow_domains/allow_ips",
                    )
        elif scope.allow_ips:
            for host in targets:
                if _as_ip(host) is not None and not _host_allowed(host, scope):
                    return _deny(
                        ErrorCode.SCOPE_BLOCKED,
                        f"{capability.tool_id}: target IP {host!r} is outside allow_ips",
                    )

    # 7. Active reconnaissance entity allow-list. Every target parameter value
    # must match the allow-list (in raw or normalised host form).
    if mode == ExecutionMode.ACTIVE_RECON and scope.allow_entities:
        groups = _target_entity_groups(capability, params)
        if not groups:
            return _deny(
                ErrorCode.SCOPE_BLOCKED,
                f"{capability.tool_id}: active reconnaissance requires an in-scope entity target",
            )
        for alternatives in groups:
            matched = any(
                _entity_entry_matches(entry, value, types)
                for value, types in alternatives
                for entry in scope.allow_entities
            )
            if not matched:
                return _deny(
                    ErrorCode.SCOPE_BLOCKED,
                    f"{capability.tool_id}: entity target {alternatives[0][0]!r} is "
                    f"outside allow_entities",
                )

    return PolicyDecision(allowed=True, reason=f"{capability.tool_id}: allowed by scope policy")
