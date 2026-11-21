"""Python-native passive DNS resolver (A/AAAA) — no third-party API."""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any, Iterable

from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput

__all__ = ["collect"]

DEFAULT_TIMEOUT_SEC = 15


def _resolve_blocking(target: str) -> list[tuple[str, str]]:
    """Resolve A/AAAA records for ``target``; returns sorted (ip, family) pairs."""
    infos: Iterable[Any] = socket.getaddrinfo(
        target, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
    )
    addresses: list[tuple[str, str]] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4] if len(info) > 4 else None
        if not sockaddr:
            continue
        ip = str(sockaddr[0]).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        family = getattr(info[0], "name", str(info[0]))
        addresses.append((ip, family))
    # IPv4 first, then IPv6, deterministic within each family.
    addresses.sort(key=lambda item: (0 if item[1] == "AF_INET" else 1, item[0]))
    return addresses


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Resolve ``params['target']`` with the host resolver, bounded by timeout."""
    _ = scope  # passive resolution performs no outbound connection to the target
    target = str((params or {}).get("target") or "").strip()
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="dns_lookup requires a non-empty 'target'",
        )
    try:
        addresses = await asyncio.wait_for(
            asyncio.to_thread(_resolve_blocking, target), timeout=timeout_sec
        )
    except (asyncio.TimeoutError, TimeoutError):
        message = f"DNS resolution timed out after {timeout_sec}s for {target}"
        return BuiltinOutput(exit_code=-1, stderr=message, error_code=ErrorCode.TIMEOUT,
                             error_message=message)
    except socket.gaierror as exc:
        message = f"DNS resolution failed for {target}: {exc}"
        return BuiltinOutput(exit_code=1, stderr=message, error_message=message)
    except Exception as exc:  # noqa: BLE001 - a collector must never raise
        message = f"DNS resolution error for {target}: {type(exc).__name__}: {exc}"
        return BuiltinOutput(exit_code=1, stderr=message, error_message=message)

    payload = {
        "target": target,
        "addresses": [{"ip": ip, "family": family} for ip, family in addresses],
    }
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)
