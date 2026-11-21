"""Python-native passive TLS certificate collector — SSRF-guarded."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from typing import Any

from hub.models import ErrorCode, ScopeConfig
from hub.security.policy import assert_safe_host
from hub.tools.builtin import BuiltinOutput

__all__ = ["collect"]

DEFAULT_TIMEOUT_SEC = 15


def _extract_host(target: str) -> str:
    """Reduce a URL or ``host[:port]`` target to a bare hostname."""
    text = str(target or "").strip()
    if not text:
        return ""
    if text.startswith("["):
        end = text.find("]")
        return text[1:end].lower() if end > 0 else ""
    if text.count(":") == 1:
        head, _, tail = text.rpartition(":")
        if tail.isdigit():
            text = head
    return text.strip().strip("[]").strip().lower().rstrip(".")


def _rdn_to_dict(rdn: Any) -> dict[str, str]:
    """Flatten getpeercert()'s nested RDN structure into a plain dict."""
    result: dict[str, str] = {}
    if not rdn:
        return result
    for entry in rdn:
        try:
            pairs = entry if isinstance(entry, (list, tuple)) else [entry]
        except TypeError:
            continue
        for pair in pairs:
            try:
                key, value = pair
            except (TypeError, ValueError):
                continue
            result[str(key)] = str(value)
    return result


def _peer_cert_payload(host: str, timeout_sec: int) -> dict[str, Any]:
    """Blocking TLS handshake + peer-certificate extraction."""
    context = ssl.create_default_context()
    # Validate the chain (rejects broken MITM) but not the hostname: OSINT
    # collection must work for hosts whose certificate name does not match.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection((host, 443), timeout=timeout_sec) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            certificate = tls_socket.getpeercert() or {}
            version = tls_socket.version() or ""
    return {
        "host": host,
        "version": str(version),
        "subject": _rdn_to_dict(certificate.get("subject")),
        "issuer": _rdn_to_dict(certificate.get("issuer")),
        "subjectAltName": [[str(kind), str(value)]
                           for kind, value in certificate.get("subjectAltName", [])],
        "notBefore": str(certificate.get("notBefore", "")),
        "notAfter": str(certificate.get("notAfter", "")),
    }


async def _collect_host(host: str, timeout_sec: int) -> BuiltinOutput:
    safe, reason = await asyncio.to_thread(assert_safe_host, host)
    if not safe:
        return BuiltinOutput(exit_code=-1, stderr=reason, error_code=ErrorCode.SCOPE_BLOCKED,
                             error_message=reason)
    try:
        payload = await asyncio.to_thread(_peer_cert_payload, host, timeout_sec)
    except (asyncio.TimeoutError, TimeoutError) as exc:
        message = f"TLS handshake timed out after {timeout_sec}s for {host}: {exc}"
        return BuiltinOutput(exit_code=-1, stderr=str(exc), error_code=ErrorCode.TIMEOUT,
                             error_message=message)
    except ssl.SSLError as exc:
        message = f"TLS handshake failed for {host}: {exc}"
        return BuiltinOutput(exit_code=1, stderr=str(exc), error_message=message)
    except socket.gaierror as exc:
        message = f"DNS resolution failed for {host}: {exc}"
        return BuiltinOutput(exit_code=1, stderr=str(exc), error_message=message)
    except OSError as exc:
        message = f"TLS connection failed for {host}: {exc}"
        return BuiltinOutput(exit_code=1, stderr=str(exc), error_message=message)
    except Exception as exc:  # noqa: BLE001 - a collector must never raise
        message = f"TLS certificate collection error for {host}: {type(exc).__name__}: {exc}"
        return BuiltinOutput(exit_code=1, stderr=str(exc), error_message=message)

    if not payload["subject"] and not payload["issuer"] and not payload["subjectAltName"]:
        message = f"no peer certificate returned by {host}"
        return BuiltinOutput(exit_code=1, stderr=message, error_message=message)
    return BuiltinOutput(stdout=json.dumps(payload, sort_keys=True), exit_code=0)


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Read the peer TLS certificate of ``https://<target>:443``."""
    _ = scope  # host allow/deny lists are enforced by the runtime policy gate
    target = str((params or {}).get("target") or "").strip()
    if not target:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: target",
            error_message="tls_cert requires a non-empty 'target'",
        )
    host = _extract_host(target)
    if not host:
        return BuiltinOutput(exit_code=2, stderr=f"invalid target host: {target!r}",
                             error_message=f"tls_cert received an invalid target: {target!r}")
    try:
        return await asyncio.wait_for(_collect_host(host, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"TLS certificate collection timed out after {timeout_sec}s for {host}"
        return BuiltinOutput(exit_code=-1, stderr=message, error_code=ErrorCode.TIMEOUT,
                             error_message=message)
