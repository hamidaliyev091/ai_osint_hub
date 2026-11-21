"""Secret redaction registry used before any raw output is persisted or logged.

Secrets are registered by :mod:`hub.credentials` as soon as they are loaded. Every
raw tool stdout/stderr/error message passes through :func:`redact` before it can
reach SQLite evidence artifacts, the execution ledger, CLI output or the web UI.
"""

from __future__ import annotations

import threading
from typing import Any

_SECRETS: dict[str, str] = {}
_LOCK = threading.RLock()
_MIN_SECRET_LEN = 4
_PLACEHOLDER = "[REDACTED:{provider}]"


def register_secret(value: Any, provider: str) -> None:
    """Register a raw secret value; redacted text uses the provider label."""
    if value is None:
        return
    text = str(value).strip()
    if len(text) < _MIN_SECRET_LEN:
        return
    provider_label = (provider or "CREDENTIAL").strip().upper() or "CREDENTIAL"
    with _LOCK:
        _SECRETS[text] = provider_label


def unregister_secret(value: Any) -> None:
    text = str(value or "").strip()
    with _LOCK:
        _SECRETS.pop(text, None)


def clear_secrets(provider: str | None = None) -> None:
    """Clear all registered secrets (or only one provider's entries)."""
    with _LOCK:
        if provider is None:
            _SECRETS.clear()
            return
        label = provider.strip().upper()
        for value, registered in list(_SECRETS.items()):
            if registered == label:
                _SECRETS.pop(value, None)


def registered_count() -> int:
    with _LOCK:
        return len(_SECRETS)


def redact(text: Any) -> str:
    """Replace every registered secret occurrence with ``[REDACTED:<PROVIDER>]``."""
    if text is None:
        return ""
    result = str(text)
    if not result:
        return result
    with _LOCK:
        # Longest first so a key that contains another key is fully replaced.
        ordered = sorted(_SECRETS.items(), key=lambda item: len(item[0]), reverse=True)
    for value, provider in ordered:
        if value and value in result:
            result = result.replace(value, _PLACEHOLDER.format(provider=provider))
    return result


def redact_obj(value: Any) -> Any:
    """Recursively redact strings inside dict/list structures."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_obj(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        redacted = [redact_obj(item) for item in value]
        return tuple(redacted) if isinstance(value, tuple) else redacted
    return value


def masked_preview(value: Any, *, visible: int = 4) -> str:
    """Masked preview such as ``github_pat_...89ab`` — never the full secret."""
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= visible * 2:
        return "…" + text[-2:]
    return f"{text[:visible]}…{text[-visible:]}"


__all__ = [
    "register_secret",
    "unregister_secret",
    "clear_secrets",
    "registered_count",
    "redact",
    "redact_obj",
    "masked_preview",
]
