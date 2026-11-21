"""Short-lived provider rate-limit cooldown cache (Phase 14).

When an API-backed tool hit an HTTP 429 / provider restriction in any
investigation, it is put in a cross-run cooldown for 24 hours. The pivot
planner skips cooling tools immediately, so a new investigation never spends a
tool call on a known-restricted provider again.

The cache is persisted at ``$AI_OSINT_HUB_HOME/rate_limit_cache.json`` (outside
the repository when using the default home). It is cleared by
:func:`reset_cache` and whenever credentials are updated through the Web UI or
``python -m hub.cli auth set``.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

__all__ = [
    "RATE_LIMIT_COOLDOWN_SEC",
    "COOLDOWN_TOOLS",
    "cache_path",
    "mark_rate_limited",
    "is_cooling",
    "cooled_tool_ids",
    "active_cooldowns",
    "reset_cache",
    "clear_tools",
]

RATE_LIMIT_COOLDOWN_SEC = 24 * 60 * 60  # 24h: restricted API accounts stay cooled
#: Provider-backed API tools; CLI scrapers are handled by the per-run breaker.
COOLDOWN_TOOLS = frozenset({
    "hunter_lookup", "censys_lookup", "shodan_lookup", "virustotal_lookup",
})
_LOCK = threading.RLock()
_MEMORY: dict[str, float] | None = None


def cache_path() -> Path:
    home = os.environ.get("AI_OSINT_HUB_HOME")
    base = Path(home).expanduser() if home else Path.home() / ".ai_osint_hub"
    return (base / "rate_limit_cache.json").resolve()


def _load() -> dict[str, float]:
    global _MEMORY
    with _LOCK:
        if _MEMORY is not None:
            return _MEMORY
        values: dict[str, float] = {}
        path = cache_path()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        tools = raw.get("tools") if isinstance(raw, dict) else None
        if isinstance(tools, dict):
            now = time.time()
            for tool_id, timestamp in tools.items():
                try:
                    expires = float(timestamp)
                except (TypeError, ValueError):
                    continue
                if expires > now:
                    values[str(tool_id).lower()] = expires
        _MEMORY = values
        return values


def _save(values: dict[str, float]) -> None:
    path = cache_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {tool_id: expires for tool_id, expires in values.items()
                      if expires > time.time()},
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass


def mark_rate_limited(tool_id: str, *, seconds: int = RATE_LIMIT_COOLDOWN_SEC) -> None:
    """Record a provider rate-limit cooldown for ``tool_id``."""
    key = str(tool_id or "").strip().lower()
    if not key:
        return
    with _LOCK:
        values = dict(_load())
        expires = time.time() + max(1, int(seconds))
        values[key] = expires
        global _MEMORY
        _MEMORY = values
        _save(values)


def is_cooling(tool_id: str, *, now: Optional[float] = None) -> bool:
    key = str(tool_id or "").strip().lower()
    if not key:
        return False
    current = time.time() if now is None else float(now)
    with _LOCK:
        values = _load()
        expires = values.get(key)
        if expires is None:
            return False
        if expires <= current:
            values.pop(key, None)
            _save(values)
            return False
        return True


def cooled_tool_ids(*, now: Optional[float] = None) -> set[str]:
    current = time.time() if now is None else float(now)
    with _LOCK:
        values = _load()
        expired = [tool_id for tool_id, expires in values.items()
                   if expires <= current]
        if expired:
            for tool_id in expired:
                values.pop(tool_id, None)
            _save(values)
        return {tool_id for tool_id, expires in values.items()
                if expires > current}


def active_cooldowns() -> dict[str, float]:
    """Return tool → remaining seconds for active cooldowns."""
    now = time.time()
    with _LOCK:
        values = _load()
        return {tool_id: round(max(0.0, expires - now), 1)
                for tool_id, expires in values.items() if expires > now}


def clear_tools(tool_ids: Iterable[str]) -> None:
    keys = {str(tool_id or "").strip().lower() for tool_id in tool_ids}
    with _LOCK:
        values = dict(_load())
        changed = False
        for key in keys:
            if key in values:
                values.pop(key, None)
                changed = True
        global _MEMORY
        _MEMORY = values
        if changed:
            _save(values)


def reset_cache() -> None:
    """Clear all in-memory and on-disk rate-limit cooldowns."""
    global _MEMORY
    with _LOCK:
        _MEMORY = {}
        try:
            cache_path().unlink(missing_ok=True)
        except OSError:
            pass
