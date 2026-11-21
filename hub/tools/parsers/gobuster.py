"""Parse gobuster stdout into the v2 ParseOutput contract.

gobuster directory mode prints one line per discovered path::

    /admin                (Status: 301) [Size: 0]
    /login                (Status: 200) [Size: 1234]

Every discovered path becomes a canonical ``url`` entity with the HTTP status
code in its metadata/attributes.  No relations are invented for this tool.
Pure and deterministic: no network, no file access.
"""

from __future__ import annotations

import re

from hub.models import EntityType
from hub.tools.base import EntityCandidate, ParseOutput

__all__ = ["parse"]

_MATCH_RE = re.compile(r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d{3})\)")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def _build_url(path: str, base: str) -> str:
    if path.lower().startswith(("http://", "https://")):
        return path
    if not base:
        return path
    if not _SCHEME_RE.match(base):
        base = "http://" + base
    base = base.rstrip("/")
    return base + (path if path.startswith("/") else "/" + path)


def _confidence(status_code: int) -> float:
    if 200 <= status_code < 400:
        return 0.85
    if status_code in (401, 403):
        return 0.70
    return 0.45


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse gobuster stdout. Never raises; empty/garbage input yields warnings."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["gobuster: empty stdout"])

    base = (target or "").strip()
    entities: list[EntityCandidate] = []
    seen_urls: set[str] = set()

    for line in text.splitlines():
        match = _MATCH_RE.match(line.strip())
        if not match:
            continue
        path = match.group("path").strip()
        status_code = int(match.group("status"))
        url = _build_url(path, base)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        metadata = {"path": path, "status_code": status_code}
        if base:
            metadata["base_url"] = base
        entities.append(EntityCandidate(
            type=EntityType.URL,
            value=url,
            confidence=_confidence(status_code),
            metadata=metadata,
            evidence=line.strip(),
            attributes={"status_code": status_code},
        ))

    if not entities:
        return ParseOutput(warnings=["gobuster: no discovered paths recognised"])
    return ParseOutput(entities=entities)
