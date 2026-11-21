"""Parse hashcat stdout into the v2 ParseOutput contract.

Handles hashcat ``--show`` / potfile output where every line is a cracked
credential pair::

    5f4dcc3b5aa765d61d8327deb882cf99:password
    $2a$10$N9qo8uLI...:hunter2

Each pair yields a ``hash`` entity and a ``credential`` entity joined by
``credential ASSOCIATED_WITH hash``.  Informational hashcat status lines are
ignored.  Pure and deterministic: no network, no file access.
"""

from __future__ import annotations

import re

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_CRYPT_RE = re.compile(r"^\$[A-Za-z0-9]+\$")
_INFO_PREFIXES = (
    "session", "status", "hash.", "time.", "recovered", "progress", "speed",
    "started", "stopped", "candidates", "approaching", "dictionary", "watchdog",
    "hardware", "opencl", "cuda", "backend", "host", "device", "guess.",
    "minimum", "maximum", "kernel", "load", "sorting", "input", "output",
    "hashfile", "potfile", "rules", "optimizers", "loopback", "separator",
)


def _is_hash_token(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if _CRYPT_RE.match(text) and len(text) >= 20:
        return True
    return bool(_HEX_RE.match(text)) and len(text) >= 8


def _hash_kind(value: str) -> str:
    text = value.strip()
    if _CRYPT_RE.match(text):
        return "crypt"
    if len(text) in (32, 40, 64, 96, 128):
        return f"hex{len(text) * 4}"
    return "hex"


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse hashcat potfile/stdout. Never raises; empty/garbage input warns."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["hashcat: empty stdout"])

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_hashes: set[str] = set()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        if stripped.lower().startswith(_INFO_PREFIXES):
            continue
        hash_value, sep, password = stripped.partition(":")
        hash_value = hash_value.strip()
        password = password.strip()
        if not sep or not _is_hash_token(hash_value) or not password:
            continue
        if hash_value in seen_hashes:
            continue
        seen_hashes.add(hash_value)

        hash_kind = _hash_kind(hash_value)
        credential_value = password
        entities.append(EntityCandidate(
            type=EntityType.HASH,
            value=hash_value,
            confidence=0.95,
            metadata={"hash_type": hash_kind, "length": len(hash_value),
                      "hash_prefix": hash_value[:16]},
            evidence=stripped,
            attributes={"hash_type": hash_kind, "length": len(hash_value)},
        ))
        credential = EntityCandidate(
            type=EntityType.CREDENTIAL,
            value=credential_value,
            confidence=0.95,
            metadata={"cracked": True, "hash_type": hash_kind,
                      "hash_prefix": hash_value[:16]},
            evidence=stripped,
            attributes={"cracked": True, "hashed": True},
        )
        entities.append(credential)
        relations.append(RelationCandidate(
            subject_type=EntityType.CREDENTIAL,
            subject_value=credential_value,
            predicate=EdgeType.ASSOCIATED_WITH,
            object_type=EntityType.HASH,
            object_value=hash_value,
            confidence=0.95,
            evidence=stripped,
            metadata={"hash_type": hash_kind},
        ))

    if not entities:
        return ParseOutput(warnings=["hashcat: no hash:password pairs recognised"])
    return ParseOutput(entities=entities, relations=relations)
