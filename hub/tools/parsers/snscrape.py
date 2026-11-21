"""Parse snscrape stdout into the v2 ParseOutput contract.

snscrape emits one JSON object per post (JSONL)::

    {"url": "https://twitter.com/alice/status/1",
     "user": {"username": "alice", "displayname": "Alice"}, "source": "twitter"}

Post URLs become ``url`` entities, user objects become ``username`` entities
and the username is related to the post URL (or a profile URL when present)
with ``ASSOCIATED_WITH``.  Plain-text URL lines are handled as a fallback.
Pure and deterministic: no network, no file access.
"""

from __future__ import annotations

import json
import re

from hub.cooking import extract_urls
from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

_PLATFORM_MAP = {
    "twitter.com": "twitter",
    "x.com": "x",
    "instagram.com": "instagram",
    "reddit.com": "reddit",
    "tiktok.com": "tiktok",
    "youtube.com": "youtube",
    "facebook.com": "facebook",
    "telegram.org": "telegram",
    "t.me": "telegram",
    "github.com": "github",
}


def _subject(target: str) -> tuple[EntityType, str]:
    """Resolve the relation subject type/value for the CLI target."""
    text = (target or "").strip()
    if not text:
        return EntityType.USERNAME, ""
    try:
        found = infer_value_type(text)
    except ValueError:
        return EntityType.USERNAME, text
    return (found if found is EntityType.USERNAME else EntityType.USERNAME), text


def _platform_from_url(url: str) -> str:
    host = url.split("://", 1)[-1].split("/")[0].split(":")[0].lower()
    for domain, platform in _PLATFORM_MAP.items():
        if host == domain or host.endswith("." + domain):
            return platform
    labels = host.split(".")
    return labels[-2] if len(labels) >= 2 else host


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse snscrape JSONL stdout. Never raises; empty/garbage input warns."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["snscrape: empty stdout"])

    subject_type, subject_value = _subject(target)
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str]] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   metadata: dict, evidence: str,
                   attributes: dict | None = None) -> bool:
        value = str(value or "").strip()
        if not value:
            return False
        key = (entity_type.value, value.lower())
        if key in seen_entities:
            return False
        seen_entities.add(key)
        entities.append(EntityCandidate(
            type=entity_type,
            value=value,
            confidence=confidence,
            metadata=metadata,
            evidence=evidence,
            attributes=attributes or {},
        ))
        return True

    def add_relation(predicate: EdgeType, object_type: EntityType,
                     object_value: str, evidence: str, confidence: float) -> None:
        if not subject_value or not object_value:
            return
        key = (predicate.value, subject_value.lower(), object_value.lower())
        if key in seen_relations:
            return
        seen_relations.add(key)
        relations.append(RelationCandidate(
            subject_type=subject_type,
            subject_value=subject_value,
            predicate=predicate,
            object_type=object_type,
            object_value=object_value,
            confidence=confidence,
            evidence=evidence,
        ))

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        record = None
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                record = parsed
        except (json.JSONDecodeError, ValueError):
            record = None

        if record is None:
            for url in sorted(extract_urls(stripped)):
                if add_entity(EntityType.URL, url, 0.70,
                              {"platform": _platform_from_url(url)}, stripped):
                    add_relation(EdgeType.ASSOCIATED_WITH, EntityType.URL, url,
                                 stripped, 0.60)
            continue

        url = str(record.get("url") or record.get("link") or "").strip()
        user = record.get("user") if isinstance(record.get("user"), dict) else {}
        username = str(
            user.get("username") or user.get("screenName") or record.get("username") or ""
        ).strip().lstrip("@")
        display_name = str(user.get("displayname") or user.get("display_name") or "").strip()
        platform = str(record.get("source") or "").strip() or _platform_from_url(url)
        profile_url = str(user.get("profile_url") or user.get("url") or "").strip()

        if url:
            metadata = {
                "platform": platform,
                "date": str(record.get("date") or ""),
                "content": str(record.get("content") or "")[:200],
            }
            add_entity(EntityType.URL, url, 0.85, metadata, stripped)
        if username and not subject_value:
            subject_value = username

        subject_username = username or subject_value
        if subject_username:
            add_entity(EntityType.USERNAME, subject_username, 0.80,
                       {"displayname": display_name, "platform": platform}, stripped,
                       {"mentioned": True})
        if profile_url:
            add_entity(EntityType.SOCIAL_PROFILE, profile_url, 0.80,
                       {"platform": platform, "username": subject_username}, stripped,
                       {"registered": True})
            add_relation(EdgeType.ASSOCIATED_WITH, EntityType.SOCIAL_PROFILE,
                         profile_url, stripped, 0.80)
        elif url and subject_username:
            add_relation(EdgeType.ASSOCIATED_WITH, EntityType.URL, url, stripped, 0.75)

    if not entities:
        return ParseOutput(warnings=["snscrape: no posts or URLs recognised"])
    return ParseOutput(entities=entities, relations=relations)
