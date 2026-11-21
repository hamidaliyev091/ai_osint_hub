"""Parse maigret stdout into the v2 ParseOutput contract.

maigret searches a username across 2500+ social platforms.  It is normally run
with ``--json`` (a mapping of site -> site payload); plain-text output such as
``[+] GitHub: https://github.com/alice`` is handled as a fallback.

Claimed sites become ``service`` + ``social_profile`` entities and yield a
``username REGISTERED_ON social_profile`` relation.  Pure and deterministic.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Optional

from hub.cooking import extract_usernames_from_urls
from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

_SITE_MARKERS = ("status", "url_main", "url_user", "url", "is_claimed", "exists")
_URL_LOCATOR_KEYS = ("url_user", "url", "url_main", "profile_url")
_USERNAME_KEYS = ("username", "user", "login", "nick")
_TEXT_MATCH_RE = re.compile(r"^\[([+*!?-])\]\s+(.+?):\s*(https?://\S+)\s*$")
_TEXT_STATUS_RE = re.compile(r"^([A-Za-z0-9][\w.-]*)\s*:\s*(.+)$")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")
_CLAIMED_WORDS = ("claimed", "found", "exists", "registered")
_DEAD_WORDS = ("not found", "not claimed", "unknown", "error", "false", "missing", "not exists")
#: Generic URL path segments that are never usernames.
_GENERIC_PATH_SEGMENTS = {
    "about", "login", "signup", "signin", "explore", "home", "search",
    "channel", "user", "users", "profile", "profiles", "status", "settings",
    "watch", "help", "u", "in", "c", "v", "p", "www", "api", "terms",
    "privacy", "policy", "contact", "faq", "logout", "register", "feed",
    "share", "intent",
}


def _target_forms(target: str) -> set[str]:
    """Full-handle forms only: no dotted prefix/suffix splitting."""
    text = (target or "").strip().lower().lstrip("@")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0].strip(".")
    if not text:
        return set()
    # Punctuation-equivalent full handles only: 108.elv1n == 108_elv1n ==
    # 108-elv1n == 108elv1n. Partial tokens such as "108" or "elv1n" are NOT
    # valid target forms for a dotted handle.
    return {text, re.sub(r"[^a-z0-9]", "", text)}


def _url_path_segments(url: str) -> list[str]:
    text = (url or "").strip().lower()
    if "://" not in text:
        return []
    path = text.split("://", 1)[1]
    path = path.split("/", 1)[1] if "/" in path else ""
    return [segment.strip("@").split("?", 1)[0].split("#", 1)[0]
            for segment in path.split("/") if segment.strip()]


def _handle_matches_target(value: str, target: str) -> bool:
    if not target:
        return True
    lowered = (value or "").strip().lower().lstrip("@")
    if not lowered:
        return False
    forms = _target_forms(target)
    return (lowered in forms
            or re.sub(r"[^a-z0-9]", "", lowered) in forms)


def _profile_matches_target(url: str, username: str, target: str) -> bool:
    """Only emit a profile when its full URL/handle belongs to the target."""
    has_url = bool(str(url or "").strip())
    segments = _url_path_segments(url)
    if has_url and not segments:
        # Root-only URL (https://discord.com or https://discord.com/) is never
        # a social profile.
        return False
    if segments:
        non_generic = [segment for segment in segments
                       if segment.strip("@").lower() not in _GENERIC_PATH_SEGMENTS]
        if not non_generic:
            return False
        if not target:
            return True
        # The URL path is authoritative; a payload's sidebar/owner username is
        # ignored unless the URL itself belongs to the queried target.
        return any(_handle_matches_target(segment, target)
                   for segment in non_generic)
    if not target:
        return bool((username or "").strip())
    return _handle_matches_target(username, target)


def _subject(target: str) -> tuple[EntityType, str]:
    """Resolve the relation subject type/value for the CLI target."""
    text = (target or "").strip()
    if not text:
        return EntityType.USERNAME, ""
    try:
        found = infer_value_type(text)
    except ValueError:
        return EntityType.USERNAME, text
    if found is EntityType.USERNAME:
        return found, text
    return EntityType.USERNAME, text


def _load_json(text: str) -> Optional[Any]:
    """Parse full JSON, or the first embedded JSON object; None when absent."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start:end + 1])
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def _looks_like_site(payload: Any) -> bool:
    return isinstance(payload, dict) and any(key in payload for key in _SITE_MARKERS)


def _iter_sites(data: Any) -> Iterable[tuple[str, dict]]:
    """Yield (site_name, payload) from the supported maigret JSON shapes."""
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                site = str(item.get("sitename") or item.get("site") or item.get("name") or "").strip()
                if site:
                    yield site, item
        return
    if not isinstance(data, dict):
        return
    for container_key in ("sites", "results", "found", "social"):
        nested = data.get(container_key)
        if isinstance(nested, dict):
            for site, payload in nested.items():
                if isinstance(payload, dict):
                    yield str(site), payload
            return
    # Single-username wrapper: {"alice": {"GitHub": {...}, "Twitter": {...}}}
    for value in data.values():
        if _looks_like_site(value) or not isinstance(value, dict) or not value:
            continue
        wrapped = [item for item in value.values() if _looks_like_site(item)]
        if wrapped and len(wrapped) == len(value):
            for site, payload in value.items():
                if isinstance(payload, dict):
                    yield str(site), payload
            return
    for site, payload in data.items():
        if _looks_like_site(payload):
            yield str(site), payload


def _claim_text(site_data: dict) -> str:
    status = site_data.get("status")
    if isinstance(status, dict):
        for key in ("is_claimed", "exists", "found"):
            if isinstance(status.get(key), bool):
                return "claimed" if status[key] else "not found"
        return str(status.get("status") or status.get("result") or "")
    if isinstance(status, str):
        return status
    for key in ("is_claimed", "exists", "found"):
        if isinstance(site_data.get(key), bool):
            return "claimed" if site_data[key] else "not found"
    return str(site_data.get("status") or site_data.get("result") or "")


def _claimed(site_data: dict) -> bool:
    lowered = _claim_text(site_data).strip().lower()
    if not lowered:
        return False
    if any(word in lowered for word in _DEAD_WORDS):
        return False
    return any(word in lowered for word in _CLAIMED_WORDS)


def _profile_url(site_data: dict) -> str:
    status = site_data.get("status")
    sources = [site_data]
    if isinstance(status, dict):
        sources.append(status)
    for source in sources:
        for key in _URL_LOCATOR_KEYS:
            value = source.get(key)
            if isinstance(value, str) and value.strip().lower().startswith(("http://", "https://")):
                return value.strip()
    return ""


def _site_username(site_data: dict, fallback: str) -> str:
    status = site_data.get("status")
    sources = [site_data]
    if isinstance(status, dict):
        sources.append(status)
    for source in sources:
        for key in _USERNAME_KEYS:
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lstrip("@")
    return fallback


def _json_evidence(site: str, site_data: dict, profile_url: str) -> str:
    if profile_url:
        return profile_url
    try:
        payload = json.dumps({site: site_data}, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        payload = site
    return payload[:300]


def _parse_text(text: str, subject_type: EntityType, subject_value: str) -> ParseOutput:
    """Fallback for plain-text maigret output."""
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_sites: set[str] = set()

    def add_claimed(site: str, profile_url: str, evidence: str) -> None:
        site_key = site.strip().lower()
        if not site_key or site_key in seen_sites or not profile_url:
            return
        username = subject_value
        if not username:
            hints = extract_usernames_from_urls([profile_url])
            username = str(hints[0]["username"]) if hints else ""
        # Phase 15: ignore generic paths (youtube/about) and collateral handles
        # from recursive/page-scraping output unless they match the target.
        if not _profile_matches_target(profile_url, username, subject_value):
            return
        seen_sites.add(site_key)
        entities.append(EntityCandidate(
            type=EntityType.SERVICE,
            value=site_key,
            confidence=0.85,
            metadata={"registered": True, "url": profile_url},
            evidence=evidence,
            attributes={"registered": True},
        ))
        entities.append(EntityCandidate(
            type=EntityType.SOCIAL_PROFILE,
            value=profile_url,
            confidence=0.85,
            metadata={"site": site_key, "username": username},
            evidence=evidence,
            attributes={"registered": True},
        ))
        if username:
            relations.append(RelationCandidate(
                subject_type=subject_type,
                subject_value=username,
                predicate=EdgeType.REGISTERED_ON,
                object_type=EntityType.SOCIAL_PROFILE,
                object_value=profile_url,
                confidence=0.85,
                evidence=evidence,
                metadata={"site": site_key},
            ))

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _TEXT_MATCH_RE.match(stripped)
        if match:
            marker, site, url = match.group(1), match.group(2).strip(), match.group(3).strip()
            if marker in ("+", "*"):
                add_claimed(site, url, stripped)
            continue
        status_match = _TEXT_STATUS_RE.match(stripped)
        if not status_match:
            continue
        site, status = status_match.group(1).strip(), status_match.group(2).strip().lower()
        urls = _URL_RE.findall(status_match.group(2))
        if urls:
            add_claimed(site, urls[0], stripped)
            continue
        if not any(word in status for word in _CLAIMED_WORDS):
            continue
        site_key = site.lower()
        if site_key in seen_sites:
            continue
        seen_sites.add(site_key)
        entities.append(EntityCandidate(
            type=EntityType.SERVICE,
            value=site_key,
            confidence=0.75,
            metadata={"registered": True},
            evidence=stripped,
            attributes={"registered": True},
        ))

    if not entities:
        return ParseOutput(warnings=["maigret: no claimed profiles recognised"])
    return ParseOutput(entities=entities, relations=relations)


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse maigret stdout. Never raises; empty/garbage input yields warnings."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["maigret: empty stdout"])

    subject_type, subject_value = _subject(target)
    data = _load_json(text)
    if data is None:
        return _parse_text(text, subject_type, subject_value)

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_sites: set[str] = set()

    for site, site_data in _iter_sites(data):
        if not site or not _claimed(site_data):
            continue
        site_key = site.strip().lower()
        if site_key in seen_sites:
            continue
        profile_url = _profile_url(site_data)
        username = _site_username(site_data, "")
        # Never emit generic pages (youtube/about) or collateral handles from
        # recursive/page-scraping output unless the URL/handle matches the target.
        if not _profile_matches_target(profile_url, username or subject_value,
                                       subject_value):
            continue
        seen_sites.add(site_key)
        evidence = _json_evidence(site, site_data, profile_url)
        relation_username = subject_value or username

        entities.append(EntityCandidate(
            type=EntityType.SERVICE,
            value=site_key,
            confidence=0.90,
            metadata={"registered": True, "url": profile_url,
                      "username_found": relation_username},
            evidence=evidence,
            attributes={"registered": True},
        ))
        if not profile_url:
            continue
        entities.append(EntityCandidate(
            type=EntityType.SOCIAL_PROFILE,
            value=profile_url,
            confidence=0.90,
            metadata={"site": site_key, "username": relation_username},
            evidence=evidence,
            attributes={"registered": True},
        ))
        if relation_username:
            relations.append(RelationCandidate(
                subject_type=subject_type,
                subject_value=relation_username,
                predicate=EdgeType.REGISTERED_ON,
                object_type=EntityType.SOCIAL_PROFILE,
                object_value=profile_url,
                confidence=0.90,
                evidence=evidence,
                metadata={"site": site_key},
            ))

    if not entities:
        return ParseOutput(warnings=["maigret: no claimed profiles found in JSON output"])
    return ParseOutput(entities=entities, relations=relations)
