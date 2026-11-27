"""Parse sherlock stdout into the v2 ParseOutput contract.

sherlock prints one line per platform checked::

    [+] GitHub: https://github.com/alice
    [-] Twitter: Not Found

Claimed profiles become ``social_profile`` entities and the platform becomes a
``service`` entity; the searched username is related to each profile with
``username REGISTERED_ON social_profile``.  Pure and deterministic: no network.
"""

from __future__ import annotations

import re

from hub.cooking import extract_usernames_from_urls
from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

_MATCH_RE = re.compile(
    r"^\[(?P<marker>[+*!?-])\]\s*(?P<site>.+?):\s*(?P<url>https?://\S+)\s*$"
)
_USERNAME_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
#: Known Sherlock v0.16 soft-404 sites: they return HTTP 200 on arbitrary
#: typo strings and otherwise flood the ERKG with false profile claims.
_SOFT_404_SITES = (
    "7cups", "f3.cool", "houzz", "envato forum", "forums.envato.com",
    "aniworld", "hudsonrock", "cavalier.hudsonrock.com", "rusfootball",
    "rusfootball.info", "patched.sh", "patched", "omg.lol", "boardgamegeek",
    "giphy", "trello", "discord", "mastodon.cloud", "mastodon.xyz",
    "mstdn.io", "mstdn.social",
)
_GENERIC_PATH_SEGMENTS = frozenset({
    "members", "member", "user", "users", "profile", "profiles",
    "login", "signup", "signin", "register", "about", "search",
    "explore", "home", "account", "accounts", "settings", "help",
    "contact", "faq", "terms", "privacy", "policy", "feed", "share",
    "intent", "logout", "channel", "status", "watch", "api", "www",
    "u", "in", "c", "v", "p",
})


def _url_path_segments(url: str) -> list[str]:
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        return [
            seg.strip("@").split("?", 1)[0].split("#", 1)[0]
            for seg in (parts.path or "").split("/")
            if seg.strip()
        ]
    except ValueError:
        return []


def _is_root_only_url(url: str) -> bool:
    return not _url_path_segments(url)


def _handle_matches_target(segment: str, target: str) -> bool:
    if not target:
        return True
    clean_target = target.strip().lower().lstrip("@")
    if not clean_target:
        return True
    forms = {clean_target, re.sub(r"[^a-z0-9]", "", clean_target)}
    clean_seg = (segment or "").strip().lower().lstrip("@")
    if not clean_seg:
        return False
    return clean_seg in forms or re.sub(r"[^a-z0-9]", "", clean_seg) in forms


def _is_generic_or_mismatched_url(url: str, target: str = "") -> bool:
    segments = _url_path_segments(url)
    if not segments:
        return True
    final_seg = segments[-1].lower()
    if final_seg in _GENERIC_PATH_SEGMENTS:
        return True
    non_generic = [seg for seg in segments if seg.lower() not in _GENERIC_PATH_SEGMENTS]
    if not non_generic:
        return True
    if target and not _handle_matches_target(final_seg, target):
        return True
    return False


def _is_soft_404_site(site: str, url: str = "") -> bool:
    haystack = f"{site} {url}".lower()
    return any(marker in haystack for marker in _SOFT_404_SITES)


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


def _username_from_url(url: str, fallback: str) -> str:
    hints = extract_usernames_from_urls([url])
    if hints:
        return str(hints[0]["username"]).strip().lstrip("@")
    tail = url.split("://", 1)[-1]
    parts = [part for part in tail.split("/")[1:] if part]
    if parts:
        segment = parts[-1].split("?", 1)[0].split("#", 1)[0].strip().strip("/")
        if _USERNAME_SEGMENT_RE.match(segment):
            return segment
    return fallback


def _confidence(marker: str) -> float:
    if marker == "+":
        return 0.95
    if marker == "*":
        return 0.60
    return 0.30


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse sherlock stdout. Never raises; empty/garbage input yields warnings."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["sherlock: empty stdout"])

    subject_type, subject_value = _subject(target)
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_sites: set[str] = set()
    seen_profiles: set[str] = set()

    for line in text.splitlines():
        stripped = line.strip()
        match = _MATCH_RE.match(stripped)
        if not match:
            continue
        marker = match.group("marker")
        site = match.group("site").strip()
        url = match.group("url").strip()
        site_key = re.sub(r"\s+", " ", site).strip().lower()
        if not site_key or site_key in seen_sites:
            continue
        if _is_soft_404_site(site_key, url) or _is_generic_or_mismatched_url(url, subject_value):
            continue
        seen_sites.add(site_key)
        registered = marker in ("+", "*")
        confidence = _confidence(marker)
        entities.append(EntityCandidate(
            type=EntityType.SERVICE,
            value=site_key,
            confidence=confidence,
            metadata={"registered": registered, "url": url, "match_type": marker},
            evidence=stripped,
            attributes={"registered": registered},
        ))
        if not registered:
            continue

        username = subject_value or _username_from_url(url, "")
        if url not in seen_profiles:
            seen_profiles.add(url)
            entities.append(EntityCandidate(
                type=EntityType.SOCIAL_PROFILE,
                value=url,
                confidence=confidence,
                metadata={"site": site_key, "username": username, "match_type": marker},
                evidence=stripped,
                attributes={"registered": True},
            ))
        if username:
            relations.append(RelationCandidate(
                subject_type=subject_type,
                subject_value=username,
                predicate=EdgeType.REGISTERED_ON,
                object_type=EntityType.SOCIAL_PROFILE,
                object_value=url,
                confidence=confidence,
                evidence=stripped,
                metadata={"site": site_key},
            ))

    if not entities:
        return ParseOutput(warnings=["sherlock: no claimed profiles recognised"])
    return ParseOutput(entities=entities, relations=relations)
