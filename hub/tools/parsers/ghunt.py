"""Parse ghunt stdout into the v2 ParseOutput contract.

ghunt extracts Google account artefacts for an email address.  With ``--json``
it prints a single JSON document; plain-text output is handled as a fallback.

The checked email yields an ``email REGISTERED_ON service`` ("google") relation,
profile URLs become ``social_profile`` entities and discoverable handles become
``username`` entities.  Pure and deterministic: no network, no file access.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Optional

from hub.cooking import extract_emails, extract_urls, extract_usernames_from_urls
from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

_SOCIAL_HOSTS = (
    "youtube.com", "youtu.be", "google.com", "maps.google.com", "photos.google.com",
    "blogger.com", "twitter.com", "x.com", "instagram.com", "facebook.com",
    "github.com", "linkedin.com", "t.me", "reddit.com",
)
_IMAGE_SUFFIXES = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg")
_HANDLE_KEYS = ("username", "handle", "custom_url", "alias")
_PROFILE_KEYS = ("profile", "channel", "url", "link")


def _subject(target: str) -> tuple[EntityType, str]:
    """Resolve the relation subject type/value for the CLI target."""
    text = (target or "").strip()
    if not text:
        return EntityType.EMAIL, ""
    try:
        found = infer_value_type(text)
    except ValueError:
        return EntityType.EMAIL, text
    return (found if found is EntityType.EMAIL else EntityType.EMAIL), text


def _load_json(text: str) -> Optional[Any]:
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            return None
        stripped = text[start:end + 1]
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None


def _iter_strings(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_strings(child, path + (str(key),))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _iter_strings(child, path + (str(index),))
    elif isinstance(value, str):
        yield path, value


def _platform(url: str) -> str:
    host = url.split("://", 1)[-1].split("/")[0].split(":")[0].lower()
    for known in _SOCIAL_HOSTS:
        if host == known or host.endswith("." + known):
            if "youtube" in known:
                return "youtube"
            if "maps" in known:
                return "google_maps"
            if "photos" in known:
                return "google_photos"
            return known.split(".")[0]
    return ""


def _is_profile_url(path: tuple[str, ...], url: str, platform: str) -> bool:
    lowered = url.lower().split("?", 1)[0]
    if lowered.endswith(_IMAGE_SUFFIXES):
        return False
    keys = [part.lower() for part in path]
    if any("photo" in key or "avatar" in key or "image" in key for key in keys):
        return False
    if platform:
        return True
    return any(any(marker in key for marker in _PROFILE_KEYS) for key in keys)


def _first_snippet(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""


def _evidence_line(text: str, needle: str) -> str:
    lowered = needle.lower()
    for line in text.splitlines():
        if lowered in line.lower():
            return line.strip()
    return ""


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse ghunt stdout. Never raises; empty/garbage input yields warnings."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["ghunt: empty stdout"])

    subject_type, subject_value = _subject(target)
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str]] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   metadata: Optional[dict] = None, evidence: str = "",
                   attributes: Optional[dict] = None) -> bool:
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
            metadata=metadata or {},
            evidence=evidence,
            attributes=attributes or {},
        ))
        return True

    def add_relation(predicate: EdgeType, object_type: EntityType,
                     object_value: str, evidence: str,
                     confidence: float = 0.90) -> None:
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

    def add_handle(username: str, evidence: str, platform: str = "") -> None:
        username = str(username or "").strip().lstrip("@")
        if not username or " " in username or len(username) < 2:
            return
        add_entity(EntityType.USERNAME, username, 0.80,
                   {"platform": platform or "unknown"}, evidence or username,
                   {"registered": True})

    account_evidence = ""
    data = _load_json(text)
    if isinstance(data, dict):
        profile = data.get("profile") if isinstance(data.get("profile"), dict) else {}
        urls: list[tuple[tuple[str, ...], str]] = []
        for path, value in _iter_strings(data):
            lowered = value.strip().lower()
            key = path[-1].lower() if path else ""
            if lowered.startswith(("http://", "https://")):
                urls.append((path, value.strip()))
                platform = _platform(value)
                if _is_profile_url(path, value, platform):
                    add_entity(EntityType.SOCIAL_PROFILE, value.strip(), 0.85,
                               {"platform": platform or "unknown",
                                "json_path": ".".join(path)},
                               value.strip(), {"registered": True})
                for hint in extract_usernames_from_urls([value.strip()]):
                    add_handle(str(hint.get("username") or ""), value.strip(),
                               str(hint.get("platform") or platform))
                continue
            if key in _HANDLE_KEYS and value.strip():
                add_handle(value.strip(), f'"{key}": "{value.strip()}"')
            elif value.strip().startswith("@") and 2 <= len(value.strip()) <= 64:
                add_handle(value.strip(), f'"{key}": "{value.strip()}"')

        display_name = str(profile.get("displayName") or profile.get("display_name") or "").strip()
        if display_name:
            account_evidence = f'"displayName": "{display_name}"'
        elif urls:
            account_evidence = urls[0][1]
        account_found = bool(profile) or bool(data.get("google_services")) or bool(data.get("services"))
        if account_found and account_evidence:
            add_entity(EntityType.SERVICE, "google", 0.90,
                       {"email_target": subject_value}, account_evidence,
                       {"registered": True})
            add_relation(EdgeType.REGISTERED_ON, EntityType.SERVICE, "google",
                         account_evidence, 0.90)

        services_raw = data.get("google_services") or data.get("services") or []
        if isinstance(services_raw, list):
            for entry in services_raw:
                name = ""
                if isinstance(entry, str):
                    name = entry.strip().lower()
                elif isinstance(entry, dict):
                    name = str(entry.get("name") or entry.get("service") or "").strip().lower()
                if not name:
                    continue
                evidence = f'"google_services": "{name}"'
                if add_entity(EntityType.SERVICE, name, 0.80, {"platform": "google"},
                              evidence, {"registered": True}):
                    add_relation(EdgeType.REGISTERED_ON, EntityType.SERVICE, name,
                                 evidence, 0.80)

    # Raw text scan (works for JSON string values and plain-text ghunt output).
    for url in sorted(extract_urls(text)):
        platform = _platform(url)
        if platform:
            add_entity(EntityType.SOCIAL_PROFILE, url, 0.80,
                       {"platform": platform}, url, {"registered": True})
        for hint in extract_usernames_from_urls([url]):
            add_handle(str(hint.get("username") or ""), url,
                       str(hint.get("platform") or platform))

    for email in sorted(extract_emails(text)):
        value = email.lower()
        evidence = _evidence_line(text, value)
        add_entity(EntityType.EMAIL, value, 0.90, {"role": "subject"}, evidence)
        if not subject_value:
            subject_value = value
            subject_type = EntityType.EMAIL
            add_relation(EdgeType.REGISTERED_ON, EntityType.SERVICE, "google",
                         evidence or value, 0.70)

    if "google" in text.lower() and not any(
            entity.type is EntityType.SERVICE and entity.value == "google"
            for entity in entities):
        evidence = account_evidence or _evidence_line(text, "google") or _first_snippet(text)
        add_entity(EntityType.SERVICE, "google", 0.80,
                   {"email_target": subject_value}, evidence, {"registered": True})
        add_relation(EdgeType.REGISTERED_ON, EntityType.SERVICE, "google", evidence, 0.80)

    if not entities:
        return ParseOutput(warnings=["ghunt: no Google account artefacts recognised"])
    return ParseOutput(entities=entities, relations=relations)
