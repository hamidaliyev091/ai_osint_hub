"""Deterministic parser for the builtin Gravatar profile collector.

Input (collector stdout)::

    {"email": "matt@mullenweg.com", "md5": "...", "sha256": "...", "exists": true,
     "profile": {"displayName": "Matt Mullenweg", "preferredUsername": "matt230816",
                 "aboutMe": "...", "profileUrl": "https://gravatar.com/matt230816",
                 "thumbnailUrl": "...",
                 "accounts": [{"shortname": "twitter", "username": "photomatt",
                               "url": "...", "verified": true}]}}

Output: EMAIL entity, PERSON entity (display name), USERNAME and SOCIAL_PROFILE
entities, ``email REGISTERED_ON service "gravatar"`` and linked-account URLs.
A non-existent profile yields only the queried e-mail entity plus a warning.
"""

from __future__ import annotations

import json

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ACCOUNTS = 50


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse Gravatar collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"gravatar_lookup parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from gravatar_lookup: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected gravatar_lookup payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    email = _as_text(data.get("email") or target).lower()
    md5 = _as_text(data.get("md5"))
    sha256 = _as_text(data.get("sha256"))
    exists = bool(data.get("exists"))
    profile = data.get("profile") if isinstance(data.get("profile"), dict) else {}
    display_name = _as_text(profile.get("displayName"))
    username = _as_text(profile.get("preferredUsername"))
    about_me = _as_text(profile.get("aboutMe"))
    profile_url = _as_text(profile.get("profileUrl"))
    thumbnail_url = _as_text(profile.get("thumbnailUrl"))
    accounts = profile.get("accounts") if isinstance(profile.get("accounts"), list) else []

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   evidence: str, *, metadata: dict | None = None,
                   attributes: dict | None = None) -> bool:
        value = _as_text(value)
        if not value:
            return False
        key = (entity_type.value, value.lower())
        if key in seen:
            return False
        seen.add(key)
        entities.append(EntityCandidate(
            type=entity_type, value=value, confidence=confidence,
            metadata=dict(metadata or {}), attributes=dict(attributes or {}),
            evidence=evidence[:MAX_EVIDENCE],
        ))
        return True

    def add_relation(subject_type: EntityType, subject_value: str,
                     predicate: EdgeType, object_type: EntityType,
                     object_value: str, confidence: float, evidence: str) -> None:
        if not _as_text(subject_value) or not _as_text(object_value):
            return
        relations.append(RelationCandidate(
            subject_type=subject_type, subject_value=subject_value,
            predicate=predicate, object_type=object_type,
            object_value=object_value, confidence=confidence,
            evidence=evidence[:MAX_EVIDENCE],
        ))

    email_evidence = f"Gravatar lookup for {email}" + (
        f" (md5={md5})" if md5 else "") + (f" (sha256={sha256})" if sha256 else "")
    if email:
        add_entity(EntityType.EMAIL, email, 0.90, email_evidence,
                   metadata={"md5": md5, "sha256": sha256},
                   attributes={"md5": md5, "sha256": sha256})
    add_entity(EntityType.SERVICE, "gravatar", 0.80,
               f"Gravatar public profile service queried for {email or 'target'}",
               metadata={"kind": "profile_service"})

    social_profile_added = False
    if exists:
        if email:
            add_relation(EntityType.EMAIL, email, EdgeType.REGISTERED_ON,
                         EntityType.SERVICE, "gravatar", 0.80,
                         f"Gravatar profile exists for {email}")
        person_name = display_name or username
        if person_name:
            person_evidence = (
                f"Gravatar displayName={display_name or '?'}"
                f"; preferredUsername={username or '?'}"
                + (f"; aboutMe={about_me}" if about_me else "")
            )
            add_entity(EntityType.PERSON, person_name, 0.75, person_evidence,
                       metadata={"source": "gravatar"},
                       attributes={"about_me": about_me, "gravatar_url": profile_url})
            if email:
                add_relation(EntityType.PERSON, person_name, EdgeType.HAS_EMAIL,
                             EntityType.EMAIL, email, 0.70,
                             f"Gravatar profile {person_name} is linked to {email}")
        if username:
            add_entity(EntityType.USERNAME, username, 0.80,
                       f"Gravatar preferredUsername: {username}",
                       metadata={"source": "gravatar"})
        if profile_url:
            social_profile_added = add_entity(
                EntityType.SOCIAL_PROFILE, profile_url, 0.85,
                f"Gravatar profile URL for {email or 'target'}: {profile_url}")
            if social_profile_added and username:
                add_relation(EntityType.SOCIAL_PROFILE, profile_url,
                             EdgeType.HAS_USERNAME, EntityType.USERNAME, username,
                             0.75, f"Gravatar profile {profile_url} uses username {username}")
        if thumbnail_url:
            add_entity(EntityType.URL, thumbnail_url, 0.60,
                       f"Gravatar avatar thumbnail for {email or 'target'}: {thumbnail_url}",
                       metadata={"content_kind": "avatar"})
        for account in accounts[:MAX_ACCOUNTS]:
            if not isinstance(account, dict):
                continue
            account_url = _as_text(account.get("url"))
            account_username = _as_text(account.get("username"))
            shortname = _as_text(account.get("shortname"))
            verified = bool(account.get("verified"))
            account_evidence = (
                f"Gravatar linked account shortname={shortname or '?'}"
                f"; username={account_username or '?'}"
                f"; verified={verified}"
                + (f"; url={account_url}" if account_url else "")
            )
            if account_url:
                add_entity(EntityType.URL, account_url, 0.65, account_evidence,
                           metadata={"verified": verified,
                                     "service": shortname})
            if account_username:
                add_entity(EntityType.USERNAME, account_username, 0.65,
                           account_evidence, metadata={"service": shortname})
            if shortname and shortname.lower() != "gravatar":
                add_entity(EntityType.SERVICE, shortname, 0.60, account_evidence,
                           metadata={"kind": "linked_account"})
                if account_username:
                    add_relation(EntityType.SERVICE, shortname,
                                 EdgeType.HAS_USERNAME, EntityType.USERNAME,
                                 account_username, 0.60, account_evidence)
    else:
        warnings.append(f"no Gravatar profile found for {email or 'target'}")

    if not entities:
        warnings.append("no Gravatar entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
