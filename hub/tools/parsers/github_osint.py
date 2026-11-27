"""Deterministic parser for the built-in GitHub public-API collector.

Input (collector stdout)::

    {"query": {"username": "octocat", "email": ""},
     "user": {"login": "octocat", "name": "The Octocat", "company": "@github",
              "location": "San Francisco", "blog": "https://github.blog",
              "html_url": "https://github.com/octocat", "public_repos": 8, ...},
     "users": [...], "repos": [{"full_name": ...}], "emails": [{"email": ...}]}

Output: PERSON entities, ORGANIZATION/LOCATION/URL/SOCIAL_PROFILE artefacts,
REPOSITORY entities with ``person OWNS repository`` and EMAIL entities with
``person HAS_EMAIL email``; the queried username/e-mail is emitted explicitly so
the identity pivot is visible in the graph.
"""

from __future__ import annotations

import json
import re

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ITEMS = 100

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_IGNORED_LOGINS = frozenset({
    "web-flow",
    "dependabot",
    "dependabot[bot]",
    "github-actions",
    "github-actions[bot]",
    "renovate",
    "renovate[bot]",
})
_IGNORED_EMAILS = frozenset({"noreply@github.com"})


def _is_bot_login(login: str) -> bool:
    low = str(login or "").strip().lower()
    return bool(low) and (low in _IGNORED_LOGINS or low.endswith("[bot]"))


def _is_bot_email(address: str) -> bool:
    low = str(address or "").strip().lower()
    if not low:
        return False
    if low in _IGNORED_EMAILS:
        return True
    local = low.split("@", 1)[0]
    return local in _IGNORED_LOGINS or local.endswith("[bot]") or "[bot]" in local


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse GitHub collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"github_osint parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _as_url(value: str) -> str:
    text = _as_text(value)
    if not text:
        return ""
    return text if _URL_RE.match(text) else f"https://{text.lstrip('/')}"


def _organisation(company: str) -> str:
    """Normalise a GitHub company string (``@org``, ``Org Name``) to an org name."""
    text = _as_text(company)
    if not text:
        return ""
    text = text.lstrip("@").strip()
    return re.sub(r"\s+", " ", text)


def _user_list(data: dict) -> list[dict]:
    users: list[dict] = []
    raw_users = data.get("users")
    if isinstance(raw_users, list):
        users.extend(user for user in raw_users if isinstance(user, dict))
    raw_user = data.get("user")
    if isinstance(raw_user, dict) and raw_user and raw_user not in users:
        users.insert(0, raw_user)
    return users[:MAX_ITEMS]


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from github_osint: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected github_osint payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    query = data.get("query") if isinstance(data.get("query"), dict) else {}
    # An e-mail target must NEVER become USERNAME. Only use an explicit
    # username query; a bare username target is accepted, an e-mail is not.
    queried_username = _as_text(query.get("username")).lstrip("@")
    if not queried_username:
        target_text = _as_text(target)
        if target_text and "@" not in target_text and "://" not in target_text \
                and " " not in target_text:
            queried_username = target_text.lstrip("@")
    queried_email = _as_text(query.get("email"))
    users = _user_list(data)
    repos = data.get("repos") if isinstance(data.get("repos"), list) else []
    emails = data.get("emails") if isinstance(data.get("emails"), list) else []

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str]] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   evidence: str, *, metadata: dict | None = None,
                   attributes: dict | None = None) -> bool:
        value = _as_text(value)
        if not value:
            return False
        key = (entity_type.value, value.lower())
        if key in seen_entities:
            return False
        seen_entities.add(key)
        entities.append(EntityCandidate(
            type=entity_type, value=value, confidence=confidence,
            metadata=dict(metadata or {}), attributes=dict(attributes or {}),
            evidence=evidence[:MAX_EVIDENCE],
        ))
        return True

    def add_relation(subject_type: EntityType, subject_value: str,
                     predicate: EdgeType, object_type: EntityType,
                     object_value: str, confidence: float, evidence: str) -> None:
        subject_value = _as_text(subject_value)
        object_value = _as_text(object_value)
        if not subject_value or not object_value:
            return
        key = (subject_value.lower(), predicate.value, object_value.lower())
        if key in seen_relations:
            return
        seen_relations.add(key)
        relations.append(RelationCandidate(
            subject_type=subject_type, subject_value=subject_value,
            predicate=predicate, object_type=object_type,
            object_value=object_value, confidence=confidence,
            evidence=evidence[:MAX_EVIDENCE],
        ))

    primary_person = ""
    for user in users:
        login = _as_text(user.get("login"))
        if _is_bot_login(login):
            continue
        name = _as_text(user.get("name")) or login
        if not name or _is_bot_login(name):
            continue
        evidence = (
            f"GitHub public profile login={login or '?'}"
            f"; name={_as_text(user.get('name'))}"
            f"; company={_as_text(user.get('company'))}"
            f"; location={_as_text(user.get('location'))}"
            f"; public_repos={user.get('public_repos')}"
        )
        attributes = {
            "login": login,
            "github_url": _as_text(user.get("html_url")),
            "public_repos": user.get("public_repos") if isinstance(
                user.get("public_repos"), int) else 0,
        }
        aliases = [login] if login and login != name else []
        if add_entity(EntityType.PERSON, name, 0.85, evidence,
                      metadata={"source": "github"}, attributes=attributes):
            entities[-1].aliases.extend(aliases)
        if not primary_person:
            primary_person = name
        if login:
            username_evidence = f"GitHub login for {name}: {login}"
            add_entity(EntityType.USERNAME, login, 0.85, username_evidence,
                       metadata={"source": "github"})
            add_relation(EntityType.PERSON, name, EdgeType.HAS_USERNAME,
                         EntityType.USERNAME, login, 0.80, username_evidence)
        html_url = _as_text(user.get("html_url"))
        if html_url:
            add_entity(EntityType.SOCIAL_PROFILE, html_url, 0.85,
                       f"GitHub profile page for {name}: {html_url}")
        blog = _as_url(_as_text(user.get("blog")))
        if blog:
            add_entity(EntityType.URL, blog, 0.70,
                       f"GitHub profile links personal site for {name}: {blog}")
        organisation = _organisation(_as_text(user.get("company")))
        if organisation:
            org_evidence = f"GitHub profile company of {name}: {_as_text(user.get('company'))}"
            add_entity(EntityType.ORGANIZATION, organisation, 0.70, org_evidence,
                       metadata={"source": "github:company"})
            add_relation(EntityType.PERSON, name, EdgeType.ASSOCIATED_WITH,
                         EntityType.ORGANIZATION, organisation, 0.65, org_evidence)
        location = _as_text(user.get("location"))
        if location:
            location_evidence = f"GitHub profile location of {name}: {location}"
            add_entity(EntityType.LOCATION, location, 0.60, location_evidence,
                       metadata={"source": "github:location"})
            add_relation(EntityType.PERSON, name, EdgeType.LOCATED_IN,
                         EntityType.LOCATION, location, 0.60, location_evidence)

    for repo in repos[:MAX_ITEMS]:
        if not isinstance(repo, dict):
            continue
        full_name = _as_text(repo.get("full_name"))
        if not full_name:
            continue
        evidence = (f"GitHub public repository {full_name}"
                    + (f" ({_as_text(repo.get('language'))})" if repo.get("language") else "")
                    + (f": {_as_text(repo.get('description'))}" if repo.get("description") else ""))
        metadata = {"language": _as_text(repo.get("language")),
                    "fork": bool(repo.get("fork"))}
        if add_entity(EntityType.REPOSITORY, full_name, 0.80, evidence,
                      metadata=metadata):
            if primary_person:
                add_relation(EntityType.PERSON, primary_person, EdgeType.OWNS,
                             EntityType.REPOSITORY, full_name, 0.80, evidence)

    for item in emails[:MAX_ITEMS]:
        address = _as_text(item.get("email")).lower() if isinstance(item, dict) else ""
        source = _as_text(item.get("source")) if isinstance(item, dict) else ""
        if not address or not _EMAIL_RE.match(address) or _is_bot_email(address):
            continue
        evidence = f"GitHub public event commit author e-mail: {address}" + (
            f" (source {source})" if source else "")
        add_entity(EntityType.EMAIL, address, 0.80, evidence,
                   metadata={"source": source or "github:events"})
        if primary_person:
            add_relation(EntityType.PERSON, primary_person, EdgeType.HAS_EMAIL,
                         EntityType.EMAIL, address, 0.75, evidence)

    if queried_username and not _is_bot_login(queried_username):
        evidence = f"GitHub lookup was performed for username {queried_username}"
        add_entity(EntityType.USERNAME, queried_username, 0.70, evidence,
                   metadata={"source": "github:query"})
        if primary_person:
            add_relation(EntityType.PERSON, primary_person, EdgeType.HAS_USERNAME,
                         EntityType.USERNAME, queried_username, 0.70, evidence)
    if queried_email and not _is_bot_email(queried_email):
        evidence = f"GitHub user search matched e-mail address {queried_email}"
        add_entity(EntityType.EMAIL, queried_email.lower(), 0.75, evidence,
                   metadata={"source": "github:search_query"})
        if primary_person:
            add_relation(EntityType.PERSON, primary_person, EdgeType.HAS_EMAIL,
                         EntityType.EMAIL, queried_email.lower(), 0.60, evidence)
        # A non-role local-part is a legitimate GitHub handle seed even when the
        # collector only returned commit/email evidence for it.
        local_part = queried_email.split("@", 1)[0].strip().lower()
        if (local_part and "@" not in local_part
                and local_part not in {
                    "info", "contact", "admin", "support", "office", "mail",
                    "hr", "sales", "press", "help", "user", "users"}):
            local_evidence = (f"GitHub e-mail local-part handle for "
                              f"{queried_email}: {local_part}")
            if add_entity(EntityType.USERNAME, local_part, 0.65, local_evidence,
                          metadata={"source": "github:email_local_part"}):
                if primary_person:
                    add_relation(EntityType.PERSON, primary_person,
                                 EdgeType.HAS_USERNAME, EntityType.USERNAME,
                                 local_part, 0.60, local_evidence)

    if not entities:
        warnings.append("no GitHub entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
