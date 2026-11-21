"""GitHub REST API OSINT collector (public profile, repos, events, commit search).

No account/cookie is used: only the public ``api.github.com`` endpoints are
queried. An optional ``GITHUB_TOKEN`` (``get_secret("github", "token")``) is
attached as ``Authorization: Bearer <token>`` and raises the REST rate limit
from ~60 to ~5,000 req/hour; the token is never written to stdout, stderr or
error messages. ``auth_status`` reports ``CONFIGURED`` (token) or
``KEYLESS_LIMITED`` (no token) in the JSON payload.

Resilience rules (Phase 12):

* standard GitHub headers (``Accept``, ``X-GitHub-Api-Version``, ``User-Agent``);
* if an authenticated **primary** request gets 401/403, retry the whole lookup
  unauthenticated before classifying a rate-limit failure;
* secondary sub-requests (repos, events, commit search) are non-fatal — a
  403/422 there never discards a successful profile or fails the run;
* a 404 profile (username does not exist) is a clean EMPTY result, not an error.

* ``username`` -> ``/users/{u}`` + ``/users/{u}/repos`` + ``/users/{u}/events/public``
  (commit-author e-mails harvested from public event payloads) + best-effort
  ``/search/commits``.
* ``email`` -> ``/search/users?q=<email> in:email`` then profile hydration for a
  bounded number of matches + best-effort commit-author search.

Failures never raise: transport errors become TIMEOUT/SPAWN_ERROR results;
primary 401/403/429 becomes RATE_LIMITED only when no usable data was collected.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import quote, quote_plus

from hub.credentials import CONFIGURED, KEYLESS_LIMITED
from hub.models import ErrorCode, ScopeConfig
from hub.tools.builtin import BuiltinOutput
from hub.tools.builtin._http import (
    MAX_JSON_BYTES,
    decode_json,
    fetch,
    make_client,
)

__all__ = ["collect"]

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
USER_AGENT = "ai-osint-hub"
MAX_REPOS = 200
MAX_EVENTS = 100
MAX_EMAILS = 100
MAX_USERS = 10
MAX_COMMIT_RESULTS = 10
MAX_EMAIL_REPOS = 30

_USER_KEYS = (
    "login", "name", "company", "location", "blog", "bio",
    "html_url", "avatar_url", "public_repos",
)
_REPO_KEYS = ("full_name", "html_url", "language", "description", "fork")


def _github_token() -> str:
    """Resolve the optional token at call time (tests patch ``hub.credentials``)."""
    from hub.credentials import get_secret

    return get_secret("github", "token")


def _headers(token: str = "") -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": USER_AGENT,
    }
    if token:
        # Never logged/echoed: only the request header carries the token.
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _normalise_user(data: dict) -> dict:
    user: dict[str, object] = {}
    for key in _USER_KEYS:
        value = data.get(key)
        user[key] = "" if value is None else value
    return user


def _normalise_repo(data: dict) -> dict:
    return {
        "full_name": str(data.get("full_name") or ""),
        "html_url": str(data.get("html_url") or ""),
        "language": str(data.get("language") or ""),
        "description": str(data.get("description") or ""),
        "fork": bool(data.get("fork")),
    }


def _harvest_emails(events: object) -> list[dict[str, str]]:
    """Pull commit-author e-mails out of public event payloads (bounded)."""
    emails: list[dict[str, str]] = []
    seen: set[str] = set()
    if not isinstance(events, list):
        return emails
    for event in events[:MAX_EVENTS]:
        if not isinstance(event, dict):
            continue
        event_payload = event.get("payload")
        if not isinstance(event_payload, dict):
            continue
        commits = event_payload.get("commits")
        if not isinstance(commits, list):
            continue
        for commit in commits:
            author = commit.get("author") if isinstance(commit, dict) else None
            address = str(author.get("email") or "").strip().lower() if isinstance(author, dict) else ""
            if not address or "@" not in address or address in seen:
                continue
            seen.add(address)
            emails.append({"email": address, "source": "github:events_commits"})
            if len(emails) >= MAX_EMAILS:
                return emails
    return emails


def _harvest_commit_search(data: object, source: str) -> dict[str, list]:
    """Harvest author/committer logins, repositories and e-mails from commit search."""
    emails: list[dict[str, str]] = []
    logins: list[str] = []
    repos: list[dict] = []
    seen_emails: set[str] = set()
    seen_logins: set[str] = set()
    seen_repos: set[str] = set()
    if not isinstance(data, dict):
        return {"emails": emails, "logins": logins, "repos": repos}
    items = data.get("items")
    if not isinstance(items, list):
        return {"emails": emails, "logins": logins, "repos": repos}
    for item in items[:MAX_COMMIT_RESULTS]:
        if not isinstance(item, dict):
            continue
        commit = item.get("commit")
        author = commit.get("author") if isinstance(commit, dict) else None
        address = (str(author.get("email") or "").strip().lower()
                   if isinstance(author, dict) else "")
        if address and "@" in address and address not in seen_emails:
            seen_emails.add(address)
            emails.append({"email": address, "source": source})
        actor_sources = [
            item.get("author"), item.get("committer"),
            commit.get("author") if isinstance(commit, dict) else None,
            commit.get("committer") if isinstance(commit, dict) else None,
        ]
        for actor in actor_sources:
            login = (str(actor.get("login") or "").strip()
                     if isinstance(actor, dict) else "")
            if login and login.lower() not in seen_logins:
                seen_logins.add(login.lower())
                logins.append(login)
        repository = item.get("repository")
        if isinstance(repository, dict):
            repo = _normalise_repo(repository)
            if repo["full_name"] and repo["full_name"].lower() not in seen_repos:
                seen_repos.add(repo["full_name"].lower())
                repos.append(repo)
    return {"emails": emails, "logins": logins, "repos": repos}


def _merge_repos(lookup: "_Lookup", repos: list[dict]) -> None:
    known = {str(repo.get("full_name") or "").lower() for repo in lookup.repos}
    for repo in repos:
        full_name = str(repo.get("full_name") or "")
        if not full_name or full_name.lower() in known:
            continue
        known.add(full_name.lower())
        lookup.repos.append(repo)
        if len(lookup.repos) >= MAX_REPOS:
            break


async def _fetch_json(client, url: str):
    """GET a JSON endpoint; returns ``(FetchResult, parsed-payload-or-None)``."""
    result = await fetch(client, url, max_bytes=MAX_JSON_BYTES)
    if not result.ok or not 200 <= result.status_code < 300:
        return result, None
    try:
        return result, decode_json(result.body)
    except ValueError:
        return result, None


class _Lookup:
    """Mutable bookkeeping for one GitHub lookup (query + collected payload)."""

    def __init__(self, username: str, email: str, auth_status: str,
                 *, authenticated: bool = False) -> None:
        self.username = username
        self.email = email
        self.auth_status = auth_status
        self.authenticated = authenticated
        self.users: list[dict] = []
        self.repos: list[dict] = []
        self.emails: list[dict] = []
        self.notes: list[str] = []
        self.rate_limited = False
        self.auth_failed = False
        self.timed_out = False
        self.transport_error = ""
        self.hydrated_logins: set[str] = set()

    def record_failure(self, result, label: str, *, primary: bool = False) -> bool:
        """Record a failure; return True when the call produced no data.

        Primary failures can trip the run-level rate-limit result. Secondary
        sub-request failures are warnings only and never abort a profile run.
        """
        status = int(result.status_code or 0)
        if primary and self.authenticated and status in {401, 403}:
            # Token rejected / expired: signal the caller to retry unauthenticated.
            self.auth_failed = True
        if result.error_code == ErrorCode.TIMEOUT:
            self.timed_out = True
            self.transport_error = f"{label}: {result.error}"
        elif result.error:
            self.transport_error = f"{label}: {result.error}"
        elif status in {401, 403, 429}:
            if primary:
                self.rate_limited = True
                self.notes.append(
                    f"{label}: GitHub API rate limit / credentials rejected "
                    f"(HTTP {status})")
            else:
                self.notes.append(
                    f"{label}: optional sub-request HTTP {status} (ignored)")
        return bool(result.error) or status in {401, 403, 429}

    def payload(self) -> dict:
        users = self.users
        return {
            "query": {"username": self.username, "email": self.email},
            "auth_status": self.auth_status,
            "user": users[0] if users else {},
            "users": users,
            "repos": self.repos,
            "emails": self.emails,
        }


async def _hydrate_login(client, lookup: _Lookup, login: str, *,
                         fallback_user: dict | None = None) -> None:
    """Fetch one discovered login's profile + repos (bounded, non-fatal)."""
    login = str(login or "").strip()
    if not login or login in lookup.hydrated_logins:
        return
    lookup.hydrated_logins.add(login)
    profile_result, profile = await _fetch_json(
        client, f"{GITHUB_API}/users/{quote(login, safe='')}")
    user = dict(fallback_user or {})
    if profile_result.status_code == 200 and isinstance(profile, dict):
        user = _normalise_user(profile)
    elif lookup.record_failure(profile_result, f"profile {login}"):
        user = user or {}
    if user:
        key = str(user.get("login") or login).lower()
        if not any(str(existing.get("login") or "").lower() == key
                   for existing in lookup.users):
            lookup.users.append(user)

    repos_result, repos = await _fetch_json(
        client, f"{GITHUB_API}/users/{quote(login, safe='')}/repos"
                f"?per_page={MAX_EMAIL_REPOS}&sort=updated")
    if repos_result.status_code == 200 and isinstance(repos, list):
        _merge_repos(lookup, [
            _normalise_repo(item) for item in repos
            if isinstance(item, dict)])
    elif lookup.record_failure(repos_result, f"repos {login}"):
        pass


async def _lookup_username(client, lookup: _Lookup) -> None:
    base = f"{GITHUB_API}/users/{quote(lookup.username, safe='')}"
    result, data = await _fetch_json(client, base)
    if lookup.record_failure(result, "profile", primary=True):
        if lookup.auth_failed:
            return
        if result.status_code not in {404}:
            return
    if result.status_code == 200 and isinstance(data, dict):
        user = _normalise_user(data)
        lookup.users.append(user)
        if user.get("login"):
            lookup.hydrated_logins.add(str(user["login"]))
    elif result.status_code == 404:
        lookup.notes.append("GitHub user not found")
    else:
        lookup.notes.append(f"profile: unexpected HTTP {result.status_code}")
    if not lookup.users:
        return

    result, data = await _fetch_json(
        client, f"{base}/repos?per_page=100&sort=pushed")
    if not lookup.record_failure(result, "repos"):
        if result.status_code == 200 and isinstance(data, list):
            lookup.repos = [_normalise_repo(item) for item in data[:MAX_REPOS]
                            if isinstance(item, dict)]
        elif result.status_code not in {404}:
            lookup.notes.append(f"repos: unexpected HTTP {result.status_code}")

    result, data = await _fetch_json(
        client, f"{base}/events/public?per_page=100")
    if not lookup.record_failure(result, "events"):
        if result.status_code == 200 and isinstance(data, list):
            lookup.emails = _harvest_emails(data)
        elif result.status_code not in {404}:
            lookup.notes.append(f"events: unexpected HTTP {result.status_code}")

    # Best-effort commit-author search: 401/403/422 here is a warning only.
    query = quote_plus(f"author:{lookup.username}")
    result, data = await _fetch_json(
        client, f"{GITHUB_API}/search/commits?q={query}&per_page=10")
    if 200 <= int(result.status_code or 0) < 300:
        found = _harvest_commit_search(data, "github:search_commits")
        known = {row["email"] for row in lookup.emails}
        lookup.emails.extend(row for row in found["emails"]
                             if row["email"] not in known)
        lookup.emails = lookup.emails[:MAX_EMAILS]
        _merge_repos(lookup, found["repos"])
        for login in found["logins"]:
            await _hydrate_login(client, lookup, login)
    else:
        lookup.record_failure(result, "commit search")


async def _lookup_email(client, lookup: _Lookup) -> None:
    # 1. GitHub user search for the full e-mail address.
    query = quote_plus(f"{lookup.email} in:email")
    result, data = await _fetch_json(client, f"{GITHUB_API}/search/users?q={query}")
    if lookup.record_failure(result, "search", primary=True):
        if lookup.auth_failed:
            return
    search_items: list[dict] = []
    if result.status_code == 422:
        lookup.notes.append("GitHub user search rejected the e-mail query")
    elif result.status_code != 200 or not isinstance(data, dict):
        lookup.notes.append(f"search: unexpected HTTP {result.status_code}")
    else:
        items = data.get("items")
        if isinstance(items, list):
            search_items = [item for item in items[:MAX_USERS]
                            if isinstance(item, dict)]
            for item in search_items:
                login = str(item.get("login") or "").strip()
                if login:
                    await _hydrate_login(
                        client, lookup, login,
                        fallback_user=_normalise_user(item))

    # 2. Probe the e-mail local-part directly (high-signal handle) even when
    # user search returns nothing.
    local_part = lookup.email.split("@", 1)[0].strip()
    if local_part:
        await _hydrate_login(client, lookup, local_part)

    # 3. Commit search: keep author/committer login + repository full_name and
    # hydrate every discovered login in the same run.
    email_query = quote_plus(f"author-email:{lookup.email}")
    result, data = await _fetch_json(
        client, f"{GITHUB_API}/search/commits?q={email_query}&per_page=10")
    if 200 <= int(result.status_code or 0) < 300:
        found = _harvest_commit_search(data, "github:search_commits")
        known = {row["email"] for row in lookup.emails}
        lookup.emails.extend(row for row in found["emails"]
                             if row["email"] not in known)
        lookup.emails = lookup.emails[:MAX_EMAILS]
        _merge_repos(lookup, found["repos"])
        for login in found["logins"]:
            await _hydrate_login(client, lookup, login)
    else:
        lookup.record_failure(result, "commit search")


async def _execute(params: dict, timeout_sec: int) -> BuiltinOutput:
    username = str(params.get("username") or "").strip().lstrip("@")
    email = str(params.get("email") or "").strip()
    token = _github_token()

    # First attempt (authenticated when a token exists). On primary 401/403 from
    # an authenticated request, retry the whole lookup unauthenticated once.
    lookup = await _run_lookup_with_timeout(username, email, token=token,
                                            timeout_sec=timeout_sec)
    if lookup.auth_failed and token:
        retry = await _run_lookup_with_timeout(username, email, token="",
                                               timeout_sec=timeout_sec)
        retry.notes.insert(
            0, "authenticated request was rejected; retried unauthenticated")
        lookup = retry

    seen: set[str] = set()
    unique_users: list[dict] = []
    for user in lookup.users:
        key = str(user.get("login") or "").lower() or json.dumps(user, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        unique_users.append(user)
    lookup.users = unique_users

    data = lookup.payload()
    collected = bool(unique_users or lookup.repos or lookup.emails or lookup.users)
    if lookup.rate_limited and not collected:
        message = "GitHub API rate limit reached while collecting public data"
        return BuiltinOutput(exit_code=1, stderr=message,
                             error_code=ErrorCode.RATE_LIMITED,
                             error_message=message)
    if not collected and lookup.transport_error:
        code = ErrorCode.TIMEOUT if lookup.timed_out else ErrorCode.SPAWN_ERROR
        return BuiltinOutput(
            exit_code=-1 if lookup.timed_out else 1,
            stderr=lookup.transport_error,
            error_code=code,
            error_message=f"github_osint: {lookup.transport_error}",
        )
    if not collected:
        # Nonexistent username (404), empty search, or no public data: clean EMPTY.
        note = "; ".join(lookup.notes)[:1000] or "no public GitHub data found"
        return BuiltinOutput(stdout="", stderr=note, exit_code=0)
    return BuiltinOutput(
        stdout=json.dumps(data, sort_keys=True),
        stderr="; ".join(lookup.notes)[:1000],
        exit_code=0,
    )


async def _run_lookup_with_timeout(username: str, email: str, *,
                                   token: str, timeout_sec: int) -> _Lookup:
    auth_status = CONFIGURED if token else KEYLESS_LIMITED
    lookup = _Lookup(username, email, auth_status, authenticated=bool(token))
    client = make_client(
        timeout_sec=timeout_sec,
        follow_redirects=False,
        headers=_headers(token),
    )
    async with client:
        if username:
            await _lookup_username(client, lookup)
        if email and not lookup.auth_failed:
            await _lookup_email(client, lookup)
    return lookup


async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput:
    """Look up a GitHub username and/or e-mail address via the public REST API."""
    _ = scope  # api.github.com is a fixed passive source; no target-site access
    username = str((params or {}).get("username") or "").strip()
    email = str((params or {}).get("email") or "").strip()
    if not username and not email:
        return BuiltinOutput(
            exit_code=2,
            stderr="missing required parameter: username or email",
            error_message="github_osint requires 'username' and/or 'email'",
        )
    try:
        return await asyncio.wait_for(_execute(params, timeout_sec), timeout=timeout_sec)
    except (asyncio.TimeoutError, TimeoutError):
        message = f"github_osint timed out after {timeout_sec}s"
        return BuiltinOutput(exit_code=-1, stderr=message,
                             error_code=ErrorCode.TIMEOUT, error_message=message)
