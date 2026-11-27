"""Unstructured multi-clue subject intake and bounded handle permutations.

Phase 8 of the AI OSINT Hub: turn a messy paragraph (or structured seed fields)
into a complete ERKG seed set with ``USER_PROVIDED_SEED`` provenance, link every
clue to the primary subject so cross-tool corroboration works across user
clues, and deterministically generate bounded username/email hypotheses
(confidence <= 0.35) for the pivot engine to test with passive collectors.

Everything here is pure deterministic Python — no network, no LLM.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from hub.cooking import (
    extract_emails,
    extract_phones,
    extract_urls,
    parse_raw_input,
)
from hub.erkg.resolution import (
    PROVIDER_INFRASTRUCTURE_DOMAINS,
    is_noreply_email,
    is_provider_infrastructure_domain,
)
from hub.models import EntityType
from hub.tools.base import EntityCandidate, infer_value_type

USER_PROVIDED_SEED = "USER_PROVIDED_SEED"
#: Domain derived from a user-provided email seed (seed-wave coverage, not scope).
EMAIL_DERIVED_DOMAIN = "EMAIL_DERIVED_DOMAIN"
EMAIL_DERIVED_USERNAME = "EMAIL_DERIVED_USERNAME"
#: Generic role mailboxes are never promoted to personal username seeds.
_ROLE_MAILBOX_LOCALPARTS = frozenset({
    "info", "contact", "admin", "support", "office", "mail", "hr", "sales",
    "press", "help", "staff", "team", "user", "users", "target", "subject",
    "test", "demo", "sample", "example",
})
_AZ_MOBILE_PREFIXES = frozenset({"050", "051", "055", "070", "077", "099", "010"})
_AZ_LOCATION_MARKERS = frozenset({
    "az", "baku", "bakı", "azerbaijan", "azərbaycan", "azerbaidjan",
})
_FREEMAIL_DOMAINS = set(PROVIDER_INFRASTRUCTURE_DOMAINS) | {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "ymail.com", "proton.me", "protonmail.com", "icloud.com",
    "me.com", "mac.com", "mail.com", "aol.com", "gmx.com", "gmx.net",
    "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com", "126.com",
}

# Bounds keep intake deterministic and prevent clue-list explosions.
MAX_CLUES = {
    EntityType.PERSON: 5,
    EntityType.USERNAME: 10,
    EntityType.EMAIL: 15,
    EntityType.DOMAIN: 10,
    EntityType.SUBDOMAIN: 10,
    EntityType.IP: 10,
    EntityType.URL: 10,
    EntityType.PHONE: 5,
    EntityType.ORGANIZATION: 5,
    EntityType.LOCATION: 5,
}
MAX_HYPOTHESIS_USERNAMES = 6
MAX_HYPOTHESIS_EMAILS = 4
MAX_HYPOTHESIS_CONFIDENCE = 0.35

_COMMON_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
    "protonmail.com", "icloud.com", "mail.com", "aol.com", "yandex.com",
}

_STOPWORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "has", "have", "his", "like", "this",
    "that", "with", "from", "they", "will", "been", "when", "make", "more",
    "some", "than", "them", "very", "just", "what", "over", "such", "only",
    "other", "into", "then", "also", "most", "even", "much", "well", "back",
    "down", "does", "target", "subject", "information", "intelligence",
    "investigate", "investigation", "profile", "person", "individual",
    # Short prose/OSINT note words that must never become handle fragments.
    "in", "at", "on", "of", "to", "be", "a", "an", "or", "by", "is", "goes",
    "will", "few", "days", "day", "nd", "rd", "th", "st", "course", "student",
    "students", "studies", "school", "university", "works", "work", "lives",
    "living", "located", "based", "and", "with", "about", "from", "near",
}

_RELATION_ORGS = {
    "sister", "brother", "mother", "father", "friend", "colleague", "cousin",
    "wife", "husband", "uncle", "aunt", "son", "daughter", "partner",
}

# Cue-based extraction (deterministic, bounded).
_PERSON_CUE_RE = re.compile(
    r"\b(?i:target is|subject is|name is|named|called|real name is)\s+"
    r"([^\W\d_][\w'’.\-]*(?:\s+[^\W\d_][\w'’.\-]*){0,2})", re.UNICODE)
#: Explicit username labels only (Phase 15): bare prose tokens are never handles.
_USERNAME_CUE_RE = re.compile(
    r"(?:\b(?:username|user|handle|nick|nickname|screen\s*name|alias)\b"
    r"\s*[:=]\s*|\b(?:aka|goes\s+by)\b\s*[:=]?\s*)"
    r"(?P<rest>[^\n;,]{1,160})",
    re.IGNORECASE,
)
_SLASH_HANDLE_RE = re.compile(r"(?<![\w/])u/([A-Za-z0-9._\-]{2,32})", re.IGNORECASE)
_AT_HANDLE_RE = re.compile(r"(?<![\w@])@([A-Za-z0-9._\-]{2,32})")
_CUE_TOKEN_RE = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9._\-]{1,31}")
_ORDINAL_RE = re.compile(r"^\d{1,2}(?:st|nd|rd|th)$", re.IGNORECASE)
_HANDLE_CONNECTORS = {"and", "or", "the", "a", "an", "is", "aka", "alias"}
#: Tokens that are prose/version terms, not standalone investigation handles.
_STANDALONE_PROSE_TERMS = {
    "2nd", "3rd", "1st", "4th", "18", "2026", "c2", "v2", "b2b", "sha256",
    "ipv4", "http2", "web3",
}
_PROFILE_HOSTS = {
    "github.com", "gitlab.com", "twitter.com", "x.com", "instagram.com",
    "tiktok.com", "facebook.com", "reddit.com", "t.me", "telegram.me",
    "keybase.io", "medium.com", "dev.to", "linkedin.com", "youtube.com",
    "mastodon.social",
}
_GENERIC_PATH_SEGMENTS = {
    "about", "login", "signup", "signin", "explore", "home", "search",
    "channel", "user", "users", "profile", "profiles", "status", "settings",
    "watch", "help", "u", "in", "c", "v", "p", "www", "api",
}


def _is_ordinal_or_prose_number(value: str) -> bool:
    lowered = value.lower()
    return (bool(_ORDINAL_RE.match(lowered))
            or bool(re.fullmatch(r"\d+", lowered))
            or lowered in {"2nd", "18"})


def _valid_handle_literal(value: str) -> str:
    """Lowercase a handle candidate, or return '' when it is prose/ordinal."""
    candidate = value.strip().lstrip("@").strip(".,;:()[]\"'")
    candidate = candidate.lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._\-]{1,31}", candidate):
        return ""
    if _is_ordinal_or_prose_number(candidate):
        return ""
    if candidate in _HANDLE_CONNECTORS or candidate in _STOPWORDS:
        return ""
    return candidate


def _cue_username_values(text: str, excluded: set[str]) -> list[str]:
    """Extract handles only after explicit username indicators."""
    found: list[str] = []
    for match in _USERNAME_CUE_RE.finditer(text):
        for token in _CUE_TOKEN_RE.findall(match.group("rest")):
            candidate = _valid_handle_literal(token)
            if candidate and candidate not in excluded and candidate not in found:
                found.append(candidate)
    for handle in _SLASH_HANDLE_RE.findall(text):
        candidate = _valid_handle_literal(handle)
        if candidate and candidate not in excluded and candidate not in found:
            found.append(candidate)
    return found


def _profile_url_username(url: str) -> str:
    """Return a handle from a known social profile URL path (or '')."""
    lowered = (url or "").strip().lower()
    if not lowered.startswith(("http://", "https://")):
        return ""
    host = lowered.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    host = host[4:] if host.startswith("www.") else host
    if host not in _PROFILE_HOSTS:
        return ""
    path = lowered.split("://", 1)[1]
    path = path.split("/", 1)[1] if "/" in path else ""
    segments = [segment.strip("@").split("?", 1)[0].split("#", 1)[0]
                for segment in path.split("/") if segment.strip()]
    for segment in segments:
        if segment.lower() in _GENERIC_PATH_SEGMENTS:
            continue
        candidate = _valid_handle_literal(segment)
        if candidate:
            return candidate
    return ""
_ORG_CUE_RE = re.compile(
    r"\b(?i:works? (?:at|for)|employed (?:at|by)|organization|organisation|"
    r"company|employer|member of)\s*[:\s]?\s*"
    r"([^\W\d_][\w&'’.\-]*(?:\s+[^\W\d_][\w&'’.\-]*){0,3})", re.UNICODE)
_LOCATION_CUE_RE = re.compile(
    r"\b(?i:lives? in|located in|based in|residing in|resides in|from|in)\s+"
    r"([^\W\d_][\w'’.\-]*(?:\s+[^\W\d_][\w'’.\-]*){0,2})", re.UNICODE)
_TITLE_PERSON_RE = re.compile(
    r"^\s*([^\W\d_][\w'’.\-]*(?:\s+[^\W\d_][\w'’.\-]*){1,2})\s*$",
    re.UNICODE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_HOST_CANDIDATE_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)

_STRUCTURED_KEYS = (
    "name", "usernames", "emails", "domains", "subdomains", "phones",
    "organizations", "locations", "urls", "ips",
)


def _as_list(value: Any, *, split_whitespace: bool = False,
             split_separators: bool = True) -> list[str]:
    """Split structured values on field-appropriate separators.

    Organizations split on commas/semicolons/newlines; handle-like fields
    (usernames, emails, domains, phones, URLs, IPs) also split on whitespace so
    ``"elv1ntsk 108.elv1n"`` becomes two seeds. Locations are kept as raw items
    here so ``"Baku, AZ"`` can be expanded hierarchically later (city + country).
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value]
    else:
        items = [str(value)]
    pattern = r"[,;\n\s]+" if split_whitespace else r"[,;\n]+"
    cleaned: list[str] = []
    for item in items:
        parts = (re.split(pattern, item) if split_separators else [item])
        for part in parts:
            part = part.strip().strip("\"'")
            if part and part not in cleaned:
                cleaned.append(part)
    return cleaned


@dataclass
class SeedClue:
    """One user-provided clue extracted from text or structured fields."""

    entity_type: EntityType
    value: str
    source: str = "free_text"       # free_text | structured
    field_name: str = ""
    confidence: float = 0.85
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: str = USER_PROVIDED_SEED

    def dedupe_key(self) -> tuple[str, str]:
        value = self.value.strip()
        if self.entity_type in (EntityType.EMAIL, EntityType.USERNAME,
                                EntityType.DOMAIN, EntityType.SUBDOMAIN,
                                EntityType.ORGANIZATION, EntityType.LOCATION):
            value = value.lower()
        return (self.entity_type.value, value)

    def to_candidate(self) -> EntityCandidate:
        attributes = {
            "provenance": self.provenance,
            "clue_source": self.source,
        }
        if self.field_name:
            attributes["clue_field"] = self.field_name
        metadata = {
            "origin": "raw_input",
            "provenance": self.provenance,
            "clue_source": self.source,
            **self.metadata,
        }
        return EntityCandidate(
            type=self.entity_type,
            value=self.value,
            confidence=self.confidence,
            metadata=metadata,
            attributes=attributes,
            evidence=f"[{self.provenance} {self.source}] {self.value}",
            direct=True,
        )


@dataclass
class StructuredSeeds:
    """Optional structured seed fields from CLI/MCP/Web/API callers."""

    name: Optional[str] = None
    usernames: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: Optional[dict[str, Any]]) -> "StructuredSeeds":
        if not data:
            return cls()
        name = data.get("name") or data.get("person") or data.get("full_name")
        organizations = data.get("organizations") or data.get("org") or data.get("organization")
        locations = data.get("locations") or data.get("location")
        return cls(
            name=str(name).strip() if name else None,
            usernames=_as_list(data.get("usernames") or data.get("username"),
                               split_whitespace=True),
            emails=_as_list(data.get("emails") or data.get("email"),
                            split_whitespace=True),
            domains=_as_list(data.get("domains") or data.get("domain"),
                             split_whitespace=True),
            subdomains=_as_list(data.get("subdomains") or data.get("subdomain"),
                                split_whitespace=True),
            phones=_as_list(data.get("phones") or data.get("phone"),
                            split_whitespace=True),
            organizations=_as_list(organizations),
            locations=_as_list(locations, split_separators=False),
            urls=_as_list(data.get("urls") or data.get("url"),
                          split_whitespace=True),
            ips=_as_list(data.get("ips") or data.get("ip"),
                         split_whitespace=True),
        )

    def is_empty(self) -> bool:
        return not any((self.name, self.usernames, self.emails, self.domains,
                        self.subdomains, self.phones, self.organizations,
                        self.locations, self.urls, self.ips))


def _valid_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[](),;")))
    except ValueError:
        return None


def _clean_person(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip(" .,;:'\"()[]-"))
    return value


def _title_sequence(value: str) -> str:
    """Trim a captured phrase to its leading title-cased words (Unicode-safe)."""
    words = [word.strip(" .,;:'\"()[]-") for word in str(value or "").split()]
    kept: list[str] = []
    for index, word in enumerate(words):
        if not word:
            continue
        if index > 0 and not word[0].isupper():
            break
        if index == 0 and not word[0].isalnum() and not word[0].isalpha():
            break
        kept.append(word)
        if len(kept) >= 3:
            break
    return _clean_person(" ".join(kept))


def _clean_org(value: str) -> str:
    """Trim trailing prepositional phrases captured after an organization name."""
    cleaned = _clean_person(value)
    parts = re.split(r"\s+(?:in|at|from|of|and|with)\s+", cleaned, maxsplit=1,
                     flags=re.IGNORECASE)
    return parts[0].strip()


#: Multi-variant transliteration for Azerbaijani/Turkish/Latin diacritics.
#: Each variant list is ordered by precision (digraph first, ASCII fallback second).
_TRANSLIT_VARIANTS: dict[str, tuple[str, ...]] = {
    "ş": ("sh", "s"), "ç": ("ch", "c"), "ğ": ("gh", "g"),
    "ə": ("e", "a"), "ı": ("i",), "i̇": ("i",), "ö": ("o",), "ü": ("u",),
    "ñ": ("n",), "á": ("a",), "à": ("a",), "â": ("a",), "ä": ("a",),
    "é": ("e",), "è": ("e",), "ê": ("e",), "ë": ("e",), "í": ("i",),
    "ì": ("i",), "î": ("i",), "ï": ("i",), "ó": ("o",), "ò": ("o",),
    "ô": ("o",), "õ": ("o",), "ú": ("u",), "ù": ("u",), "û": ("u",),
    "ý": ("y",), "ÿ": ("y",), "ß": ("ss",), "œ": ("oe",), "æ": ("ae",),
}


def _char_transliterations(char: str) -> tuple[str, ...]:
    lowered = char.lower()
    if lowered in _TRANSLIT_VARIANTS:
        return _TRANSLIT_VARIANTS[lowered]
    folded = unicodedata.normalize("NFKD", char)
    ascii_text = folded.encode("ascii", "ignore").decode("ascii").lower()
    if ascii_text:
        return (ascii_text,)
    if char.isalnum():
        return (lowered,)
    return ()


def transliteration_variants(value: str, *, max_variants: int = 8) -> list[str]:
    """Return ordered ASCII/digraph transliterations of one word-like token."""
    variants: list[str] = [""]
    for char in str(value or ""):
        options = _char_transliterations(char)
        if not options:
            continue
        expanded: list[str] = []
        for prefix in variants:
            for option in options:
                candidate = prefix + option
                if candidate not in expanded:
                    expanded.append(candidate)
        variants = expanded[:max(1, int(max_variants))]
    return [variant for variant in variants if variant]


def _handle_is_clean(candidate: str) -> bool:
    """Reject stopword/noisy fragments anywhere inside a handle candidate."""
    text = str(candidate or "").strip().lower()
    if not text or text in _STOPWORDS:
        return False
    parts = [part for part in re.split(r"[._\-]+", text) if part]
    if not parts:
        return False
    return not any(part in _STOPWORDS for part in parts)


_CITY_COUNTRY_RE = re.compile(
    r"^\s*([^,;]+?)\s*[,;]\s*([A-Za-z]{2})\s*$", re.UNICODE)


def _expand_location_values(value: str) -> list[str]:
    """Expand hierarchical location phrases.

    ``"Baku, AZ"`` becomes ``["Baku, AZ", "Baku", "AZ"]`` so phoneinfoga's
    country-level ``LOCATED_IN -> az`` corroborates the user-provided city clue
    without any functional contradiction. Semicolon/newline lists and plain
    comma lists are split normally.
    """
    results: list[str] = []

    def push(candidate: str) -> None:
        cleaned = _clean_person(candidate)
        if cleaned and cleaned not in results:
            results.append(cleaned)

    for part in re.split(r"[;\n]+", str(value or "")):
        part = part.strip()
        if not part:
            continue
        match = _CITY_COUNTRY_RE.match(part)
        if match:
            city = _clean_person(match.group(1))
            code = match.group(2).upper()
            if city:
                push(f"{city}, {code}")
                push(city)
            push(code)
            continue
        for piece in re.split(r",\s+", part):
            push(piece)
    return results


def _surname_tokens_from_emails(emails: Iterable[str],
                                first_names: Iterable[str] = ()) -> list[str]:
    """Extract known surname-like tokens from seed email local-parts."""
    first_set = {str(name).strip().lower() for name in first_names if name}
    tokens: list[str] = []
    for email in emails:
        local = str(email).split("@", 1)[0]
        for token in re.split(r"[._\-+]+", local):
            lowered = token.strip().lower()
            if len(lowered) < 3 or lowered.isdigit() or lowered in _STOPWORDS:
                continue
            if lowered in first_set or lowered in tokens:
                continue
            # Never treat an email handle/first-name fragment as a surname;
            # this is what produced kamranmammadov01-based doubled handles.
            if re.search(r"\d", lowered):
                continue
            if any(first and (first in lowered or lowered in first)
                   for first in first_set):
                continue
            tokens.append(lowered)
    return tokens[:4]


def _email_derived_username(email: str) -> str:
    """Return a safe personal local-part username, or '' for role/noreply mailboxes."""
    text = str(email or "").strip().lower()
    if "@" not in text or is_noreply_email(text):
        return ""
    local = text.split("@", 1)[0].split("+", 1)[0]
    if local.endswith(".std"):
        local = local.rsplit(".", 1)[0]
    if not local or local in _ROLE_MAILBOX_LOCALPARTS:
        return ""
    if re.fullmatch(r"[a-z0-9][a-z0-9._\-]{1,63}", local):
        return local
    return ""


def _has_az_context(locations: Iterable[str], text: str = "") -> bool:
    haystack = " ".join([str(item) for item in locations] + [str(text or "")]).lower()
    return any(marker in haystack for marker in _AZ_LOCATION_MARKERS)


def _normalise_phone_number(value: str, *, az_context: bool = False) -> str:
    """Normalize local/international phone input toward E.164."""
    text = str(value or "").strip()
    has_plus = text.startswith("+")
    digits = re.sub(r"\D", "", text)
    if not digits:
        return text.lower()
    if has_plus:
        return f"+{digits}"
    if text.startswith("00") and len(digits) > 2:
        return f"+{digits[2:]}"
    if len(digits) == 10 and digits.startswith("0"):
        if az_context or digits[:3] in _AZ_MOBILE_PREFIXES:
            return f"+994{digits[1:]}"
    if len(digits) == 9 and az_context and digits[:2] in {
            prefix[1:] for prefix in _AZ_MOBILE_PREFIXES}:
        return f"+994{digits}"
    return digits


def _is_person_like(value: str) -> bool:
    words = [word for word in value.split() if word]
    if not 2 <= len(words) <= 3:
        return False
    if any(word.lower().strip(".,") in _STOPWORDS for word in words):
        return False
    return all(bool(word) and word[0].isupper()
               and re.fullmatch(r"[^\W\d_][\w'’.\-]*", word, re.UNICODE)
               for word in words)


def _is_org_like(value: str) -> bool:
    words = value.split()
    if not words or len(words) > 4:
        return False
    if any(word.lower().strip(".,") in _STOPWORDS for word in words):
        return False
    return any(bool(word) and word[0].isupper() for word in words)


class MultiClueIntake:
    """Deterministic extraction of complete seed sets from free text + fields."""

    def __init__(self, *, max_per_type: Optional[dict[EntityType, int]] = None):
        limits = dict(MAX_CLUES)
        if max_per_type:
            limits.update(max_per_type)
        self.limits = limits

    # ── extraction ─────────────────────────────────────────────────
    def extract(self, raw_input: str,
                structured: Optional["StructuredSeeds | dict[str, Any]"] = None
                ) -> list[SeedClue]:
        text = raw_input or ""
        fields = (structured if isinstance(structured, StructuredSeeds)
                  else StructuredSeeds.from_mapping(structured))
        clues: list[SeedClue] = []
        seen: set[tuple[str, str]] = set()

        def add(entity_type: EntityType, value: str, *, source: str,
                field_name: str = "", confidence: Optional[float] = None,
                metadata: Optional[dict[str, Any]] = None,
                provenance: str = USER_PROVIDED_SEED) -> None:
            if not value:
                return
            clue = SeedClue(
                entity_type=entity_type,
                value=value.strip(),
                source=source,
                field_name=field_name,
                confidence=confidence if confidence is not None else _default_confidence(entity_type),
                metadata=metadata or {},
                provenance=provenance,
            )
            key = clue.dedupe_key()
            if key in seen:
                return
            seen.add(key)
            clues.append(clue)

        # ── structured fields (highest trust) ──
        if fields.name:
            add(EntityType.PERSON, _clean_person(fields.name), source="structured",
                field_name="name", confidence=0.95)
        for index, username in enumerate(fields.usernames):
            add(EntityType.USERNAME, username.lstrip("@"), source="structured",
                field_name="usernames", confidence=0.90)
        for email in fields.emails:
            email_val = email.lower()
            email_meta = (
                {"is_noreply": True, "provider_infrastructure": True}
                if is_noreply_email(email_val) else {}
            )
            add(EntityType.EMAIL, email_val, source="structured",
                field_name="emails", confidence=0.95, metadata=email_meta)
        for domain in fields.domains:
            cleaned = _clean_domain(domain)
            if cleaned:
                dom_meta = (
                    {"provider_infrastructure": True}
                    if is_provider_infrastructure_domain(cleaned) else {}
                )
                add(EntityType.DOMAIN, cleaned, source="structured",
                    field_name="domains", confidence=0.90, metadata=dom_meta)
        for subdomain in fields.subdomains:
            cleaned = _clean_domain(subdomain)
            if cleaned:
                sub_meta = (
                    {"provider_infrastructure": True}
                    if is_provider_infrastructure_domain(cleaned) else {}
                )
                add(EntityType.SUBDOMAIN, cleaned, source="structured",
                    field_name="subdomains", confidence=0.90, metadata=sub_meta)
        for phone in fields.phones:
            cleaned = _clean_phone(phone,
                                   az_context=_has_az_context(fields.locations, text))
            if cleaned:
                add(EntityType.PHONE, cleaned, source="structured",
                    field_name="phones", confidence=0.90)
        for url in fields.urls:
            cleaned = url.strip()
            if cleaned:
                add(EntityType.URL, cleaned, source="structured",
                    field_name="urls", confidence=0.90)
        for ip in fields.ips:
            cleaned = _valid_ip(ip)
            if cleaned:
                add(EntityType.IP, cleaned, source="structured",
                    field_name="ips", confidence=0.90)
        for organization in fields.organizations:
            add(EntityType.ORGANIZATION, organization, source="structured",
                field_name="organizations", confidence=0.85)
        for location in fields.locations:
            for candidate in _expand_location_values(location):
                add(EntityType.LOCATION, candidate, source="structured",
                    field_name="locations", confidence=0.85)

        # ── free-text extraction ──
        structured_person = bool(fields.name)
        az_context = _has_az_context(fields.locations, text)
        parsed = parse_raw_input(text)
        person_first_names = {person["name"].lower() for person in parsed.get("persons", [])}
        email_domains = {email.split("@", 1)[1].lower()
                         for email in parsed.get("emails", []) if "@" in email}

        for email in parsed.get("emails", [])[: self.limits[EntityType.EMAIL]]:
            email_val = email.lower()
            email_meta = (
                {"is_noreply": True, "provider_infrastructure": True}
                if is_noreply_email(email_val) else {}
            )
            add(EntityType.EMAIL, email_val, source="free_text",
                field_name="emails", confidence=0.85, metadata=email_meta)
        for phone in parsed.get("phones", [])[: self.limits[EntityType.PHONE]]:
            cleaned_phone = _clean_phone(phone, az_context=az_context)
            if cleaned_phone:
                add(EntityType.PHONE, cleaned_phone, source="free_text",
                    field_name="phones", confidence=0.80)
        for url in extract_urls(text)[: self.limits[EntityType.URL]]:
            add(EntityType.URL, url.rstrip("/"), source="free_text", field_name="urls",
                confidence=0.80)
        # A mail domain parsed from "user@host" is NOT an explicit domain clue:
        # only keep it when the host is also mentioned outside the email address
        # (which also prevents auto-locking scope to the seed email's domain).
        text_without_emails = text
        for email in parsed.get("emails", []):
            text_without_emails = text_without_emails.replace(email, " ")
        for domain in parsed.get("domains", [])[: self.limits[EntityType.DOMAIN]]:
            cleaned = _clean_domain(domain)
            if not cleaned or cleaned in _COMMON_EMAIL_DOMAINS:
                continue
            # Require an explicit mention outside any email address: prevents
            # e-mail local-parts (elvin.s.tashkin.std) being misread as domains.
            if not re.search(
                    r"(?<![\w@.-])" + re.escape(cleaned) + r"(?![\w.-])",
                    text_without_emails, re.IGNORECASE):
                continue
            add(EntityType.DOMAIN, cleaned, source="free_text", field_name="domains",
                confidence=0.80)
        # A custom/institutional mail domain from an email seed is a first-class
        # seed-wave DOMAIN entity (domain collectors must be scheduled), but it is
        # tagged EMAIL_DERIVED_DOMAIN so it never auto-locks scope. Freemail
        # providers are intentionally excluded.
        email_values = [clue.value for clue in clues
                        if clue.entity_type == EntityType.EMAIL]
        for email_value in email_values:
            if "@" not in email_value or is_noreply_email(email_value):
                continue
            mail_domain = _clean_domain(email_value.split("@", 1)[1])
            if (not mail_domain or mail_domain in _FREEMAIL_DOMAINS
                    or is_provider_infrastructure_domain(mail_domain)):
                continue
            add(EntityType.DOMAIN, mail_domain, source="email_derived",
                field_name="domains", confidence=0.80,
                metadata={"derived_from_email": email_value},
                provenance=EMAIL_DERIVED_DOMAIN)
        # A personal local-part is a high-signal seed handle (but never a role
        # mailbox): promote it into the primary seed wave, not hypotheses.
        for email_value in email_values:
            local_username = _email_derived_username(email_value)
            if not local_username:
                continue
            add(EntityType.USERNAME, local_username, source="email_derived",
                field_name="usernames", confidence=0.64,
                metadata={"derived_from_email": email_value,
                          "derived_confidence": 0.64, "confidence": 0.64},
                provenance=EMAIL_DERIVED_USERNAME)

        # Candidate IPs: token-based so compressed IPv6 (`::`) is handled.
        for token in re.findall(r"[0-9A-Fa-f:.]{3,}", text):
            token = token.strip(".,;:()[]{}<>\"'")
            cleaned = _valid_ip(token)
            if cleaned:
                add(EntityType.IP, cleaned, source="free_text", field_name="ips",
                    confidence=0.75)

        # Persons: explicit structured name is authoritative. Never mine partial
        # prose tokens ("Ali" from "Aliyev"/"Ali Neft Məktəbi") alongside it.
        if not structured_person:
            for match in _PERSON_CUE_RE.finditer(text):
                candidate = _title_sequence(match.group(1))
                if candidate and (not person_first_names
                                  or candidate.lower().split()[0] in person_first_names
                                  or _is_person_like(candidate)):
                    add(EntityType.PERSON, candidate, source="free_text",
                        field_name="name", confidence=0.85)
            for person in parsed.get("persons", [])[: self.limits[EntityType.PERSON]]:
                add(EntityType.PERSON, person["name"], source="free_text",
                    field_name="name", confidence=0.80)
            if not any(clue.entity_type == EntityType.PERSON for clue in clues):
                # A bare "Elvin Taşkin" (no cue words) is still a PERSON subject.
                match = _TITLE_PERSON_RE.match(text.strip())
                if match:
                    candidate = _title_sequence(match.group(1))
                    if candidate and _is_person_like(candidate):
                        add(EntityType.PERSON, candidate, source="free_text",
                            field_name="name", confidence=0.75)

        # Organizations and locations via cue phrases; comma/semicolon lists in
        # free text ("works at acme, techuni, laborg") split into distinct clues.
        for match in _ORG_CUE_RE.finditer(text):
            raw_candidate = _clean_org(_title_sequence(match.group(1)))
            for candidate in re.split(r"[,;\n]+", raw_candidate):
                candidate = _clean_org(candidate)
                if candidate and _is_org_like(candidate):
                    add(EntityType.ORGANIZATION, candidate, source="free_text",
                        field_name="organizations", confidence=0.75)
        for match in _LOCATION_CUE_RE.finditer(text):
            raw_candidate = _title_sequence(match.group(1))
            for candidate in _expand_location_values(raw_candidate):
                candidate = _clean_person(candidate)
                if not candidate or not _is_org_like(candidate):
                    continue
                if any(candidate.lower() == clue.value.lower()
                       for clue in clues
                       if clue.entity_type == EntityType.ORGANIZATION):
                    continue
                add(EntityType.LOCATION, candidate, source="free_text",
                    field_name="locations", confidence=0.70)

        # Usernames: ONLY explicit @handles, cue labels, u/<handle>, or social
        # profile URL paths. Bare prose tokens (2nd, 18, c2, sha256, …) are not
        # handles; Phase 14's dotted-handle fallback is intentionally gone.
        excluded_username_tokens = set(_RELATION_ORGS) | set(_STOPWORDS)
        for address in parsed.get("emails", []):
            excluded_username_tokens.update({
                address.lower(), address.split("@", 1)[0].lower(),
                address.split("@", 1)[-1].lower(),
            })
        excluded_username_tokens.update(email_domains)
        excluded_username_tokens.update(_COMMON_EMAIL_DOMAINS)
        for candidate in _cue_username_values(text, excluded_username_tokens):
            add(EntityType.USERNAME, candidate, source="free_text",
                field_name="usernames", confidence=0.80)
        for handle in _AT_HANDLE_RE.findall(text):
            candidate = _valid_handle_literal(handle)
            if candidate and candidate not in excluded_username_tokens:
                add(EntityType.USERNAME, candidate, source="free_text",
                    field_name="usernames", confidence=0.85)
        for url in extract_urls(text):
            candidate = _profile_url_username(url)
            if candidate and candidate not in excluded_username_tokens:
                add(EntityType.USERNAME, candidate, source="free_text",
                    field_name="usernames", confidence=0.75)

        # A raw input that is exactly one bare handle (e.g. `investigate
        # hamid091`) remains a valid target; a prose sentence never is.
        if not any(clue.entity_type == EntityType.USERNAME for clue in clues):
            stripped = text.strip()
            if re.fullmatch(r"@?[A-Za-z0-9][A-Za-z0-9._\-]{1,63}", stripped):
                candidate = _valid_handle_literal(stripped)
                if (candidate and candidate not in _STANDALONE_PROSE_TERMS
                        and not any(candidate == clue.value.lower()
                                    for clue in clues)):
                    add(EntityType.USERNAME, candidate, source="free_text",
                        field_name="fallback", confidence=0.50)

        return self._bounded(clues)

    # ── helpers ────────────────────────────────────────────────────
    def _bounded(self, clues: list[SeedClue]) -> list[SeedClue]:
        counts: dict[EntityType, int] = {}
        bounded: list[SeedClue] = []
        for clue in clues:
            limit = self.limits.get(clue.entity_type, 10)
            if counts.get(clue.entity_type, 0) >= limit:
                continue
            counts[clue.entity_type] = counts.get(clue.entity_type, 0) + 1
            bounded.append(clue)
        return bounded

    def seed_candidates(self, raw_input: str,
                        structured: Optional["StructuredSeeds | dict[str, Any]"] = None
                        ) -> list[EntityCandidate]:
        """EntityCandidates ready for ERKG seed ingestion (with provenance)."""
        return [clue.to_candidate() for clue in self.extract(raw_input, structured)]

    def primary_person_name(self, raw_input: str,
                            structured: Optional["StructuredSeeds | dict[str, Any]"] = None
                            ) -> Optional[str]:
        fields = (structured if isinstance(structured, StructuredSeeds)
                  else StructuredSeeds.from_mapping(structured))
        if fields.name:
            return _clean_person(fields.name)
        clues = self.extract(raw_input, fields)
        for clue in clues:
            if clue.entity_type == EntityType.PERSON:
                return clue.value
        return None

    # ── bounded hypothesis generation ─────────────────────────────
    def hypothesis_drafts(self, raw_input: str,
                          structured: Optional["StructuredSeeds | dict[str, Any]"] = None,
                          *, max_usernames: int = MAX_HYPOTHESIS_USERNAMES,
                          max_emails: int = MAX_HYPOTHESIS_EMAILS
                          ) -> list["HypothesisDraft"]:
        """High-precision, deterministic handle/email hypotheses.

        Rules (Phase 11):
        * transliterate diacritics with digraph + ASCII variants (``Taşkin`` ->
          ``tashkin``/``taskin``; never ``takin``);
        * refuse stopword fragments and single-first-name generic emails
          (never ``elvin@gmail.com`` / ``elvin_in``);
        * usernames combine first + surname (max 6), emails require both parts
          (max 4); known surname tokens are mined from seed email local-parts.
        """
        fields = (structured if isinstance(structured, StructuredSeeds)
                  else StructuredSeeds.from_mapping(structured))
        clues = self.extract(raw_input, fields)
        persons = [clue.value for clue in clues if clue.entity_type == EntityType.PERSON]
        if not persons:
            # The bounded permutation engine only fires for a named PERSON subject.
            return []
        domains = [clue.value for clue in clues if clue.entity_type == EntityType.DOMAIN]
        known_usernames = {clue.value.lower() for clue in clues
                           if clue.entity_type == EntityType.USERNAME}
        known_emails = {clue.value.lower() for clue in clues
                        if clue.entity_type == EntityType.EMAIL}
        first_name_tokens = {
            transliteration_variants(part)[0]
            for person in persons
            for part in str(person).split()[:1]
            if part
        }
        known_surnames = _surname_tokens_from_emails(known_emails, first_name_tokens)
        # Tiny suffix set that commonly appears in e-mail local-parts but is not
        # a surname; never use these to construct hypotheses.
        known_surnames = [token for token in known_surnames
                          if token not in {"std", "stu", "student", "uni", "edu",
                                           "mail", "email", "info", "contact",
                                           "official", "admin", "user"}]

        drafts: list[HypothesisDraft] = []
        seen: set[tuple[str, str]] = set()

        def add_draft(draft: HypothesisDraft) -> None:
            key = (draft.entity_type.value, draft.value.lower())
            if key in seen:
                return
            limit = max_usernames if draft.entity_type == EntityType.USERNAME else max_emails
            current = sum(1 for existing in drafts
                          if existing.entity_type == draft.entity_type)
            if current >= limit:
                return
            seen.add(key)
            drafts.append(draft)

        # ── ordered name variants (digraph first, ASCII fallback second) ──
        name_variants: list[tuple[list[str], list[str]]] = []
        for person in persons[:2]:
            parts = [part for part in re.split(r"\s+", person.strip()) if part]
            if not parts:
                continue
            first_variants = transliteration_variants(parts[0], max_variants=4)[:2]
            last_variants = (transliteration_variants(parts[-1], max_variants=4)[:3]
                             if len(parts) > 1 else [])
            surname_options = list(last_variants)
            for surname in known_surnames:
                if surname not in surname_options:
                    surname_options.append(surname)
            if not first_variants and parts[0]:
                first_variants = [re.sub(r"[^a-z0-9]", "", parts[0].lower())]
            name_variants.append((first_variants, surname_options))

        # ── usernames: high-precision first+surname combinations (max 6) ──
        usernames: list[str] = []
        for first_variants, surname_options in name_variants:
            if not surname_options:
                # Single-name subjects only get their cleaned name as a handle.
                usernames.extend(first_variants[:2])
                continue
            for first in first_variants[:2]:
                for surname in surname_options[:3]:
                    if not first or not surname:
                        continue
                    # Never concatenate overlapping tokens (kamran +
                    # kamranmammadov01) into doubled handles.
                    if first in surname or surname in first:
                        continue
                    usernames.extend([
                        f"{first}.{surname}",
                        f"{first}_{surname}",
                        f"{first}{surname}",
                    ])
                # Explicit surname-only handle keeps the strongest known token.
                usernames.append(surname_options[0])
        # Supplied handles may contribute sanitized dot/underscore variants only.
        for handle in sorted(known_usernames):
            base = re.sub(r"[^a-z0-9._\-]", "", handle.lower())
            if len(base) < 3 or base in known_usernames:
                continue
            usernames.append(base.replace(".", "_"))
            usernames.append(base.replace("_", "."))

        for username in usernames:
            candidate = username.strip().lstrip("@").lower()
            if not re.fullmatch(r"[a-z0-9][a-z0-9._\-]{2,29}", candidate):
                continue
            if candidate in known_usernames or not _handle_is_clean(candidate):
                continue
            # Dot-separated name handles (elvin.tashkin) look like hostnames but
            # are valid usernames; only skip values that are actual seed domains.
            if candidate in domains:
                continue
            add_draft(HypothesisDraft(
                entity_type=EntityType.USERNAME,
                value=candidate,
                confidence=0.30,
                generator="username_permutation",
                rationale=("Name-derived high-precision handle (transliterated)"
                           " from user-provided subject"),
            ))

        # ── emails: first+surname only (max 4), never single-first-name ──
        email_domains: list[str] = []
        for domain in domains:
            cleaned = _clean_domain(domain)
            if cleaned and cleaned not in email_domains:
                email_domains.append(cleaned)
        for email in sorted(known_emails):
            if "@" not in email:
                continue
            domain = _clean_domain(email.split("@", 1)[1])
            if domain and domain not in email_domains:
                email_domains.append(domain)
        email_domains = email_domains[:4]
        used_common_providers = not email_domains
        if used_common_providers:
            email_domains = ["gmail.com", "outlook.com", "protonmail.com"]
        local_parts: list[str] = []
        for first_variants, surname_options in name_variants:
            if not surname_options:
                continue
            first = first_variants[0] if first_variants else ""
            if not first:
                continue
            # Dot-separated primary + ASCII variants first so the 4-email cap
            # always contains both "tashkin" and "taskin" transliterations.
            for surname in surname_options[:2]:
                if first and surname and first not in surname and surname not in first:
                    local_parts.append(f"{first}.{surname}")
            for surname in surname_options[:2]:
                if not first or not surname or first in surname or surname in first:
                    continue
                local_parts.extend([
                    f"{first}{surname}",
                    f"{first}_{surname}",
                    f"{first[0]}.{surname}",
                ])
        for index, local in enumerate(local_parts):
            local_clean = re.sub(r"[^a-z0-9._\-]", "", local)
            if len(local_clean) < 3 or not _handle_is_clean(local_clean):
                continue
            domain = email_domains[index % len(email_domains)]
            email = f"{local_clean}@{domain}"
            if email in known_emails:
                continue
            add_draft(HypothesisDraft(
                entity_type=EntityType.EMAIL,
                value=email,
                confidence=0.28 if used_common_providers else 0.30,
                generator="email_permutation",
                rationale=("High-precision first+surname email hypothesis"
                           + (" (common provider)" if used_common_providers else "")),
            ))

        return drafts


@dataclass
class HypothesisDraft:
    """A bounded, deterministic hypothesis entity for the pivot engine."""

    entity_type: EntityType
    value: str
    confidence: float = 0.30
    generator: str = "intake"
    rationale: str = ""

    def __post_init__(self) -> None:
        self.confidence = min(MAX_HYPOTHESIS_CONFIDENCE, max(0.05, self.confidence))


def _default_confidence(entity_type: EntityType) -> float:
    return {
        EntityType.PERSON: 0.85,
        EntityType.EMAIL: 0.85,
        EntityType.USERNAME: 0.80,
        EntityType.DOMAIN: 0.80,
        EntityType.SUBDOMAIN: 0.80,
        EntityType.PHONE: 0.80,
        EntityType.ORGANIZATION: 0.75,
        EntityType.LOCATION: 0.70,
        EntityType.URL: 0.80,
        EntityType.IP: 0.80,
    }.get(entity_type, 0.75)


def _clean_domain(value: str) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    text = text.split("/")[0].split("?")[0].split("#")[0]
    text = text.split(":")[0].lstrip("@").rstrip(".")
    text = re.sub(r"^www\.", "", text)
    return text if _HOST_CANDIDATE_RE.match(text) else ""


def _clean_phone(value: str, *, az_context: bool = False) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) < 7:
        return ""
    return _normalise_phone_number(value, az_context=az_context)


__all__ = [
    "USER_PROVIDED_SEED",
    "EMAIL_DERIVED_DOMAIN",
    "EMAIL_DERIVED_USERNAME",
    "SeedClue",
    "StructuredSeeds",
    "HypothesisDraft",
    "MultiClueIntake",
    "MAX_HYPOTHESIS_CONFIDENCE",
]
