"""Entity resolution — canonicalization, alias merging and derivation.

Every raw string produced by a parser (or by the user seed) is canonicalized
per entity type, given a deterministic canonical entity id, and merged into an
existing entity when any alias matches. Original raw strings are always
preserved on the entity (`raw_values`) while aliases stay queryable.

`derive_entity_drafts` also decomposes composite evidence into the ERKG entity
types required by the spec: a bare ``sub.example.com`` host yields a
``Subdomain`` node plus its parent ``Domain``; an email yields its mail
``Domain``; a social profile URL yields a ``SocialProfile`` plus ``Username``;
a GitHub repository URL yields a ``Repository`` instead of a generic URL.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from hub.models import EdgeType, Entity, EntityType, sha256_text

# ── Public suffix subset used to decide Domain vs Subdomain ─────────────
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "co.in",
    "com.cn", "com.tr", "com.az", "co.az", "com.ua", "co.za", "com.sg",
    "com.hk", "co.kr", "com.mx", "com.ar", "com.co", "com.pl",
}
#: Second-level country-code suffixes for any 2-letter ccTLD (edu.az, ac.uk…).
_CC_SECOND_LEVEL_LABELS = {
    "edu", "ac", "gov", "org", "com", "net", "co", "mil", "int",
}
#: Filename/code extensions that must never become DOMAIN/SUBDOMAIN entities.
_FILE_EXTENSIONS = {
    "yaml", "yml", "json", "xml", "txt", "md", "py", "exe", "dll", "conf",
    "ini", "cfg", "sqlite", "sqlite3", "db", "log", "html", "htm", "js",
    "css", "png", "jpg", "jpeg", "gif", "svg", "pdf", "csv", "tsv", "sh",
    "bat", "ps1", "toml", "lock",
}


def _is_multi_label_suffix(labels: list[str]) -> bool:
    if len(labels) < 2:
        return False
    suffix = ".".join(labels[-2:]).lower()
    if suffix in _MULTI_LABEL_SUFFIXES:
        return True
    first, last = labels[-2].lower(), labels[-1].lower()
    return (first in _CC_SECOND_LEVEL_LABELS and len(last) == 2
            and last.isalpha())


def _has_file_extension(host: str) -> bool:
    if "." not in host:
        return False
    return host.rsplit(".", 1)[-1].lower() in _FILE_EXTENSIONS
_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "yclid", "mc_cid", "mc_eid", "igshid", "si",
    "ref", "ref_src", "ref_url", "share", "share_id", "__twitter_impression",
    "s", "t", "trk", "trkinfo", "spm", "from",
}
_SOCIAL_PLATFORMS: dict[str, str] = {
    "github.com": "github", "gitlab.com": "gitlab", "bitbucket.org": "bitbucket",
    "twitter.com": "twitter", "x.com": "twitter", "instagram.com": "instagram",
    "facebook.com": "facebook", "fb.com": "facebook", "reddit.com": "reddit",
    "linkedin.com": "linkedin", "youtube.com": "youtube", "tiktok.com": "tiktok",
    "chess.com": "chess", "spotify.com": "spotify", "medium.com": "medium",
    "t.me": "telegram", "telegram.me": "telegram", "pinterest.com": "pinterest",
    "twitch.tv": "twitch", "steamcommunity.com": "steam", "keybase.io": "keybase",
}
_REPO_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# ════════════════════════════════════════════════════════════════════════
# Drafts produced before persistence
# ════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class EntityDraft:
    entity_type: EntityType
    raw_value: str
    canonical_value: str
    display_value: str
    aliases: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    derived_from: str = ""

    @property
    def alias_keys(self) -> list[str]:
        return alias_keys_for(self.entity_type, self.raw_value, self.canonical_value,
                             self.aliases)


@dataclass(frozen=True)
class RelationDraft:
    subject_type: EntityType
    subject_raw: str
    predicate: EdgeType
    object_type: EntityType
    object_raw: str
    metadata: dict[str, Any] = field(default_factory=dict)


# ════════════════════════════════════════════════════════════════════════
# Low-level normalizers
# ════════════════════════════════════════════════════════════════════════

def _nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text or "")


def _clean_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _idna_domain(domain: str) -> str:
    """Punycode-normalize a domain (best effort; returns lowercased fallback)."""
    domain = domain.strip().lower().strip(".")
    if not domain or domain.isascii():
        return domain
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return domain


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _hostname_from_url_like(value: str) -> tuple[str, str, str]:
    """Return (scheme, host, path) for a URL-like or bare host string."""
    text = value.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", text):
        text = "//" + text.lstrip("/")
    try:
        parts = urlsplit(text)
        return parts.scheme.lower(), (parts.hostname or ""), parts.path
    except ValueError:
        # Malformed URL (e.g. broken IPv6 bracket) — caller falls back to raw text.
        return "", "", ""


def normalize_email(value: str) -> str:
    text = _nfkc(value).strip().strip(".,;:<>()[]\"'")
    if text.lower().startswith("mailto:"):
        text = text[7:]
    if "@" not in text:
        return text.lower()
    local, _, domain = text.partition("@")
    return f"{local.lower()}@{normalize_domain(domain)}"


def normalize_domain(value: str) -> str:
    text = _nfkc(value).strip().strip(".,;:<>()[]\"'")
    if not text or "," in text:
        return text.lower()
    _, host, _ = _hostname_from_url_like(text)
    host = _idna_domain((host or text).split("@")[-1])
    host = _strip_www(host).rstrip(".")
    if not host or _has_file_extension(host):
        return ""
    return host


def normalize_url(value: str) -> str:
    text = _nfkc(value).strip().strip("<>\"'")
    if not text:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", text):
        text = "https://" + text.lstrip("/")
    try:
        parts = urlsplit(text)
    except ValueError:
        return value.strip().lower()
    scheme = (parts.scheme or "https").lower()
    host = _strip_www(_idna_domain(parts.hostname or ""))
    port = ""
    if parts.port and not ((scheme == "https" and parts.port == 443)
                          or (scheme == "http" and parts.port == 80)):
        port = f":{parts.port}"
    path = parts.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query_pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                   if k.lower() not in _TRACKING_PARAMS
                   and not k.lower().startswith("utm_")]
    query = urlencode(sorted(query_pairs))
    return urlunsplit((scheme, host + port, path, query, ""))


#: Generic URL-path-ish slugs that must never be persisted as USERNAME entities.
_USERNAME_BLOCKLIST = frozenset({
    "about", "search", "profile", "profiles", "user", "users", "login",
    "signup", "signin", "explore", "home", "settings", "help", "contact",
    "search-by-username", "profil", "feed", "share", "intent",
    "members", "member", "account", "accounts", "register",
})
USERNAME_BLOCKLIST = _USERNAME_BLOCKLIST
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]{1,63}$", re.IGNORECASE)

#: Public freemail, relay, and synthetic noreply provider domains.
#: Never count these as target-owned infrastructure or inflate confidence.
PROVIDER_INFRASTRUCTURE_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me", "aol.com", "gmx.com", "gmx.net",
    "mail.com", "yandex.ru", "yandex.com", "mail.ru", "inbox.ru", "list.ru",
    "bk.ru", "qq.com", "163.com", "126.com", "users.noreply.github.com",
    "noreply.github.com", "privaterelay.appleid.com", "mozmail.com",
    "duck.com", "anonaddy.me", "simplelogin.com",
})


def is_noreply_email(value: str) -> bool:
    """True for synthetic/noreply email addresses (e.g. *@users.noreply.github.com)."""
    addr = normalize_email(value)
    if "@" not in addr:
        return False
    local, _, domain = addr.partition("@")
    if domain in {"users.noreply.github.com", "noreply.github.com"} or domain.endswith(".noreply.github.com"):
        return True
    if domain.startswith(("noreply.", "no-reply.")):
        return True
    if local in {"noreply", "no-reply", "donotreply", "do-not-reply"}:
        return True
    if local.startswith(("noreply+", "noreply.", "noreply-", "no-reply+", "no-reply.", "no-reply-")):
        return True
    if "+noreply" in local:
        return True
    return False


def is_provider_infrastructure_domain(host: str) -> bool:
    """True for public freemail, relay, or noreply provider infrastructure hosts."""
    norm = normalize_domain(host)
    if not norm:
        return False
    if norm in PROVIDER_INFRASTRUCTURE_DOMAINS:
        return True
    return (
        norm.startswith(("noreply.", "no-reply."))
        or norm.endswith(".noreply.github.com")
    )


def is_valid_username(value: str) -> bool:
    """True only for a handle-shaped value (never e-mail/URL/generic slug)."""
    text = _clean_ws(str(value or "")).strip().lstrip("@").lower()
    if not text or "@" in text or "/" in text or "\\" in text or " " in text:
        return False
    if text in _USERNAME_BLOCKLIST or "search-by-username" in text:
        return False
    return bool(_USERNAME_RE.fullmatch(text))


def normalize_username(value: str) -> str:
    text = _nfkc(value).strip()
    url_match = re.search(
        r"^(?:https?://)?(?:www\.)?"
        r"(github|gitlab|bitbucket|twitter|x|instagram|facebook|reddit|linkedin|"
        r"youtube|tiktok|chess|spotify|medium|pinterest|twitch)\.(?:com|org|tv|io|me)"
        r"/(?:in/|u(?:ser)?/|@|member/|user/)?([A-Za-z0-9_.\-]+)",
        text, re.IGNORECASE)
    if url_match:
        text = url_match.group(2)
    candidate = _clean_ws(text).strip().lstrip("@").lower()
    # Global invariant: an e-mail address (or URL/path) is never a username.
    return candidate if is_valid_username(candidate) else ""


def normalize_phone(value: str) -> str:
    text = _nfkc(value).strip()
    has_plus = text.startswith("+")
    digits = re.sub(r"\D", "", text)
    if not digits:
        return text.lower()
    if has_plus:
        return f"+{digits}"
    # Generic international prefix 00...
    if text.startswith("00") and len(digits) > 2:
        return f"+{digits[2:]}"
    # Local Azerbaijani 10-digit mobile numbers (050/051/055/070/077/099/010).
    if len(digits) == 10 and digits[:3] in {
            "050", "051", "055", "070", "077", "099", "010"}:
        return f"+994{digits[1:]}"
    return digits


def normalize_person(value: str) -> str:
    text = _clean_ws(_nfkc(value)).lower()
    return text.strip(" .,;:'\"()[]-")


def normalize_organization(value: str) -> str:
    return normalize_person(value)


def normalize_ip(value: str) -> str:
    text = _nfkc(value).strip().strip("[]")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


def normalize_asn(value: str) -> str:
    text = _nfkc(value).strip().upper()
    if text.startswith("AS"):
        digits = re.sub(r"[^0-9]", "", text)
        return f"AS{digits}" if digits else text
    digits = re.sub(r"[^0-9]", "", text)
    return f"AS{digits}" if digits else text


def normalize_repository(value: str) -> str:
    text = _nfkc(value).strip()
    if "/" in text and not re.match(r"^[a-zA-Z][\w+.\-]*://", text):
        return text.lower().strip("/")
    _, host, path = _hostname_from_url_like(text)
    host = _strip_www((host or "").lower())
    path = path.strip("/")
    path = re.sub(r"\.git$", "", path, flags=re.IGNORECASE)
    return f"{host}/{path}".rstrip("/").lower()


def normalize_social_profile(value: str) -> str:
    text = _nfkc(value).strip()
    if "://" in text or text.count("/") >= 1:
        _, host, path = _hostname_from_url_like(text)
        host = _strip_www((host or "").lower())
        platform = _SOCIAL_PLATFORMS.get(host, host)
        segments = [seg for seg in path.split("/") if seg]
        if segments:
            handle = segments[-1].lstrip("@").lower()
            return f"{platform}/{handle}"
        return platform
    return text.lower()


def normalize_breach_record(value: str) -> str:
    text = _clean_ws(_nfkc(value)).lower()
    text = re.sub(r"^(?:breach|leak|database)\s*:?\s*", "", text)
    return text.strip(" .,;:'\"")


def normalize_crypto_address(value: str) -> str:
    text = _nfkc(value).strip()
    if text.lower().startswith("0x"):
        return text.lower()
    return text


def normalize_hash(value: str) -> str:
    return _nfkc(value).strip().lower()


def normalize_service(value: str) -> str:
    text = _clean_ws(_nfkc(value)).lower()
    text = re.sub(r"^https?://", "", text)
    return _strip_www(text.rstrip("/"))


def normalize_port(value: str) -> str:
    text = _nfkc(value).strip().lower()
    m = re.match(r"^(\d{1,5})(?:/(\w+))?$", text)
    if m:
        port = int(m.group(1))
        proto = m.group(2) or ""
        return f"{port}/{proto}" if proto else str(port)
    return text


def normalize_location(value: str) -> str:
    return normalize_person(value)


def normalize_credential(value: str) -> str:
    return _nfkc(value).strip()


_NORMALIZERS = {
    EntityType.PERSON: normalize_person,
    EntityType.USERNAME: normalize_username,
    EntityType.EMAIL: normalize_email,
    EntityType.DOMAIN: normalize_domain,
    EntityType.SUBDOMAIN: normalize_domain,
    EntityType.IP: normalize_ip,
    EntityType.ASN: normalize_asn,
    EntityType.ORGANIZATION: normalize_organization,
    EntityType.PHONE: normalize_phone,
    EntityType.REPOSITORY: normalize_repository,
    EntityType.SOCIAL_PROFILE: normalize_social_profile,
    EntityType.BREACH_RECORD: normalize_breach_record,
    EntityType.CRYPTO_ADDRESS: normalize_crypto_address,
    EntityType.SERVICE: normalize_service,
    EntityType.CREDENTIAL: normalize_credential,
    EntityType.HASH: normalize_hash,
    EntityType.PORT: normalize_port,
    EntityType.LOCATION: normalize_location,
    EntityType.URL: normalize_url,
}


def normalize_value(entity_type: EntityType | str, raw_value: str) -> str:
    etype = EntityType.coerce(entity_type)
    return _NORMALIZERS[etype](str(raw_value))


# ════════════════════════════════════════════════════════════════════════
# Hostname classification
# ════════════════════════════════════════════════════════════════════════

def split_hostname(hostname: str) -> Optional[tuple[str, str, bool]]:
    """Return (host, registrable_domain, is_subdomain) or None for IP/invalid."""
    host = normalize_domain(hostname)
    if not host or " " in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if "." not in host:
        return None
    labels = host.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None
    suffix_len = 2 if _is_multi_label_suffix(labels) else 1
    if len(labels) <= suffix_len + 1:
        return host, host, False
    registrable = ".".join(labels[-(suffix_len + 1):])
    return host, registrable, host != registrable


def parent_domain(hostname: str) -> Optional[str]:
    parts = split_hostname(hostname)
    if parts is None:
        return None
    host, registrable, is_sub = parts
    if not is_sub:
        return None
    return registrable


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified)


# ════════════════════════════════════════════════════════════════════════
# Canonical ids / alias keys
# ════════════════════════════════════════════════════════════════════════

def canonical_entity_id(entity_type: EntityType | str, canonical_value: str) -> str:
    etype = EntityType.coerce(entity_type)
    return f"{etype.value}:{sha256_text(f'{etype.value}|{canonical_value}')[:16]}"


def alias_keys_for(entity_type: EntityType | str, raw_value: str,
                   canonical_value: str,
                   extra_aliases: Iterable[str] = ()) -> list[str]:
    etype = EntityType.coerce(entity_type)
    aliases: set[str] = {canonical_value}
    raw = str(raw_value or "").strip()
    if raw:
        aliases.add(raw.lower())
        lowered = raw.lower()
        if lowered.startswith("http"):
            url = normalize_url(raw)
            aliases.add(url)
            aliases.add(url.rstrip("/"))
        aliases.add(raw)
    for alias in extra_aliases:
        if alias:
            aliases.add(str(alias).strip())
            aliases.add(str(alias).strip().lower())
    keys = [f"{etype.value}:{a}" for a in aliases if a]
    return sorted(set(keys))


# ════════════════════════════════════════════════════════════════════════
# Derivation (one raw candidate -> ERKG nodes + relations)
# ════════════════════════════════════════════════════════════════════════

def _draft(entity_type: EntityType, raw_value: str, *,
           metadata: Optional[dict[str, Any]] = None,
           aliases: Optional[list[str]] = None,
           derived_from: str = "") -> EntityDraft:
    canonical = normalize_value(entity_type, raw_value)
    return EntityDraft(
        entity_type=entity_type,
        raw_value=str(raw_value),
        canonical_value=canonical,
        display_value=str(raw_value).strip(),
        aliases=list(aliases or []),
        metadata=dict(metadata or {}),
        derived_from=derived_from,
    )


def _classify_url_entity(raw: str, metadata: dict[str, Any]) -> EntityDraft:
    """Turn a URL into the most specific canonical entity type it represents."""
    url = normalize_url(raw)
    parts = urlsplit(url)
    host = _strip_www((parts.hostname or "").lower())
    segments = [seg for seg in parts.path.split("/") if seg]
    if host in _REPO_HOSTS and len(segments) >= 2:
        repo = f"{host}/{segments[0]}/{segments[1]}"
        repo = re.sub(r"\.git$", "", repo, flags=re.IGNORECASE)
        base_meta = dict(metadata)
        base_meta["url"] = url
        return _draft(EntityType.REPOSITORY, repo, metadata=base_meta, derived_from=raw)
    if host in _SOCIAL_PLATFORMS and segments:
        handle = segments[-1].lstrip("@")
        profile = _draft(EntityType.SOCIAL_PROFILE, url, metadata=dict(metadata),
                         derived_from=raw)
        profile.metadata.setdefault("platform", _SOCIAL_PLATFORMS[host])
        profile.metadata.setdefault("handle", handle)
        return profile
    return _draft(EntityType.URL, raw, metadata=metadata)


def derive_entity_drafts(entity_type: EntityType | str, raw_value: str,
                         metadata: Optional[dict[str, Any]] = None,
                         aliases: Optional[list[str]] = None
                         ) -> tuple[list[EntityDraft], list[RelationDraft]]:
    """Expand one raw entity into ERKG drafts plus derived node/relation drafts.

    Always returns the primary draft first. Never raises; unparsable values fall
    back to a normalized single draft.
    """
    etype = EntityType.coerce(entity_type)
    raw = str(raw_value or "").strip()
    metadata = dict(metadata or {})
    aliases = list(aliases or [])
    drafts: list[EntityDraft] = []
    relations: list[RelationDraft] = []

    try:
        # ── URLs may be repositories / social profiles / plain URLs ──
        if etype == EntityType.URL:
            primary = _classify_url_entity(raw, metadata)
            drafts.append(primary)
            if primary.entity_type == EntityType.REPOSITORY:
                host = primary.canonical_value.split("/", 1)[0]
                drafts.append(_draft(EntityType.DOMAIN, host, derived_from=raw,
                                     metadata={"role": "repository_host",
                                               "provider_infrastructure": True}))
                relations.append(RelationDraft(
                    primary.entity_type, primary.raw_value, EdgeType.FOUND_IN,
                    EntityType.DOMAIN, host, {"role": "repository_host"}))
            elif primary.entity_type == EntityType.SOCIAL_PROFILE:
                handle = primary.metadata.get("handle") or ""
                if handle:
                    drafts.append(_draft(EntityType.USERNAME, handle, derived_from=raw,
                                         metadata={"role": "profile_handle"}))
                    relations.append(RelationDraft(
                        EntityType.SOCIAL_PROFILE, raw, EdgeType.HAS_USERNAME,
                        EntityType.USERNAME, handle, {"role": "profile_handle"}))
            return drafts, relations

        # ── Hostnames: classify Domain vs Subdomain, derive the parent ──
        if etype in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
            parts = split_hostname(raw)
            if parts is None:
                # File/config names (proxies.yaml, keys.json…) are never hostnames.
                if normalize_domain(raw):
                    meta = dict(metadata)
                    if is_provider_infrastructure_domain(raw):
                        meta["provider_infrastructure"] = True
                    drafts.append(_draft(EntityType.DOMAIN, raw, metadata=meta))
                return drafts, relations
            host, registrable, is_sub = parts
            if etype == EntityType.SUBDOMAIN and not is_sub:
                etype = EntityType.DOMAIN
            primary_type = EntityType.SUBDOMAIN if (is_sub or etype == EntityType.SUBDOMAIN) else EntityType.DOMAIN
            if etype == EntityType.DOMAIN and is_sub:
                # amass/theHarvester report subdomains as domains; split them.
                primary_type = EntityType.SUBDOMAIN
            primary_meta = dict(metadata)
            if is_provider_infrastructure_domain(host):
                primary_meta["provider_infrastructure"] = True
                if host.startswith(("noreply.", "no-reply.")) or host.endswith(".noreply.github.com"):
                    primary_meta["is_noreply"] = True
            primary = _draft(primary_type, raw, metadata=primary_meta, aliases=aliases)
            drafts.append(primary)
            if is_sub:
                parent_meta: dict[str, Any] = {"role": "registrable_parent"}
                if is_provider_infrastructure_domain(registrable):
                    parent_meta["provider_infrastructure"] = True
                parent = _draft(EntityType.DOMAIN, registrable, derived_from=raw,
                                metadata=parent_meta)
                drafts.append(parent)
                relations.append(RelationDraft(
                    primary_type, raw, EdgeType.SUBDOMAIN_OF,
                    EntityType.DOMAIN, registrable, {"role": "registrable_parent"}))
            else:
                # Ensure hostname is canonical (strip www) even for plain domains.
                drafts[0] = _draft(EntityType.DOMAIN, registrable if not is_sub else raw,
                                   metadata=primary_meta, aliases=aliases)
            return drafts, relations

        # ── Email: derive the mail domain (respecting subdomain vs domain) ──
        if etype == EntityType.EMAIL:
            norm_email = normalize_email(raw)
            email_meta = dict(metadata)
            noreply = is_noreply_email(norm_email)
            if noreply:
                email_meta["is_noreply"] = True
                email_meta["provider_infrastructure"] = True
            if not _EMAIL_RE.match(norm_email):
                drafts.append(_draft(EntityType.EMAIL, raw, metadata=email_meta,
                                     aliases=aliases))
                return drafts, relations
            primary = _draft(EntityType.EMAIL, raw, metadata=email_meta, aliases=aliases)
            drafts.append(primary)
            domain = primary.canonical_value.split("@", 1)[1]
            domain_meta: dict[str, Any] = {"role": "mail_domain"}
            if noreply or is_provider_infrastructure_domain(domain):
                domain_meta["provider_infrastructure"] = True
            if noreply:
                domain_meta["is_noreply"] = True
            host_parts = split_hostname(domain)
            if host_parts is not None:
                host, _registrable, is_sub = host_parts
                host_type = EntityType.SUBDOMAIN if is_sub else EntityType.DOMAIN
                drafts.append(_draft(host_type, host, derived_from=raw,
                                     metadata=domain_meta))
                relations.append(RelationDraft(
                    EntityType.EMAIL, raw, EdgeType.ASSOCIATED_WITH,
                    host_type, host, {"role": "mail_domain"}))
            else:
                drafts.append(_draft(EntityType.DOMAIN, domain, derived_from=raw,
                                     metadata=domain_meta))
                relations.append(RelationDraft(
                    EntityType.EMAIL, raw, EdgeType.ASSOCIATED_WITH,
                    EntityType.DOMAIN, domain, {"role": "mail_domain"}))
            return drafts, relations

        # ── Username: never persist an e-mail address/URL/generic slug ──
        if etype == EntityType.USERNAME:
            normalized = normalize_username(raw)
            if not normalized:
                return [], relations
            drafts.append(_draft(EntityType.USERNAME, normalized, metadata=metadata,
                                 aliases=aliases))
            return drafts, relations

        # ── Social profile values may be URLs or platform/handle strings ──
        if etype == EntityType.SOCIAL_PROFILE and ("://" in raw or raw.count("/") >= 1):
            profile = _draft(EntityType.SOCIAL_PROFILE, raw, metadata=metadata,
                             aliases=aliases)
            drafts.append(profile)
            handle = profile.canonical_value.split("/", 1)[-1]
            if handle and handle != profile.canonical_value:
                drafts.append(_draft(EntityType.USERNAME, handle, derived_from=raw))
                relations.append(RelationDraft(
                    EntityType.SOCIAL_PROFILE, raw, EdgeType.HAS_USERNAME,
                    EntityType.USERNAME, handle))
            return drafts, relations

        # ── Default: single normalized draft ──
        drafts.append(_draft(etype, raw, metadata=metadata, aliases=aliases))
        return drafts, relations
    except Exception:  # noqa: BLE001 - resolution must never crash a run
        fallback = _draft(etype, raw, metadata=metadata, aliases=aliases)
        return [fallback], relations


# ════════════════════════════════════════════════════════════════════════
# Resolver (persistence-aware)
# ════════════════════════════════════════════════════════════════════════

class EntityResolver:
    """Resolve raw values to persisted canonical entities via the ERKG store."""

    def __init__(self, store):
        self.store = store

    def resolve(self, investigation_id: str, entity_type: EntityType | str,
                raw_value: str, *, artifact_id: Optional[str], timestamp: str,
                metadata: Optional[dict[str, Any]] = None,
                aliases: Optional[list[str]] = None) -> tuple[Entity, bool]:
        etype = EntityType.coerce(entity_type)
        draft = _draft(etype, raw_value, metadata=metadata, aliases=aliases)
        return self.resolve_draft(investigation_id, draft, artifact_id=artifact_id,
                                  timestamp=timestamp)

    def resolve_draft(self, investigation_id: str, draft: EntityDraft, *,
                      artifact_id: Optional[str], timestamp: str) -> tuple[Entity, bool]:
        keys = draft.alias_keys
        for key in keys:
            found_id = self.store.find_entity_by_alias(investigation_id, key)
            if found_id:
                entity = self.store.get_entity(found_id)
                if entity is not None and entity.type == draft.entity_type:
                    self.store.touch_entity(
                        found_id,
                        raw_value=draft.raw_value,
                        aliases=draft.aliases,
                        alias_keys=keys,
                        timestamp=timestamp,
                        metadata=draft.metadata,
                    )
                    entity = self.store.get_entity(found_id) or entity
                    return entity, False
        entity = Entity(
            entity_id=canonical_entity_id(draft.entity_type, draft.canonical_value),
            investigation_id=investigation_id,
            type=draft.entity_type,
            canonical_value=draft.canonical_value,
            display_value=draft.display_value,
            aliases=sorted(set(draft.aliases + [draft.raw_value])),
            raw_values=[draft.raw_value],
            first_seen=timestamp,
            last_seen=timestamp,
            created_by_artifact=artifact_id,
            metadata=dict(draft.metadata),
        )
        self.store.insert_entity(investigation_id, entity, alias_keys=keys)
        return entity, True


__all__ = [
    "EntityDraft",
    "RelationDraft",
    "EntityResolver",
    "normalize_value",
    "normalize_email",
    "normalize_domain",
    "normalize_url",
    "normalize_username",
    "normalize_username",
    "normalize_phone",
    "normalize_person",
    "normalize_organization",
    "is_valid_username",
    "USERNAME_BLOCKLIST",
    "PROVIDER_INFRASTRUCTURE_DOMAINS",
    "is_noreply_email",
    "is_provider_infrastructure_domain",
    "normalize_ip",
    "normalize_asn",
    "normalize_repository",
    "normalize_social_profile",
    "normalize_breach_record",
    "normalize_crypto_address",
    "normalize_service",
    "normalize_hash",
    "normalize_port",
    "normalize_location",
    "normalize_credential",
    "canonical_entity_id",
    "alias_keys_for",
    "derive_entity_drafts",
    "split_hostname",
    "parent_domain",
    "is_public_ip",
]
