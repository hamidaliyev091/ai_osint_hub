"""Parse theHarvester stdout into the v2 ParseOutput contract.

theHarvester prints sectioned output::

    [*] Emails found: 2
    alice@example.com
    [*] Hosts found: 1
    www.example.com:93.184.216.34
    [*] IPs found: 1
    93.184.216.34
    [*] URLs found: 1
    https://www.example.com/login

Emails are related to the target domain with ``MENTIONED_IN``, hosts become
``subdomain``/``domain`` entities (``SUBDOMAIN_OF`` the target domain) and
``host:ip`` lines yield ``RESOLVES_TO`` relations.  Unsectionsed output falls
back to broad entity extraction.  Pure and deterministic.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from hub.cooking import extract_domains, extract_emails, extract_urls
from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]

_SECTION_RE = re.compile(r"^\[\*\]\s*(emails?|hosts?|ips?|urls?)\s+(?:found|:)", re.IGNORECASE)
_IGNORE_RE = re.compile(r"^(?:\[\*\]|\[-\]|total\b|#|[-=]{3,})", re.IGNORECASE)
_SPLIT_RE = re.compile(r"[\s,]+")
#: Banner/credit/config-log lines printed by theHarvester before/after results.
_BANNER_MARKERS = (
    "theharvester", "christian martorella", "cmartorella@edge-security.com",
    "edge-security.com", "read proxies", "proxies.yaml", "api-keys.yaml",
    "reading api-keys", "sourcing from", "an open source intelligence",
    "target:", "searching for", "verifying", "doing search",
)
#: Filename/config extensions never valid as DOMAIN/SUBDOMAIN tokens.
_FILE_EXTENSIONS = {
    "yaml", "yml", "json", "xml", "txt", "md", "py", "exe", "dll", "conf",
    "ini", "cfg", "sqlite", "sqlite3", "db", "log", "html", "htm", "js",
    "css", "png", "jpg", "jpeg", "gif", "svg", "pdf", "csv", "tsv", "sh",
    "bat", "ps1", "toml", "lock",
}
_BANNER_EMAIL = "cmartorella@edge-security.com"
_BANNER_DOMAIN = "edge-security.com"


def _is_file_name(token: str) -> bool:
    lowered = str(token or "").strip().lower().rstrip(".")
    return "." in lowered and lowered.rsplit(".", 1)[-1] in _FILE_EXTENSIONS


def _strip_banner_lines(text: str) -> str:
    """Remove theHarvester author/config banner lines before any extraction."""
    kept: list[str] = []
    for line in (text or "").splitlines():
        lowered = line.strip().lower()
        if any(marker in lowered for marker in _BANNER_MARKERS):
            continue
        kept.append(line)
    return "\n".join(kept)
_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)


def _base_domain(target: str) -> str:
    """Best-effort bare domain for the CLI target ('' when not a domain)."""
    text = (target or "").strip().lower()
    if not text:
        return ""
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/")[0].split(":")[0].strip().strip(".")
    if text.startswith("www."):
        text = text[4:]
    return text if _HOST_RE.match(text) else ""


def _normalise_ip(value: str) -> str:
    text = str(value or "").strip().strip("[](),.;")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _host_kind(host: str, base_domain: str) -> EntityType:
    if base_domain and host == base_domain:
        return EntityType.DOMAIN
    if base_domain and host.endswith("." + base_domain):
        return EntityType.SUBDOMAIN
    return EntityType.SUBDOMAIN if host.count(".") >= 2 else EntityType.DOMAIN


def _evidence_line(text: str, needle: str) -> str:
    lowered = needle.lower()
    for line in text.splitlines():
        if lowered in line.lower():
            return line.strip()
    return needle


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse theHarvester stdout. Never raises; empty/garbage input warns."""
    raw_text = raw_stdout or ""
    if not raw_text.strip():
        return ParseOutput(warnings=["theharvester: empty stdout"])
    text = _strip_banner_lines(raw_text)

    base_domain = _base_domain(target)
    allow_banner_identifiers = base_domain == _BANNER_DOMAIN

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_entities: set[tuple[str, str]] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, evidence: str,
                   confidence: float, metadata: Optional[dict] = None,
                   attributes: Optional[dict] = None) -> None:
        value = str(value or "").strip()
        if not value:
            return
        lowered_value = value.lower()
        if entity_type == EntityType.EMAIL and lowered_value == _BANNER_EMAIL \
                and not allow_banner_identifiers:
            return
        if entity_type in (EntityType.DOMAIN, EntityType.SUBDOMAIN) and (
                _is_file_name(value)
                or (not allow_banner_identifiers
                    and (lowered_value == _BANNER_DOMAIN
                         or lowered_value.endswith("." + _BANNER_DOMAIN)))):
            return
        key = (entity_type.value, value.lower())
        if key in seen_entities:
            return
        seen_entities.add(key)
        entities.append(EntityCandidate(
            type=entity_type,
            value=value,
            confidence=confidence,
            metadata=metadata or {},
            evidence=evidence,
            attributes=attributes or {},
        ))

    def add_relation(s_type: EntityType, s_value: str, predicate: EdgeType,
                     o_type: EntityType, o_value: str, evidence: str,
                     confidence: float, metadata: Optional[dict] = None) -> None:
        if not s_value or not o_value:
            return
        key = (predicate.value, s_value.lower(), o_value.lower())
        if key in seen_relations:
            return
        seen_relations.add(key)
        relations.append(RelationCandidate(
            subject_type=s_type,
            subject_value=s_value,
            predicate=predicate,
            object_type=o_type,
            object_value=o_value,
            confidence=confidence,
            metadata=metadata or {},
            evidence=evidence,
        ))

    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        header = _SECTION_RE.match(stripped)
        if header:
            section = header.group(1).lower().rstrip("s")
            continue
        if not section or _IGNORE_RE.match(stripped):
            continue

        if section == "email":
            for email in sorted(extract_emails(stripped)):
                value = email.lower()
                add_entity(EntityType.EMAIL, value, stripped, 0.85, {"section": "emails"})
                if base_domain:
                    add_relation(EntityType.EMAIL, value, EdgeType.MENTIONED_IN,
                                 EntityType.DOMAIN, base_domain, stripped, 0.80,
                                 {"domain": base_domain})
        elif section == "host":
            for token in _SPLIT_RE.split(stripped):
                token = token.strip().rstrip(".").strip()
                if not token:
                    continue
                host = ""
                ip_value = ""
                if ":" in token and "://" not in token:
                    host_part, ip_part = token.rsplit(":", 1)
                    host = host_part.strip().strip(".").lower()
                    if host and (not _HOST_RE.match(host) or _is_file_name(host)):
                        host = ""
                    ip_value = _normalise_ip(ip_part)
                else:
                    ip_value = _normalise_ip(token)
                    if not ip_value:
                        candidate = token.lower().strip(".")
                        host = (candidate if _HOST_RE.match(candidate)
                                and not _is_file_name(candidate) else "")
                if not host and not ip_value:
                    continue
                kind: Optional[EntityType] = None
                if host:
                    kind = _host_kind(host, base_domain)
                    metadata = {"section": "hosts"}
                    if base_domain and kind is EntityType.SUBDOMAIN:
                        metadata["parent_domain"] = base_domain
                    add_entity(kind, host, stripped, 0.80, metadata)
                    if base_domain and kind is EntityType.SUBDOMAIN:
                        add_relation(EntityType.SUBDOMAIN, host, EdgeType.SUBDOMAIN_OF,
                                     EntityType.DOMAIN, base_domain, stripped, 0.80)
                if ip_value:
                    add_entity(EntityType.IP, ip_value, stripped, 0.75,
                               {"hostname": host, "section": "hosts"})
                    if host and kind is not None:
                        add_relation(kind, host, EdgeType.RESOLVES_TO,
                                     EntityType.IP, ip_value, stripped, 0.75,
                                     {"hostname": host})
        elif section == "ip":
            for token in _SPLIT_RE.split(stripped):
                ip_value = _normalise_ip(token)
                if ip_value:
                    add_entity(EntityType.IP, ip_value, stripped, 0.75, {"section": "ips"})
        elif section == "url":
            for url in sorted(extract_urls(stripped)):
                add_entity(EntityType.URL, url.rstrip("/"), stripped, 0.80,
                           {"section": "urls"})
                if base_domain:
                    add_relation(EntityType.URL, url.rstrip("/"), EdgeType.MENTIONED_IN,
                                 EntityType.DOMAIN, base_domain, stripped, 0.65)

    if not entities:
        # Broad fallback: email/domain scraping when no sectioned output exists.
        for email in sorted(extract_emails(text)):
            value = email.lower()
            evidence = _evidence_line(text, value)
            add_entity(EntityType.EMAIL, value, evidence, 0.75, {"extraction": "broad"})
            if base_domain:
                add_relation(EntityType.EMAIL, value, EdgeType.MENTIONED_IN,
                             EntityType.DOMAIN, base_domain, evidence, 0.70)
        for host in sorted(extract_domains(text)):
            candidate = host.lower().strip(".")
            if not candidate or _is_file_name(candidate):
                continue
            evidence = _evidence_line(text, candidate)
            kind = _host_kind(candidate, base_domain)
            add_entity(kind, candidate, evidence, 0.70, {"extraction": "broad"})
            if base_domain and kind is EntityType.SUBDOMAIN:
                add_relation(EntityType.SUBDOMAIN, candidate, EdgeType.SUBDOMAIN_OF,
                             EntityType.DOMAIN, base_domain, evidence, 0.70)

    if not entities:
        return ParseOutput(warnings=["theharvester: no emails/hosts/IPs/URLs recognised"])
    return ParseOutput(entities=entities, relations=relations)
