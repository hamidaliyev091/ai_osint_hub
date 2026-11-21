"""Deterministic parser for the builtin Photon-style crawler.

Input (collector stdout)::

    {"target": "example.com", "base_host": "example.com",
     "urls": ["https://example.com/about", ...], "emails": ["a@example.com"],
     "subdomains": ["blog.example.com"], "social_profiles": [...],
     "js_endpoints": [...], "buckets": [...], "evidence": {...}}

Output: URL/SERVICE entities for discovered web artefacts, EMAIL entities with
``email MENTIONED_IN domain``, SUBDOMAIN entities with ``SUBDOMAIN_OF domain``
and SOCIAL_PROFILE entities. Bounded and evidence-backed; never raises.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ITEMS = 100
PAGE_URL_LIMIT = 15
_STATIC_EXTENSIONS = {
    "css", "js", "mjs", "map", "svg", "png", "jpg", "jpeg", "gif", "ico",
    "webp", "avif", "bmp", "woff", "woff2", "ttf", "eot", "otf", "mp4",
    "mp3", "pdf", "zip",
}
_CDN_ASSET_HOSTS = {
    "code.jquery.com", "cdnjs.cloudflare.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "cdn.jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com",
}


def _is_static_asset_url(value: str) -> bool:
    try:
        parts = urlsplit(str(value or "").strip())
    except ValueError:
        return True
    host = (parts.hostname or "").lower()
    if any(host == cdn or host.endswith("." + cdn)
           for cdn in _CDN_ASSET_HOSTS):
        return True
    path = (parts.path or "").lower().rstrip(".")
    extension = path.rsplit(".", 1)[-1] if "." in path else ""
    return extension in _STATIC_EXTENSIONS


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse photon crawler stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"photon_crawler parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _host_of(value: str) -> str:
    try:
        return (urlsplit(str(value or "")).hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return ""


def _type_of(value: str) -> EntityType:
    try:
        return infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN


def _string_list(data: dict, key: str, warnings: list[str]) -> list[str]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        warnings.append(f"{key}: expected a list, got {type(value).__name__}")
        return []
    result: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
    return result[:MAX_ITEMS]


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from photon_crawler: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected photon_crawler payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    target_value = str(data.get("target") or target or "").strip()
    base_host = str(data.get("base_host") or "").strip().lower().rstrip(".")
    if not base_host:
        base_host = _host_of(target_value) if "://" in target_value else (
            target_value.lower().rstrip(".") if target_value else "")
    urls = _string_list(data, "urls", warnings)
    emails = _string_list(data, "emails", warnings)
    subdomains = _string_list(data, "subdomains", warnings)
    social_profiles = _string_list(data, "social_profiles", warnings)
    js_endpoints = _string_list(data, "js_endpoints", warnings)
    buckets = _string_list(data, "buckets", warnings)

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   evidence: str, *, metadata: dict | None = None,
                   attributes: dict | None = None) -> bool:
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
        relations.append(RelationCandidate(
            subject_type=subject_type, subject_value=subject_value,
            predicate=predicate, object_type=object_type,
            object_value=object_value, confidence=confidence,
            evidence=evidence[:MAX_EVIDENCE],
        ))

    domain_type = _type_of(base_host) if base_host else EntityType.DOMAIN

    # Static assets (theme/media/scripts/CDN libraries) are never URL entities;
    # only high-signal HTML pages are emitted, capped per run.
    _ = js_endpoints  # still surfaced in raw payload/evidence, not as entities
    page_urls = 0
    for url in urls:
        if page_urls >= PAGE_URL_LIMIT:
            break
        if _is_static_asset_url(url):
            continue
        if add_entity(EntityType.URL, url, 0.60,
                      f"photon crawler discovered link: {url}",
                      metadata={"content_kind": "link"}):
            page_urls += 1
    for url in social_profiles:
        add_entity(EntityType.SOCIAL_PROFILE, url, 0.70,
                   f"photon crawler found social profile link: {url}")
    for url in buckets:
        if add_entity(EntityType.SERVICE, url, 0.55,
                      f"photon crawler found cloud storage bucket reference: {url}",
                      metadata={"kind": "cloud_bucket"}):
            if base_host:
                add_relation(domain_type, base_host, EdgeType.ASSOCIATED_WITH,
                             EntityType.SERVICE, url, 0.55,
                             f"bucket reference on {base_host}: {url}")
    for subdomain in subdomains:
        add_entity(EntityType.SUBDOMAIN, subdomain, 0.70,
                   f"photon crawler referenced subdomain of {base_host}: {subdomain}")
        if base_host:
            add_relation(EntityType.SUBDOMAIN, subdomain, EdgeType.SUBDOMAIN_OF,
                         domain_type, base_host, 0.70,
                         f"subdomain {subdomain} discovered under {base_host}")
    for email in emails:
        evidence = f"e-mail address published on {base_host or target_value or 'target'}: {email}"
        if add_entity(EntityType.EMAIL, email, 0.70, evidence):
            if base_host:
                add_relation(EntityType.EMAIL, email, EdgeType.MENTIONED_IN,
                             domain_type, base_host, 0.65, evidence)

    if not entities:
        warnings.append("no photon_crawler artefacts parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
