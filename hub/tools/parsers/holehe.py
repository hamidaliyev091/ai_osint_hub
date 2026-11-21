"""Parse holehe stdout into the v2 ParseOutput contract.

holehe prints one line per checked service::

    [+] twitter.com        registered
    [-] instagram.com      not registered
    [x] adobe.com          rate-limited / error

Only explicit positive ``[+]`` lines are evidence. Negative/error lines are
ignored entirely: they must never create service nodes, ``registered=False``
attributes or fake contradictions. Registration is represented by the
``email REGISTERED_ON service`` relation claim, never by a global functional
attribute on the service entity.

holehe also prints a banner/footer (author credits, BTC address, legend, timing)
which is *not* target data; those lines are skipped so handles such as
``megadose``/``palenath`` are never extracted. Profile URLs are only harvested
from lines in a positive-service context.
"""

from __future__ import annotations

import re

from hub.cooking import extract_urls, extract_usernames_from_urls
from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

#: Positive hits only (registered). ``[-]`` unused, ``[x]`` rate-limited.
_POSITIVE_LINE_RE = re.compile(r"^\[\+\]\s+(.+?)\s*$")
_NON_POSITIVE_LINE_RE = re.compile(r"^\[[xX\-?]\]\s*")
_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)
_BANNER_MARKERS = (
    "twitter :", "github :", "for btc", "bitcoin donation", "btc donation",
    "holehe :", "email used", "websites checked", "@palenath", "megadose",
    "rate limit", "email not used", "donations",
)


def _subject(target: str) -> tuple[EntityType, str]:
    """Resolve the relation subject type/value for the CLI target."""
    text = (target or "").strip()
    if not text:
        return EntityType.EMAIL, ""
    try:
        found = infer_value_type(text)
    except ValueError:
        return EntityType.EMAIL, text
    if found in (EntityType.EMAIL, EntityType.USERNAME):
        return found, text
    return EntityType.EMAIL, text


def _is_banner_line(line: str) -> bool:
    lowered = line.strip().lower()
    return any(marker in lowered for marker in _BANNER_MARKERS)


def _service_domain(raw: str) -> str:
    token = (raw or "").strip().split()[0] if (raw or "").strip() else ""
    domain = token.rstrip(".,;:").lower()
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    domain = domain.split("/")[0].split(":")[0]
    return domain


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse holehe stdout; never raises. Non-positive lines are ignored."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["holehe: empty stdout"])

    subject_type, subject_value = _subject(target)
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_domains: set[str] = set()
    positive_context = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            positive_context = False
            continue
        if _is_banner_line(stripped):
            positive_context = False
            continue

        positive_match = _POSITIVE_LINE_RE.match(stripped)
        if positive_match:
            positive_context = True
            domain = _service_domain(positive_match.group(1))
            if not _HOST_RE.match(domain) or domain in seen_domains:
                continue
            seen_domains.add(domain)
            entities.append(EntityCandidate(
                type=EntityType.SERVICE,
                value=domain,
                confidence=0.90,
                metadata={"marker": "+", "url": f"https://{domain}"},
                evidence=stripped,
                # No attributes: registration is a relationship claim, never a
                # functional HAS_ATTRIBUTE on the shared Service entity.
            ))
            if subject_value:
                relations.append(RelationCandidate(
                    subject_type=subject_type,
                    subject_value=subject_value,
                    predicate=EdgeType.REGISTERED_ON,
                    object_type=EntityType.SERVICE,
                    object_value=domain,
                    confidence=0.90,
                    evidence=stripped,
                    # No attributes/metadata here either: the ingestor copies
                    # relation metadata onto the object entity as HAS_ATTRIBUTE
                    # claims, which would reintroduce the global registration
                    # attribute (and fake cross-email contradictions).
                ))
            continue

        if _NON_POSITIVE_LINE_RE.match(stripped):
            # [-] / [x] / [?] lines are never evidence, and close the positive
            # context so their trailing error/profile text is not harvested.
            positive_context = False
            continue

        # Only lines immediately following a [+] service line may contribute
        # profile URL hints (banner/footer text is explicitly excluded above).
        if positive_context:
            for url in sorted(extract_urls(stripped)):
                if _is_banner_line(url):
                    continue
                for hint in extract_usernames_from_urls([url]):
                    username = str(hint.get("username") or "").strip().lstrip("@")
                    platform = str(hint.get("platform") or "").strip()
                    if not username:
                        continue
                    if username.lower() in {"megadose", "palenath"}:
                        continue
                    entities.append(EntityCandidate(
                        type=EntityType.USERNAME,
                        value=username,
                        confidence=0.75,
                        metadata={"platform": platform, "username_hint": True},
                        evidence=url,
                    ))

    if not entities:
        return ParseOutput(warnings=["holehe: no positive registrations found"])
    return ParseOutput(entities=entities, relations=relations)
