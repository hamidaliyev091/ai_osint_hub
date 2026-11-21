"""Parse whatweb stdout into the v2 ParseOutput contract.

whatweb fingerprints the technology stack of a web host::

    http://example.com [200 OK] Country[US], HTTPServer[nginx/1.18.0], WordPress[6.2]

The scanned URL becomes a ``url`` entity and every technology becomes a
``service`` entity related to the target domain with ``ASSOCIATED_WITH``.
Wrapper plugins (``HTTPServer``, ``X-Powered-By``) report the product as the
technology name; direct plugins (``WordPress``, ``JQuery``) are themselves the
technology.  Pure and deterministic: no network, no file access.
"""

from __future__ import annotations

import re

from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_LINE_URL_RE = re.compile(r"^(?P<url>https?://\S+)\s+\[(?P<status>\d{3})")
_BRACKET_RE = re.compile(
    r"(?P<label>[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z][A-Za-z0-9-]*)*)"
    r"\[(?P<value>[^\[\]]+)\]"
)
_PRODUCT_LABELS = {"httpserver", "server", "x-powered-by", "x-poweredby"}
_SKIP_LABELS = {
    "allow", "country", "ip", "title", "redirectlocation", "httpstatus", "cookies", "email",
    "meta-author", "meta-generator", "uncommonheaders", "via-proxy", "proxy",
    "account", "open-graph", "script", "html5", "frameset", "objectinfo",
    "passwordfield", "strict-transport-security", "content-type", "x-frame-options",
    "x-xss-protection", "content-security-policy", "set-cookie", "headers",
    "x-content-type-options", "referrer-policy", "permissions-policy",
}
_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$",
    re.IGNORECASE,
)


def _domain_of(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/")[0].split(":")[0].strip().strip(".")
    if text.startswith("www."):
        text = text[4:]
    return text if _HOST_RE.match(text) else ""


def _subject(target: str) -> tuple[EntityType, str]:
    """Resolve the relation subject type/value for the CLI target."""
    text = (target or "").strip()
    domain = _domain_of(text)
    if domain:
        return EntityType.DOMAIN, domain
    if not text:
        return EntityType.DOMAIN, ""
    try:
        found = infer_value_type(text)
    except ValueError:
        return EntityType.DOMAIN, text
    return found, text


def _normalise_label(label: str) -> str:
    return re.sub(r"\s+", " ", label).strip().lower()


def _technology(label: str, value: str) -> tuple[str, str]:
    if label in _PRODUCT_LABELS:
        product, _, version = value.partition("/")
        return product.strip().lower(), version.strip()
    return label, value.strip()


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse whatweb stdout. Never raises; empty/garbage input yields warnings."""
    text = _ANSI_RE.sub("", raw_stdout or "")
    if not text.strip():
        return ParseOutput(warnings=["whatweb: empty stdout"])

    subject_type, subject_value = _subject(target)
    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_services: set[str] = set()
    seen_urls: set[str] = set()
    seen_relations: set[tuple[str, str, str]] = set()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        line_match = _LINE_URL_RE.match(stripped)
        if line_match:
            url = line_match.group("url").strip()
            status_code = int(line_match.group("status"))
            if url not in seen_urls:
                seen_urls.add(url)
                entities.append(EntityCandidate(
                    type=EntityType.URL,
                    value=url,
                    confidence=0.90,
                    metadata={"status_code": status_code, "target": target},
                    evidence=stripped,
                    attributes={"status_code": status_code},
                ))
            if not subject_value:
                subject_type, subject_value = EntityType.DOMAIN, _domain_of(url)

        for tech_match in _BRACKET_RE.finditer(stripped):
            label = _normalise_label(tech_match.group("label"))
            value = tech_match.group("value").strip()
            if not label or label in _SKIP_LABELS or label.isdigit():
                continue
            technology, version = _technology(label, value)
            technology = technology.strip().lower()
            if not technology:
                continue
            if technology not in seen_services:
                seen_services.add(technology)
                attributes: dict = {}
                if version:
                    attributes["version"] = version
                metadata = {
                    "technology": label,
                    "version": version,
                    "raw": tech_match.group(0),
                    "target": target,
                }
                entities.append(EntityCandidate(
                    type=EntityType.SERVICE,
                    value=technology,
                    confidence=0.90,
                    metadata=metadata,
                    evidence=stripped,
                    attributes=attributes,
                ))
            if not subject_value:
                continue
            relation_key = (EdgeType.ASSOCIATED_WITH.value, subject_value.lower(), technology)
            if relation_key in seen_relations:
                continue
            seen_relations.add(relation_key)
            relations.append(RelationCandidate(
                subject_type=subject_type,
                subject_value=subject_value,
                predicate=EdgeType.ASSOCIATED_WITH,
                object_type=EntityType.SERVICE,
                object_value=technology,
                confidence=0.90,
                evidence=stripped,
                metadata={"technology": label, "version": version},
            ))

    if not entities:
        return ParseOutput(warnings=["whatweb: no technologies or URLs recognised"])
    return ParseOutput(entities=entities, relations=relations)
