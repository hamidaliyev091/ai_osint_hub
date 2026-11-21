"""Deterministic parser for the builtin HTTP header collector.

Input (collector stdout)::

    {"url": "https://example.com/", "status_code": 200,
     "headers": {"server": "nginx", ...}, "server": "nginx",
     "content_type": "text/html", "title": "Example Domain"}

Output: a URL entity, a SERVICE entity for the server technology (with
``status_code`` attribute), and ``url MENTIONED_IN domain``.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"http_headers parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_status_code(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _evidence_fragment(headers: dict[str, str], keys: tuple[str, ...]) -> str:
    parts = [f"{key}={headers[key]}" for key in keys if headers.get(key)]
    return "; ".join(parts)[:MAX_EVIDENCE]


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from http_headers: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected http_headers payload: {type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    url = str(data.get("url") or "").strip()
    if not url and target:
        host = str(target).strip().rstrip("/")
        url = host if "://" in host else f"https://{host}/"
    status_code = _as_status_code(data.get("status_code"))

    raw_headers = data.get("headers")
    headers: dict[str, str] = {}
    if isinstance(raw_headers, dict):
        headers = {str(key).lower(): str(value) for key, value in raw_headers.items()}
    else:
        warnings.append("missing 'headers' object in http_headers output")

    server = str(data.get("server") or headers.get("server") or "").strip()
    if not server:
        server = str(headers.get("x-powered-by") or "").strip()
    content_type = str(data.get("content_type") or headers.get("content-type") or "").strip()
    title = str(data.get("title") or "").strip()

    evidence = _evidence_fragment(
        headers, ("server", "content-type", "x-powered-by", "strict-transport-security")
    ) or f"HTTP status {status_code}"
    url_evidence = (f"HTTP GET {url} -> {status_code}"
                    + (f"; title={title!r}" if title else ""))

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    host = ""
    if url:
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        entities.append(EntityCandidate(
            type=EntityType.URL,
            value=url,
            confidence=0.90,
            metadata={"status_code": status_code, "content_type": content_type, "title": title},
            attributes={"status_code": status_code},
            evidence=url_evidence[:MAX_EVIDENCE],
        ))
    if server:
        entities.append(EntityCandidate(
            type=EntityType.SERVICE,
            value=server,
            confidence=0.70,
            metadata={"status_code": status_code, "content_type": content_type},
            attributes={"status_code": status_code, "server": server},
            evidence=evidence,
        ))
    if url and host:
        try:
            domain_type = infer_value_type(host)
        except ValueError:
            domain_type = EntityType.DOMAIN
        relations.append(RelationCandidate(
            subject_type=EntityType.URL,
            subject_value=url,
            predicate=EdgeType.MENTIONED_IN,
            object_type=domain_type,
            object_value=host,
            confidence=0.75,
            evidence=url_evidence[:MAX_EVIDENCE],
        ))
    if not entities:
        warnings.append("no HTTP header entities parsed")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
