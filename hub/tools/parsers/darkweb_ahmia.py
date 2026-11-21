"""Deterministic parser for the builtin Ahmia dark-web index collector.

Input (collector stdout)::

    {"query": "example.com",
     "onions": [{"url": "http://abcdefghijklmnop.onion/page",
                 "title": "Some hidden service"}],
     "evidence": {"search_url": "https://ahmia.fi/search/?q=example.com",
                  "token_used": true, ...}}

Output: URL entities for the ``.onion`` mentions, a SERVICE entity for the
Ahmia index and ``target MENTIONED_IN url`` relations.
"""

from __future__ import annotations

import json

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate, infer_value_type

__all__ = ["parse"]
PARSER_VERSION = "2.0.0"
MAX_EVIDENCE = 400
MAX_ITEMS = 50


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse Ahmia collector stdout; never raises (warnings instead)."""
    try:
        return _parse(raw_stdout, target)
    except Exception as exc:  # noqa: BLE001 - a parser must never crash a run
        return ParseOutput(
            warnings=[f"darkweb_ahmia parser error: {type(exc).__name__}: {exc}"],
            parser_version=PARSER_VERSION,
        )


def _as_text(value: object) -> str:
    return str(value or "").strip()


def _normalise_onion_url(value: str) -> str:
    text = _as_text(value)
    if not text:
        return ""
    if "://" not in text:
        text = f"http://{text.lstrip('/')}"
    return text


def _target_type(value: str) -> EntityType:
    try:
        inferred = infer_value_type(value)
    except ValueError:
        return EntityType.DOMAIN
    return inferred


def _target_matches(title: str, snippet: str, url: str, target: str,
                    mode: str) -> bool:
    target = (target or "").strip().lower()
    if not target or mode not in {"email", "username"}:
        return True
    haystack = f"{title} {snippet} {url}".lower()
    if mode == "email":
        if target in haystack:
            return True
        local = target.split("@", 1)[0]
        return len(local) >= 5 and local in haystack
    return target in haystack


def _parse(raw_stdout: str, target: str) -> ParseOutput:
    warnings: list[str] = []
    text = (raw_stdout or "").strip()
    if not text:
        return ParseOutput(warnings=["empty stdout"], parser_version=PARSER_VERSION)
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as exc:
        return ParseOutput(warnings=[f"invalid JSON from darkweb_ahmia: {exc}"],
                           parser_version=PARSER_VERSION)
    if not isinstance(data, dict):
        return ParseOutput(warnings=[f"unexpected darkweb_ahmia payload: "
                                     f"{type(data).__name__}"],
                           parser_version=PARSER_VERSION)

    raw_query = data.get("query")
    if isinstance(raw_query, dict):
        query = (_as_text(raw_query.get("clue"))
                 or _as_text(raw_query.get("domain"))
                 or _as_text(raw_query.get("email"))
                 or _as_text(raw_query.get("username")))
    else:
        query = _as_text(raw_query)
    target_value = _as_text(target) or query
    onions = data.get("onions") if isinstance(data.get("onions"), list) else []
    evidence = data.get("evidence") if isinstance(data.get("evidence"), dict) else {}
    params = evidence.get("params") if isinstance(evidence.get("params"), dict) else {}
    if params.get("email"):
        match_mode, match_target = "email", _as_text(params.get("email"))
    elif params.get("username"):
        match_mode, match_target = "username", _as_text(params.get("username"))
    elif (target_value and "@" in target_value
          and "://" not in target_value):
        match_mode, match_target = "email", target_value
    elif _target_type(target_value) is EntityType.USERNAME:
        match_mode, match_target = "username", target_value
    else:
        match_mode, match_target = "domain", target_value
    filtered_onions: list[dict] = []
    for onion in onions:
        if not isinstance(onion, dict):
            continue
        title = _as_text(onion.get("title"))
        snippet = _as_text(onion.get("snippet") or onion.get("description"))
        url = _normalise_onion_url(_as_text(onion.get("url")))
        if _target_matches(title, snippet, url, match_target, match_mode):
            filtered_onions.append(onion)
    onions = filtered_onions

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add_entity(entity_type: EntityType, value: str, confidence: float,
                   evidence: str, *, metadata: dict | None = None) -> bool:
        value = _as_text(value)
        if not value:
            return False
        key = (entity_type.value, value.lower())
        if key in seen:
            return False
        seen.add(key)
        entities.append(EntityCandidate(
            type=entity_type, value=value, confidence=confidence,
            metadata=dict(metadata or {}), evidence=evidence[:MAX_EVIDENCE],
        ))
        return True

    subject_type = _target_type(target_value) if target_value else EntityType.DOMAIN
    add_entity(EntityType.SERVICE, "ahmia", 0.70,
               f"Ahmia clearnet dark-web index searched for {query or target_value or 'target'}",
               metadata={"kind": "search_index"})
    if query:
        add_entity(subject_type, query, 0.65,
                   f"Ahmia index query for {query}",
                   metadata={"source": "ahmia"})

    for onion in onions[:MAX_ITEMS]:
        if not isinstance(onion, dict):
            continue
        url = _normalise_onion_url(_as_text(onion.get("url")))
        title = _as_text(onion.get("title"))
        if not url:
            continue
        evidence = f"Ahmia result: {url}" + (f" — {title}" if title else "")
        if add_entity(EntityType.URL, url, 0.60, evidence,
                      metadata={"title": title, "source": "ahmia"}):
            if target_value:
                relations.append(RelationCandidate(
                    subject_type=subject_type, subject_value=target_value,
                    predicate=EdgeType.MENTIONED_IN, object_type=EntityType.URL,
                    object_value=url, confidence=0.60,
                    evidence=evidence[:MAX_EVIDENCE],
                ))

    if not onions:
        warnings.append("no .onion URLs parsed from the Ahmia response")
    return ParseOutput(entities=entities, relations=relations, warnings=warnings,
                       parser_version=PARSER_VERSION)
