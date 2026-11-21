"""Parse h8mail stdout into the v2 ParseOutput contract.

h8mail looks up an email address in local breach indices and prints one
``Breach: <name>`` line per hit along with credential indicators::

    [>] Target: alice@example.com
    [>] Breach: LinkedIn (2012) - passwords

Breach hits become ``breach_record`` entities (``credentials_exposed``
attribute) and yield ``email EXPOSED_IN breach_record`` relations.  Additional
emails seen in the output are related with ``MENTIONED_IN``.  Pure and
deterministic: no network, no file access.
"""

from __future__ import annotations

import re

from hub.cooking import extract_emails
from hub.models import EdgeType, EntityType
from hub.tools.base import (
    EntityCandidate,
    ParseOutput,
    RelationCandidate,
    infer_value_type,
)

__all__ = ["parse"]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_BREACH_LABEL_RE = re.compile(r"(?:breach|leak|database)\s*[:>]\s*(.+?)\s*$", re.IGNORECASE)
_TARGET_LINE_RE = re.compile(r"(?:target|email|e-mail)\s*[:>]\s*(\S+@\S+\.\S+)", re.IGNORECASE)
_CREDENTIAL_WORDS_RE = re.compile(
    r"(?:password|passwd|hash|bcrypt|sha\d*|md5|pbkdf2|scrypt|plaintext)", re.IGNORECASE
)
_KNOWN_BREACH_RES = (
    re.compile(r"(Collection\s*#?\s*\d+)", re.IGNORECASE),
    re.compile(r"(Exploit\.in)", re.IGNORECASE),
    re.compile(r"(AntiPublic)", re.IGNORECASE),
    re.compile(
        r"\b(LinkedIn|Adobe|Dropbox|MySpace|Tumblr|Twitter|Canva|Zynga|Dubsmash|Deezer|"
        r"Yahoo|Equifax|Marriott|Experian|Capital One|LastPass|MyFitnessPal)\b",
        re.IGNORECASE,
    ),
)
_NOISE_NAMES = {"", "breach", "breaches", "leak", "leaks", "database", "unknown", "none", "n/a"}


def _subject(target: str) -> tuple[EntityType, str]:
    """Resolve the relation subject type/value for the CLI target."""
    text = (target or "").strip()
    if not text:
        return EntityType.EMAIL, ""
    try:
        found = infer_value_type(text)
    except ValueError:
        return EntityType.EMAIL, text
    return (found if found is EntityType.EMAIL else EntityType.EMAIL), text


def _clean_breach_name(name: str) -> str:
    """Normalise a breach label to a compact display name."""
    cleaned = str(name or "").strip().strip("[]()<>\"'").strip()
    cleaned = re.split(r"\s+-\s+|\s*[|;]\s*", cleaned, maxsplit=1)[0].strip()
    return re.sub(r"\s+", " ", cleaned)[:80]


def _breach_value(name: str) -> str:
    return _clean_breach_name(name).lower().strip(" .:-")


def _evidence_line(text: str, needle: str) -> str:
    lowered = needle.lower()
    for line in text.splitlines():
        if lowered in line.lower():
            return line.strip()
    return ""


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse h8mail stdout. Never raises; empty/garbage input yields warnings."""
    text = _ANSI_RE.sub("", raw_stdout or "")
    if not text.strip():
        return ParseOutput(warnings=["h8mail: empty stdout"])

    subject_type, subject_value = _subject(target)
    emails_found = sorted(extract_emails(text))
    if not subject_value and emails_found:
        subject_value = emails_found[0]
        subject_type = EntityType.EMAIL

    credentials_exposed = bool(_CREDENTIAL_WORDS_RE.search(text))
    breaches: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        label_match = _BREACH_LABEL_RE.search(stripped)
        if label_match:
            display = _clean_breach_name(label_match.group(1))
            value = _breach_value(label_match.group(1))
            if value and value not in _NOISE_NAMES and value not in breaches:
                breaches[value] = (display or value, stripped)
            continue
        for pattern in _KNOWN_BREACH_RES:
            known = pattern.search(stripped)
            if known:
                display = _clean_breach_name(known.group(0))
                value = _breach_value(known.group(0))
                if value and value not in _NOISE_NAMES and value not in breaches:
                    breaches[value] = (display or value, stripped)
                break

    if not breaches:
        return ParseOutput(warnings=["h8mail: no breach names recognised in output"])

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    for value, (display, evidence) in breaches.items():
        attributes = {"credentials_exposed": credentials_exposed}
        entities.append(EntityCandidate(
            type=EntityType.BREACH_RECORD,
            value=value,
            confidence=0.95 if credentials_exposed else 0.85,
            metadata={"breach_name": display, "credentials_exposed": credentials_exposed},
            evidence=evidence,
            attributes=attributes,
        ))
        if subject_value:
            relations.append(RelationCandidate(
                subject_type=subject_type,
                subject_value=subject_value,
                predicate=EdgeType.EXPOSED_IN,
                object_type=EntityType.BREACH_RECORD,
                object_value=value,
                confidence=0.90,
                evidence=evidence,
                metadata={"credentials_exposed": credentials_exposed},
            ))

    target_email = ""
    target_match = _TARGET_LINE_RE.search(text)
    if target_match:
        target_email = target_match.group(1).strip().lower()
    seen_emails: set[str] = set()
    for email in emails_found:
        lowered = email.lower()
        if lowered in seen_emails:
            continue
        seen_emails.add(lowered)
        evidence = _evidence_line(text, lowered)
        if not evidence:
            continue
        is_subject = lowered in (target_email, subject_value.lower())
        metadata = {"role": "subject" if is_subject else "related"}
        entities.append(EntityCandidate(
            type=EntityType.EMAIL,
            value=lowered,
            confidence=0.85 if is_subject else 0.80,
            metadata=metadata,
            evidence=evidence,
        ))
        if is_subject:
            continue
        for breach_value, (display, _breach_evidence) in breaches.items():
            relations.append(RelationCandidate(
                subject_type=EntityType.EMAIL,
                subject_value=lowered,
                predicate=EdgeType.MENTIONED_IN,
                object_type=EntityType.BREACH_RECORD,
                object_value=breach_value,
                confidence=0.70,
                evidence=evidence,
                metadata={"breach_name": display},
            ))

    return ParseOutput(entities=entities, relations=relations)
