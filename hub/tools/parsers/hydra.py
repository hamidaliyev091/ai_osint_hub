"""Parse hydra stdout into the v2 ParseOutput contract.

hydra prints one line per valid credential pair::

    [22][ssh] host: 192.0.2.10   login: admin   password: s3cr3t

Each pair yields a ``credential`` entity (``login:password``) and a ``service``
entity (``ssh:22/tcp``) joined by ``credential ASSOCIATED_WITH service``.
hydra is policy-blocked from execution; this parser exists for recorded /
imported output only.  Pure and deterministic: no network, no file access.
"""

from __future__ import annotations

import re

from hub.models import EdgeType, EntityType
from hub.tools.base import EntityCandidate, ParseOutput, RelationCandidate

__all__ = ["parse"]

_SUCCESS_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[A-Za-z0-9_.-]+)\]\s+host:\s*(?P<host>\S+)\s+"
    r"login:\s*(?P<login>\S+)\s+password:\s*(?P<password>.*?)\s*$",
    re.MULTILINE,
)


def parse(raw_stdout: str, target: str = "") -> ParseOutput:
    """Parse hydra stdout. Never raises; empty/garbage input yields warnings."""
    text = raw_stdout or ""
    if not text.strip():
        return ParseOutput(warnings=["hydra: empty stdout"])

    entities: list[EntityCandidate] = []
    relations: list[RelationCandidate] = []
    seen_credentials: set[str] = set()
    seen_services: set[str] = set()

    for match in _SUCCESS_RE.finditer(text):
        port = match.group("port")
        service_name = match.group("service").strip().lower()
        host = match.group("host").strip()
        login = match.group("login").strip()
        password = match.group("password").strip()
        evidence = match.group(0).strip()

        service_value = f"{service_name}:{port}/tcp"
        metadata = {
            "username": login,
            "password": password,
            "host": host,
            "port": int(port),
            "service_name": service_name,
            "protocol": "tcp",
        }
        if target:
            metadata["target"] = target
        if service_value not in seen_services:
            seen_services.add(service_value)
            entities.append(EntityCandidate(
                type=EntityType.SERVICE,
                value=service_value,
                confidence=0.95,
                metadata={"host": host, "port": int(port), "protocol": "tcp",
                          "service_name": service_name, "target": target},
                evidence=evidence,
                attributes={"port": int(port), "protocol": "tcp",
                            "service_name": service_name},
            ))

        credential_value = f"{login}:{password}"
        if credential_value in seen_credentials:
            continue
        seen_credentials.add(credential_value)
        entities.append(EntityCandidate(
            type=EntityType.CREDENTIAL,
            value=credential_value,
            confidence=0.95,
            metadata=metadata,
            evidence=evidence,
            attributes={"username": login, "password": password,
                        "host": host, "port": int(port),
                        "service_name": service_name},
        ))
        relations.append(RelationCandidate(
            subject_type=EntityType.CREDENTIAL,
            subject_value=credential_value,
            predicate=EdgeType.ASSOCIATED_WITH,
            object_type=EntityType.SERVICE,
            object_value=service_value,
            confidence=0.95,
            evidence=evidence,
            metadata={"host": host, "port": int(port)},
        ))

    if not entities:
        return ParseOutput(warnings=["hydra: no valid credentials recognised"])
    return ParseOutput(entities=entities, relations=relations)
