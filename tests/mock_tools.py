"""Deterministic mock OSINT capabilities + runner for engine tests.

The engine is fully dependency-injected: tests register fake ``ToolCapability``
manifests, supply a ``MockRunner`` that returns scripted :class:`ParseOutput`
payloads as JSON stdout, and use the generic ``parse_mock`` stage-1 parser.
No subprocess, no network, no real tools.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from hub.models import (
    EntityType,
    ExecutionMode,
    ExecutionStatus,
    InvocationSpec,
    ParameterSpec,
    ToolCapability,
    ToolRunResult,
    utc_now,
)
from hub.tools.base import ParseOutput, coerce_parse_output

_FORMAT_FOR_TYPE: dict[EntityType, str] = {
    EntityType.EMAIL: "email",
    EntityType.USERNAME: "username",
    EntityType.DOMAIN: "domain",
    EntityType.SUBDOMAIN: "hostname",
    EntityType.IP: "ip",
    EntityType.URL: "url",
    EntityType.PHONE: "phone",
    EntityType.HASH: "hash",
    EntityType.SERVICE: "service",
    EntityType.PERSON: "person",
    EntityType.ORGANIZATION: "organization",
    EntityType.ASN: "asn",
    EntityType.REPOSITORY: "repository",
    EntityType.SOCIAL_PROFILE: "social_profile",
    EntityType.BREACH_RECORD: "breach_record",
    EntityType.CRYPTO_ADDRESS: "crypto_address",
}

_PARAM_NAME_FOR_TYPE: dict[EntityType, str] = {
    EntityType.EMAIL: "email",
    EntityType.USERNAME: "username",
    EntityType.DOMAIN: "domain",
    EntityType.SUBDOMAIN: "target",
    EntityType.IP: "ip",
    EntityType.URL: "url",
    EntityType.PHONE: "phone",
    EntityType.HASH: "hash",
    EntityType.SERVICE: "service",
    EntityType.PERSON: "person",
    EntityType.ORGANIZATION: "organization",
    EntityType.ASN: "asn",
    EntityType.REPOSITORY: "repository",
    EntityType.SOCIAL_PROFILE: "profile",
    EntityType.BREACH_RECORD: "breach",
    EntityType.CRYPTO_ADDRESS: "address",
}


def make_capability(tool_id: str, accepted: list[EntityType], produced: list[EntityType],
                    *, prior_yield: float = 0.8, reliability: float = 0.85,
                    mode: ExecutionMode = ExecutionMode.PASSIVE,
                    authorization_required: bool = False,
                    parameters: Optional[dict[str, ParameterSpec]] = None
                    ) -> ToolCapability:
    primary = accepted[0]
    params = parameters or {
        _PARAM_NAME_FOR_TYPE[primary]: ParameterSpec(
            name=_PARAM_NAME_FOR_TYPE[primary], type="string", required=True,
            format=_FORMAT_FOR_TYPE[primary]),
    }
    return ToolCapability(
        tool_id=tool_id,
        display_name=f"Mock {tool_id}",
        description=f"Deterministic mock capability {tool_id}",
        accepted_entity_types=accepted,
        produced_entity_types=produced,
        execution_mode=mode,
        parameters=params,
        timeout_sec=30,
        rate_limit_rps=10.0,
        reliability=reliability,
        prior_yield=prior_yield,
        invocation=InvocationSpec(kind="builtin",
                                  builtin_ref="tests.mock_tools:collect_mock"),
        parser_ref="tests.mock_tools:parse_mock",
        authorization_required=authorization_required,
        invocation_verified=True,
    )


async def collect_mock(params: dict[str, Any], *, timeout_sec: int = 5,
                       scope=None):  # pragma: no cover - never dispatched in tests
    raise AssertionError("MockRunner should intercept builtin collectors")


def parse_mock(raw_stdout: str, target: str = "") -> ParseOutput:
    """Stage-1 parser for scripted mock stdout (JSON-encoded ParseOutput)."""
    try:
        data = json.loads(raw_stdout or "{}")
    except json.JSONDecodeError:
        raise ValueError("mock stdout is not valid JSON") from None
    return coerce_parse_output(data)


@dataclass
class MockCall:
    tool_id: str
    params: dict[str, Any]
    entity_id: str = ""
    investigation_id: str = ""


@dataclass
class MockRunner:
    """Runner that pops a scripted result per (tool_id) call and records calls."""

    script: dict[str, list[Any]] = field(default_factory=dict)
    default: Any = None
    calls: list[MockCall] = field(default_factory=list)

    async def run(self, capability: ToolCapability, params: dict[str, Any],
                  context: Any) -> ToolRunResult:
        entity_id = getattr(context, "entity_id", "")
        self.calls.append(MockCall(
            tool_id=capability.tool_id, params=dict(params), entity_id=entity_id,
            investigation_id=getattr(context, "investigation_id", ""),
        ))
        queue = self.script.get(capability.tool_id)
        entry: Any
        if queue:
            entry = queue.pop(0)
        elif self.default is not None:
            entry = self.default(capability, params) if callable(self.default) else self.default
        else:
            entry = ParseOutput()

        if isinstance(entry, BaseException):
            raise entry
        if isinstance(entry, ToolRunResult):
            return entry.model_copy(update={
                "tool_id": capability.tool_id,
                "entity_id": entity_id,
                "params": dict(params),
                "started_at": entry.started_at or utc_now(),
            })
        if isinstance(entry, ParseOutput):
            payload = entry.model_dump(mode="json")
        elif isinstance(entry, dict):
            payload = entry
        else:
            payload = ParseOutput().model_dump(mode="json")
        return ToolRunResult(
            tool_id=capability.tool_id,
            entity_id=entity_id,
            params=dict(params),
            status=ExecutionStatus.SUCCESS,
            stdout=json.dumps(payload),
            exit_code=0,
            duration_ms=5,
            started_at=utc_now(),
        )

    # ── convenience assertions ─────────────────────────────────────
    @property
    def tool_calls(self) -> list[str]:
        return [call.tool_id for call in self.calls]

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def run_keys(self) -> list[tuple[str, str]]:
        return [(call.entity_id, call.tool_id) for call in self.calls]


# ── ParseOutput script builders ────────────────────────────────────────

def services_output(email: str, services: list[str], *, confidence: float = 0.9,
                    attributes: Optional[dict[str, dict[str, Any]]] = None,
                    evidence_suffix: str = "") -> ParseOutput:
    from hub.tools.base import EntityCandidate, RelationCandidate

    entities = []
    relations = []
    for service in services:
        evidence = f"[+] {service}{evidence_suffix}"
        entities.append(EntityCandidate(
            type=EntityType.SERVICE, value=service, confidence=confidence,
            evidence=evidence, attributes=(attributes or {}).get(service, {}),
        ))
        relations.append(RelationCandidate(
            subject_type=EntityType.EMAIL, subject_value=email,
            predicate="REGISTERED_ON", object_type=EntityType.SERVICE,
            object_value=service, confidence=confidence, evidence=evidence,
        ))
    return ParseOutput(entities=entities, relations=relations)


def breach_output(email: str, breaches: list[str], *,
                  confidence: float = 0.8) -> ParseOutput:
    from hub.tools.base import EntityCandidate, RelationCandidate

    entities = [EntityCandidate(type=EntityType.BREACH_RECORD, value=breach,
                                confidence=confidence, evidence=f"breach: {breach}")
                for breach in breaches]
    relations = [RelationCandidate(
        subject_type=EntityType.EMAIL, subject_value=email, predicate="EXPOSED_IN",
        object_type=EntityType.BREACH_RECORD, object_value=breach,
        confidence=confidence, evidence=f"breach: {breach}") for breach in breaches]
    return ParseOutput(entities=entities, relations=relations)


def profile_output(service: str, username: str, *, confidence: float = 0.85
                   ) -> ParseOutput:
    from hub.tools.base import EntityCandidate, RelationCandidate

    return ParseOutput(
        entities=[
            EntityCandidate(type=EntityType.USERNAME, value=username,
                            confidence=confidence, evidence=f"profile: {username}"),
            EntityCandidate(type=EntityType.SOCIAL_PROFILE,
                            value=f"https://{service}.com/{username}",
                            confidence=confidence, evidence=f"profile: {username}"),
        ],
        relations=[RelationCandidate(
            subject_type=EntityType.SERVICE, subject_value=service,
            predicate="HAS_USERNAME", object_type=EntityType.USERNAME,
            object_value=username, confidence=confidence,
            evidence=f"profile: {username}")],
    )


def identity_output(entity_type: EntityType, value: str, *, confidence: float = 0.85
                    ) -> ParseOutput:
    from hub.tools.base import EntityCandidate

    return ParseOutput(entities=[EntityCandidate(
        type=entity_type, value=value, confidence=confidence,
        evidence=f"confirmed {entity_type.value}: {value}")])


def empty_output() -> ParseOutput:
    return ParseOutput()
