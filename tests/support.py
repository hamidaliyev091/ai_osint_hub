"""Shared test helpers for building ERKG state without duplication."""

from __future__ import annotations

from typing import Any, Optional

from hub.erkg.graph import GraphView
from hub.erkg.resolution import derive_entity_drafts
from hub.erkg.store import ERKGStore
from hub.models import (
    Entity,
    EntityType,
    EvidenceArtifact,
    InvestigationConfig,
    InvestigationState,
    utc_now,
)

DEFAULT_INV = "inv-test"


def bootstrap(store: ERKGStore, target_id: str = DEFAULT_INV, *,
              raw_input: str = "seed target") -> InvestigationState:
    now = utc_now()
    state = InvestigationState(
        target_id=target_id, raw_input=raw_input, created_at=now, updated_at=now,
        config=InvestigationConfig(target_id=target_id, raw_input=raw_input),
    )
    store.create_investigation(state)
    return state


def artifact(store: ERKGStore, tool: str = "holehe", *, suffix: str = "1",
             investigation_id: str = DEFAULT_INV, snippet: str = "evidence",
             investigation: Optional[InvestigationState] = None) -> str:
    investigation_id = investigation.target_id if investigation else investigation_id
    value = EvidenceArtifact(
        artifact_id=f"art_{tool}_{suffix}",
        investigation_id=investigation_id,
        source_tool=tool,
        invocation_params_hash=f"hash_{tool}_{suffix}",
        timestamp_utc=utc_now(),
        raw_evidence_snippet=snippet,
        raw_output_sha256=(suffix * 64)[:64],
        parser_version="2.0.0",
    )
    store.add_artifact(value)
    return value.artifact_id


def entity(store: ERKGStore, etype: EntityType | str, value: str,
           *, investigation_id: str = DEFAULT_INV, artifact_id: Optional[str] = None,
           aliases: Optional[list[str]] = None,
           metadata: Optional[dict[str, Any]] = None) -> Entity:
    etype = EntityType.coerce(etype)
    drafts, _ = derive_entity_drafts(etype, value)
    draft = drafts[0]
    now = utc_now()
    from hub.erkg.resolution import canonical_entity_id

    value_obj = Entity(
        entity_id=canonical_entity_id(draft.entity_type, draft.canonical_value),
        investigation_id=investigation_id,
        type=draft.entity_type,
        canonical_value=draft.canonical_value,
        display_value=draft.display_value,
        aliases=sorted(set((aliases or []) + [draft.raw_value])),
        raw_values=[draft.raw_value],
        first_seen=now,
        last_seen=now,
        created_by_artifact=artifact_id,
        metadata=metadata or {},
    )
    store.insert_entity(investigation_id, value_obj,
                        alias_keys=[f"{draft.entity_type.value}:{a}"
                                    for a in value_obj.aliases
                                    if a])
    return store.get_entity(value_obj.entity_id)


def claim(store: ERKGStore, subject_id: str, predicate: str, *,
          object_id: Optional[str] = None, object_literal: Any = "__unset__",
          tools: tuple[str, ...] = ("holehe",), investigation_id: str = DEFAULT_INV,
          snippet: str = "claim evidence"):
    if object_literal == "__unset__":
        object_literal = None
    artifact_ids: list[str] = []
    if tools:
        for index, tool in enumerate(tools):
            artifact_ids.append(artifact(store, tool, suffix=f"{index + 10}",
                                         investigation_id=investigation_id,
                                         snippet=snippet))
    result = None
    for index, tool in enumerate(tools):
        if object_id is not None:
            result = store.upsert_claim(
                investigation_id, subject_id, predicate, object_id=object_id,
                artifact_id=artifact_ids[index], source_tool=tool,
                snippet=snippet)
        else:
            result = store.upsert_claim(
                investigation_id, subject_id, predicate,
                object_literal={} if object_literal is None else object_literal,
                artifact_id=artifact_ids[index], source_tool=tool,
                snippet=snippet)
    return result


def hypothesis_claim(store: ERKGStore, subject_id: str, predicate: str, *,
                     object_id: Optional[str] = None,
                     object_literal: Any = "__unset__",
                     investigation_id: str = DEFAULT_INV):
    kwargs: dict[str, Any] = {}
    if object_id is not None:
        kwargs["object_id"] = object_id
    else:
        kwargs["object_literal"] = None if object_literal == "__unset__" else object_literal
    return store.add_hypothesis_claim(investigation_id, subject_id, predicate,
                                      timestamp=utc_now(), **kwargs)


def graph(store: ERKGStore, seed_ids: list[str],
          investigation_id: str = DEFAULT_INV) -> GraphView:
    return GraphView(store, investigation_id, seed_entity_ids=seed_ids)


def set_seeds(store: ERKGStore, seed_ids: list[str],
              investigation_id: str = DEFAULT_INV) -> None:
    import json

    store.update_investigation(investigation_id,
                               seed_entity_ids_json=json.dumps(seed_ids))
