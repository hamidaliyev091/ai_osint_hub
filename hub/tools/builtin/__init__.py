"""Python-native passive collectors (no external binaries, no third-party APIs).

Each collector module exposes::

    async def collect(params: dict, *, timeout_sec: int, scope: ScopeConfig) -> BuiltinOutput

and emits JSON on ``stdout`` that the matching parser in
:mod:`hub.tools.parsers` converts into entities/relations. Collectors never
raise for network failures — they return an error-classified
:class:`BuiltinOutput`.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from hub.models import ErrorCode

__all__ = ["BuiltinOutput"]


class BuiltinOutput(BaseModel):
    """Normalized result of one python-native collector invocation."""

    model_config = ConfigDict(extra="forbid")

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    error_code: ErrorCode | None = None
    error_message: str = Field(default="")
