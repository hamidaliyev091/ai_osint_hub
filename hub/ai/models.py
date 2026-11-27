"""Pydantic models for the hybrid offline + online AI layer (``hub.ai``).

All AI functionality is strictly opt-in (``enabled=False`` by default) so the
deterministic OSINT core runs identically with zero LLM dependencies.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AIProviderKind(str, Enum):
    """Supported local and remote AI inference providers."""

    DISABLED = "disabled"
    LOCAL_EMBEDDED = "local_embedded"
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    GEMINI = "gemini"
    DEEPSEEK = "deepseek"
    OPENAI_COMPAT = "openai_compat"


class AIHardwarePreset(str, Enum):
    """Hardware-adaptive AI & Vision presets (default: disabled)."""

    DISABLED = "disabled"
    CPU_LIGHT = "cpu_light"
    VRAM_8GB = "vram_8gb"
    VRAM_16GB_PLUS = "vram_16gb_plus"
    CLOUD_BYOK = "cloud_byok"


AI_PRESETS_CATALOG: dict[str, dict[str, Any]] = {
    AIHardwarePreset.DISABLED.value: {
        "preset": AIHardwarePreset.DISABLED.value,
        "label": "Zero-LLM Deterministic (Disabled)",
        "description": "Pure deterministic OSINT core with zero LLM/VLM inference.",
        "enabled": False,
        "provider": AIProviderKind.DISABLED.value,
        "vision_enabled": False,
        "text_model": "",
        "vision_model": "",
        "embedding_model": "",
        "num_ctx": 8192,
        "keep_alive": "2m",
        "pull_commands": [],
    },
    AIHardwarePreset.CPU_LIGHT.value: {
        "preset": AIHardwarePreset.CPU_LIGHT.value,
        "label": "CPU-Light (<= 8 GB RAM, No GPU)",
        "description": "Compact local Ollama profile for CPU-only machines.",
        "enabled": True,
        "provider": AIProviderKind.OLLAMA.value,
        "vision_enabled": False,
        "text_model": "qwen2.5:3b",
        "vision_model": "",
        "embedding_model": "embeddinggemma",
        "num_ctx": 4096,
        "keep_alive": "60s",
        "pull_commands": ["ollama pull qwen2.5:3b", "ollama pull embeddinggemma"],
    },
    AIHardwarePreset.VRAM_8GB.value: {
        "preset": AIHardwarePreset.VRAM_8GB.value,
        "label": "8 GB VRAM + 32 GB RAM (Recommended Local)",
        "description": "Tuned for 8 GB VRAM GPUs with 90s keep_alive to avoid sequential VRAM thrashing.",
        "enabled": True,
        "provider": AIProviderKind.OLLAMA.value,
        "vision_enabled": True,
        "text_model": "gemma4:e4b",
        "vision_model": "qwen2.5vl:7b",
        "embedding_model": "embeddinggemma",
        "num_ctx": 8192,
        "keep_alive": "90s",
        "pull_commands": [
            "ollama pull gemma4:e4b",
            "ollama pull qwen2.5vl:7b",
            "ollama pull embeddinggemma",
        ],
    },
    AIHardwarePreset.VRAM_16GB_PLUS.value: {
        "preset": AIHardwarePreset.VRAM_16GB_PLUS.value,
        "label": "16+ GB VRAM Workstation",
        "description": "Extended context local Ollama profile for 16+ GB VRAM GPUs.",
        "enabled": True,
        "provider": AIProviderKind.OLLAMA.value,
        "vision_enabled": True,
        "text_model": "gemma4:12b",
        "vision_model": "qwen2.5vl:7b",
        "embedding_model": "embeddinggemma",
        "num_ctx": 16384,
        "keep_alive": "5m",
        "pull_commands": [
            "ollama pull gemma4:12b",
            "ollama pull qwen2.5vl:7b",
            "ollama pull embeddinggemma",
        ],
    },
    AIHardwarePreset.CLOUD_BYOK.value: {
        "preset": AIHardwarePreset.CLOUD_BYOK.value,
        "label": "Cloud BYOK (Gemini / DeepSeek / OpenAI)",
        "description": "Bring-your-own-key remote inference with strict redaction and quarantine.",
        "enabled": True,
        "provider": AIProviderKind.GEMINI.value,
        "vision_enabled": True,
        "text_model": "gemini-2.5-flash",
        "vision_model": "gemini-2.5-flash",
        "embedding_model": "",
        "num_ctx": 8192,
        "keep_alive": "2m",
        "pull_commands": [],
    },
}


class AIConfig(BaseModel):
    """Persisted configuration for ``hub.ai`` (strict zero-LLM default)."""

    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    mode: Literal["off", "local_embedded", "ollama", "cloud"] = "off"
    preset: AIHardwarePreset = AIHardwarePreset.DISABLED
    provider: AIProviderKind = AIProviderKind.DISABLED
    num_ctx: int = Field(default=8192, ge=512, le=131072)
    keep_alive: str = "2m"

    # Embedded local AI defaults (fastembed, zero external server)
    local_embedded_text_model: str = "BAAI/bge-small-en-v1.5"
    local_embedded_vision_model: str = "Qdrant/clip-ViT-B-32-vision"

    # Local consumer-hardware defaults (8 GB VRAM + 32 GB RAM)
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "gemma4"
    ollama_vision_model: str = "qwen2.5vl:7b"
    ollama_embedding_model: str = "embeddinggemma"
    ollama_num_ctx: int = Field(default=8192, ge=512, le=131072)
    ollama_keep_alive: str = "5m"

    lmstudio_base_url: str = "http://127.0.0.1:1234/v1"
    lmstudio_model: str = "local-model"
    lmstudio_vision_model: str = ""
    lmstudio_embedding_model: str = ""

    # Remote API providers (explicit user config / env only)
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"

    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com"

    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    openai_vision_model: str = ""
    openai_embedding_model: str = "text-embedding-3-small"

    # Execution & safety bounds
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, ge=64, le=16384)
    timeout_sec: float = Field(default=30.0, ge=1.0, le=300.0)
    vision_enabled: bool = False
    reflection_enabled: bool = True

    @model_validator(mode="after")
    def _sync_mode_and_provider(self) -> "AIConfig":
        mode_set = "mode" in self.model_fields_set
        provider_set = "provider" in self.model_fields_set
        enabled_set = "enabled" in self.model_fields_set
        if mode_set and not provider_set and not enabled_set:
            if self.mode == "off":
                self.enabled = False
                self.provider = AIProviderKind.DISABLED
            elif self.mode == "local_embedded":
                self.enabled = True
                self.provider = AIProviderKind.LOCAL_EMBEDDED
            elif self.mode == "ollama":
                self.enabled = True
                self.provider = AIProviderKind.OLLAMA
            elif self.mode == "cloud":
                self.enabled = True
                self.provider = AIProviderKind.GEMINI
            return self

        if not self.enabled or self.provider == AIProviderKind.DISABLED:
            self.mode = "off"
        elif self.provider == AIProviderKind.LOCAL_EMBEDDED:
            self.mode = "local_embedded"
        elif self.provider in {AIProviderKind.OLLAMA, AIProviderKind.LMSTUDIO}:
            self.mode = "ollama"
        else:
            self.mode = "cloud"
        return self


class ReflectionAmbiguousMatch(BaseModel):
    """One proposed entity disambiguation link from Stage-2 reflection."""

    model_config = ConfigDict(extra="ignore")

    entity_id: str = ""
    candidate_entity_id: str = ""
    confidence: float = Field(default=0.35, ge=0.0, le=1.0)
    reason: str = ""


class ReflectionHypothesisProposal(BaseModel):
    """One proposed follow-up hypothesis from Stage-2 reflection."""

    model_config = ConfigDict(extra="ignore")

    question: str = ""
    target_entity_id: str = ""
    proposed_tool_ids: list[str] = Field(default_factory=list)


class ReflectionProposal(BaseModel):
    """Strict schema validated against LLM Stage-2 reflection JSON."""

    model_config = ConfigDict(extra="ignore")

    ambiguous_matches: list[ReflectionAmbiguousMatch] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    proposed_hypotheses: list[ReflectionHypothesisProposal] = Field(default_factory=list)
    notes: str = ""


class VisionExtractionResult(BaseModel):
    """Structured quarantined VLM extraction output (always AI_INFERRED)."""

    model_config = ConfigDict(extra="ignore")

    summary: str = ""
    visible_text: list[str] = Field(default_factory=list)
    persons: list[str] = Field(default_factory=list)
    organizations: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)
    injection_detected: list[str] = Field(default_factory=list)
    provider: str = ""
    model: str = ""
    epistemic_provenance: str = "AI_INFERRED"
    confidence: float = Field(default=0.35, ge=0.0, le=0.45)


class AIStatusReport(BaseModel):
    """Safe, secret-redacted AI layer status report."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    mode: str = "off"
    preset: AIHardwarePreset = AIHardwarePreset.DISABLED
    provider: AIProviderKind
    active: bool
    config_path: str
    vision_enabled: bool
    reflection_enabled: bool
    num_ctx: int = 8192
    keep_alive: str = "2m"
    models: dict[str, str] = Field(default_factory=dict)
    endpoints: dict[str, str] = Field(default_factory=dict)
    credentials: dict[str, dict[str, Any]] = Field(default_factory=dict)
    local_probes: dict[str, Any] = Field(default_factory=dict)
    local_embedded: dict[str, Any] = Field(default_factory=dict)
    hardware_profile: dict[str, Any] = Field(default_factory=dict)
    presets_catalog: dict[str, dict[str, Any]] = Field(default_factory=dict)
    installed_models: list[str] = Field(default_factory=list)
    missing_models: list[str] = Field(default_factory=list)
    pull_commands: list[str] = Field(default_factory=list)


__all__ = [
    "AIProviderKind",
    "AIHardwarePreset",
    "AI_PRESETS_CATALOG",
    "AIConfig",
    "ReflectionAmbiguousMatch",
    "ReflectionHypothesisProposal",
    "ReflectionProposal",
    "VisionExtractionResult",
    "AIStatusReport",
]
