"""Pure-httpx async inference clients for local and remote AI providers.

Supports Ollama, LM Studio, OpenAI-compatible endpoints, Gemini REST API, and
DeepSeek API using only ``httpx`` (already a core dependency). Never raises
unhandled network/JSON exceptions and always redacts secrets from errors.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from hub.ai.models import AIConfig, AIProviderKind
from hub.security.redaction import redact

MAX_IMAGE_COUNT = 4


@dataclass
class AIResponse:
    """Structured outcome of one LLM/VLM completion call."""

    ok: bool
    text: str = ""
    provider: str = ""
    model: str = ""
    status: str = "ok"  # ok | disabled | unavailable | error
    error: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class EmbeddingResponse:
    """Structured outcome of an embedding request."""

    ok: bool
    vectors: list[list[float]] = field(default_factory=list)
    provider: str = ""
    model: str = ""
    status: str = "ok"
    error: str = ""


def _timeout(config: AIConfig, timeout_sec: float | None = None) -> httpx.Timeout:
    total = max(1.0, float(timeout_sec if timeout_sec is not None else config.timeout_sec))
    return httpx.Timeout(total, connect=min(5.0, total))


def _make_async_client(
    config: AIConfig,
    *,
    timeout_sec: float | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    kwargs: dict[str, Any] = {"timeout": _timeout(config, timeout_sec)}
    if transport is not None:
        kwargs["transport"] = transport
    return httpx.AsyncClient(**kwargs)


def _openai_url(base_url: str, suffix: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return suffix
    if not base.endswith("/v1") and suffix in {"chat/completions", "embeddings", "models"}:
        # Preserve explicit path if user supplied /openai/v1 or similar; only append
        # /v1 when the base URL is bare host:port.
        from urllib.parse import urlsplit

        parsed = urlsplit(base)
        if not parsed.path or parsed.path == "/":
            base = f"{base}/v1"
    return f"{base}/{suffix.lstrip('/')}"


def _extract_json_error(resp: httpx.Response) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict):
            err = data.get("error")
            if isinstance(err, dict):
                return redact(str(err.get("message") or err))
            if err:
                return redact(str(err))
    except Exception:  # noqa: BLE001
        pass
    return redact((resp.text or f"HTTP {resp.status_code}")[:300])


def _resolve_provider(config: AIConfig, provider_override: str | None = None) -> AIProviderKind:
    if provider_override:
        return AIProviderKind(str(provider_override).strip().lower())
    return config.provider


async def chat_completion(
    config: AIConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    provider_override: str | None = None,
    model_override: str | None = None,
    images_b64: list[str] | None = None,
    image_mime: str = "image/jpeg",
    json_mode: bool = False,
    max_tokens: int | None = None,
    timeout_sec: float | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AIResponse:
    """Execute a bounded chat/vision completion against the active provider."""
    provider = _resolve_provider(config, provider_override)
    if not config.enabled or provider == AIProviderKind.DISABLED:
        return AIResponse(
            ok=False,
            provider=provider.value,
            status="disabled",
            error="AI provider is disabled",
        )

    capped_tokens = max(32, min(int(max_tokens or config.max_tokens), 8192))
    images = [b for b in (images_b64 or []) if b][:MAX_IMAGE_COUNT]

    try:
        async with _make_async_client(config, timeout_sec=timeout_sec, transport=transport) as client:
            if provider == AIProviderKind.OLLAMA:
                return await _ollama_chat(
                    client,
                    config,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    model_override=model_override,
                    images_b64=images,
                    json_mode=json_mode,
                    max_tokens=capped_tokens,
                )
            if provider in {AIProviderKind.LMSTUDIO, AIProviderKind.OPENAI_COMPAT}:
                return await _openai_compat_chat(
                    client,
                    config,
                    provider=provider,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    model_override=model_override,
                    images_b64=images,
                    image_mime=image_mime,
                    json_mode=json_mode,
                    max_tokens=capped_tokens,
                )
            if provider == AIProviderKind.DEEPSEEK:
                return await _deepseek_chat(
                    client,
                    config,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    model_override=model_override,
                    json_mode=json_mode,
                    max_tokens=capped_tokens,
                )
            if provider == AIProviderKind.GEMINI:
                return await _gemini_chat(
                    client,
                    config,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    model_override=model_override,
                    images_b64=images,
                    image_mime=image_mime,
                    json_mode=json_mode,
                    max_tokens=capped_tokens,
                )
    except httpx.TimeoutException as exc:
        return AIResponse(
            ok=False,
            provider=provider.value,
            status="unavailable",
            error=redact(f"AI request timed out: {type(exc).__name__}"),
        )
    except httpx.HTTPError as exc:
        return AIResponse(
            ok=False,
            provider=provider.value,
            status="unavailable",
            error=redact(f"AI endpoint unreachable: {type(exc).__name__}: {exc}"),
        )
    except Exception as exc:  # noqa: BLE001
        return AIResponse(
            ok=False,
            provider=provider.value,
            status="error",
            error=redact(f"AI request failed: {type(exc).__name__}: {exc}"),
        )

    return AIResponse(
        ok=False,
        provider=provider.value,
        status="error",
        error=f"Unsupported AI provider: {provider.value}",
    )


def _effective_ollama_num_ctx(config: AIConfig) -> int:
    if "num_ctx" in config.model_fields_set:
        return int(config.num_ctx)
    if "ollama_num_ctx" in config.model_fields_set:
        return int(config.ollama_num_ctx)
    return int(config.num_ctx or config.ollama_num_ctx)


def _effective_ollama_keep_alive(config: AIConfig) -> str:
    if "keep_alive" in config.model_fields_set and config.keep_alive:
        return str(config.keep_alive)
    if "ollama_keep_alive" in config.model_fields_set and config.ollama_keep_alive:
        return str(config.ollama_keep_alive)
    return str(config.keep_alive or config.ollama_keep_alive or "2m")


async def _ollama_chat(
    client: httpx.AsyncClient,
    config: AIConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    model_override: str | None,
    images_b64: list[str],
    json_mode: bool,
    max_tokens: int,
) -> AIResponse:
    default_model = config.ollama_vision_model if images_b64 else config.ollama_model
    model = (model_override or default_model).strip()
    user_msg: dict[str, Any] = {"role": "user", "content": user_prompt}
    if images_b64:
        user_msg["images"] = images_b64
    num_ctx = _effective_ollama_num_ctx(config)
    keep_alive = _effective_ollama_keep_alive(config)
    options: dict[str, Any] = {
        "temperature": config.temperature,
        "num_predict": max_tokens,
    }
    if num_ctx > 0:
        options["num_ctx"] = num_ctx
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            user_msg,
        ],
        "stream": False,
        "options": options,
    }
    if keep_alive:
        payload["keep_alive"] = keep_alive
    if json_mode:
        payload["format"] = "json"
    url = f"{config.ollama_host.rstrip('/')}/api/chat"
    resp = await client.post(url, json=payload)
    if resp.status_code >= 400:
        return AIResponse(
            ok=False,
            provider="ollama",
            model=model,
            status="error" if resp.status_code < 500 else "unavailable",
            error=f"Ollama HTTP {resp.status_code}: {_extract_json_error(resp)}",
        )
    data = resp.json()
    message = data.get("message") if isinstance(data, dict) else {}
    text = str((message or {}).get("content") or "")
    usage = {}
    if isinstance(data, dict):
        if "prompt_eval_count" in data:
            usage["prompt_tokens"] = int(data.get("prompt_eval_count") or 0)
        if "eval_count" in data:
            usage["completion_tokens"] = int(data.get("eval_count") or 0)
    return AIResponse(
        ok=bool(text),
        text=text,
        provider="ollama",
        model=model,
        status="ok" if text else "error",
        error="" if text else "Ollama returned empty response",
        usage=usage,
        raw=data if isinstance(data, dict) else {},
    )


async def _openai_compat_chat(
    client: httpx.AsyncClient,
    config: AIConfig,
    *,
    provider: AIProviderKind,
    system_prompt: str,
    user_prompt: str,
    model_override: str | None,
    images_b64: list[str],
    image_mime: str,
    json_mode: bool,
    max_tokens: int,
) -> AIResponse:
    if provider == AIProviderKind.LMSTUDIO:
        base_url = config.lmstudio_base_url
        api_key = ""
        default_model = (
            config.lmstudio_vision_model
            if images_b64 and config.lmstudio_vision_model
            else config.lmstudio_model
        )
    else:
        base_url = config.openai_base_url
        api_key = config.openai_api_key.strip()
        default_model = (
            config.openai_vision_model
            if images_b64 and config.openai_vision_model
            else config.openai_model
        )
    model = (model_override or default_model).strip()
    if provider == AIProviderKind.OPENAI_COMPAT and not api_key and "127.0.0.1" not in base_url and "localhost" not in base_url:
        return AIResponse(
            ok=False,
            provider=provider.value,
            model=model,
            status="unavailable",
            error="OPENAI_API_KEY not configured",
        )

    if images_b64:
        user_content: Any = [{"type": "text", "text": user_prompt}]
        for b64 in images_b64:
            user_content.append({"type": "image_url", "image_url": {"url": f"data:{image_mime};base64,{b64}"}})
    else:
        user_content = user_prompt

    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": config.temperature,
        "max_tokens": max_tokens,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    url = _openai_url(base_url, "chat/completions")
    resp = await client.post(url, json=payload, headers=headers)
    if resp.status_code >= 400:
        return AIResponse(
            ok=False,
            provider=provider.value,
            model=model,
            status="error" if resp.status_code < 500 else "unavailable",
            error=f"{provider.value} HTTP {resp.status_code}: {_extract_json_error(resp)}",
        )
    data = resp.json()
    choices = data.get("choices") if isinstance(data, dict) else None
    text = ""
    if isinstance(choices, list) and choices:
        msg = choices[0].get("message") if isinstance(choices[0], dict) else {}
        text = str((msg or {}).get("content") or "")
    usage = data.get("usage") if isinstance(data, dict) and isinstance(data.get("usage"), dict) else {}
    return AIResponse(
        ok=bool(text),
        text=text,
        provider=provider.value,
        model=model,
        status="ok" if text else "error",
        error="" if text else f"{provider.value} returned empty completion",
        usage={k: int(v) for k, v in usage.items() if isinstance(v, (int, float))},
        raw=data if isinstance(data, dict) else {},
    )


async def _deepseek_chat(
    client: httpx.AsyncClient,
    config: AIConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    model_override: str | None,
    json_mode: bool,
    max_tokens: int,
) -> AIResponse:
    api_key = config.deepseek_api_key.strip()
    model = (model_override or config.deepseek_model).strip()
    if not api_key:
        return AIResponse(
            ok=False,
            provider="deepseek",
            model=model,
            status="unavailable",
            error="DEEPSEEK_API_KEY not configured",
        )
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": config.temperature,
        "max_tokens": max_tokens,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    url = f"{config.deepseek_base_url.rstrip('/')}/chat/completions"
    resp = await client.post(
        url,
        json=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    if resp.status_code >= 400:
        return AIResponse(
            ok=False,
            provider="deepseek",
            model=model,
            status="error" if resp.status_code < 500 else "unavailable",
            error=f"DeepSeek HTTP {resp.status_code}: {_extract_json_error(resp)}",
        )
    data = resp.json()
    choices = data.get("choices") if isinstance(data, dict) else None
    text = ""
    if isinstance(choices, list) and choices:
        msg = choices[0].get("message") if isinstance(choices[0], dict) else {}
        text = str((msg or {}).get("content") or "")
    usage = data.get("usage") if isinstance(data, dict) and isinstance(data.get("usage"), dict) else {}
    return AIResponse(
        ok=bool(text),
        text=text,
        provider="deepseek",
        model=model,
        status="ok" if text else "error",
        error="" if text else "DeepSeek returned empty completion",
        usage={k: int(v) for k, v in usage.items() if isinstance(v, (int, float))},
        raw=data if isinstance(data, dict) else {},
    )


async def _gemini_chat(
    client: httpx.AsyncClient,
    config: AIConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    model_override: str | None,
    images_b64: list[str],
    image_mime: str,
    json_mode: bool,
    max_tokens: int,
) -> AIResponse:
    api_key = config.gemini_api_key.strip()
    model = (model_override or config.gemini_model).strip()
    if not api_key:
        return AIResponse(
            ok=False,
            provider="gemini",
            model=model,
            status="unavailable",
            error="GEMINI_API_KEY not configured",
        )
    parts: list[dict[str, Any]] = [{"text": user_prompt}]
    for b64 in images_b64:
        parts.append({"inlineData": {"mimeType": image_mime, "data": b64}})
    gen_cfg: dict[str, Any] = {
        "temperature": config.temperature,
        "maxOutputTokens": max_tokens,
    }
    if json_mode:
        gen_cfg["responseMimeType"] = "application/json"
    payload: dict[str, Any] = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": gen_cfg,
    }
    url = f"{config.gemini_base_url.rstrip('/')}/models/{model}:generateContent"
    resp = await client.post(
        url,
        json=payload,
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
        },
    )
    if resp.status_code >= 400:
        return AIResponse(
            ok=False,
            provider="gemini",
            model=model,
            status="error" if resp.status_code < 500 else "unavailable",
            error=f"Gemini HTTP {resp.status_code}: {_extract_json_error(resp)}",
        )
    data = resp.json()
    text = ""
    candidates = data.get("candidates") if isinstance(data, dict) else None
    if isinstance(candidates, list) and candidates:
        content = candidates[0].get("content") if isinstance(candidates[0], dict) else {}
        resp_parts = (content or {}).get("parts") or []
        text = "".join(str(p.get("text") or "") for p in resp_parts if isinstance(p, dict))
    meta = data.get("usageMetadata") if isinstance(data, dict) and isinstance(data.get("usageMetadata"), dict) else {}
    usage = {}
    if "promptTokenCount" in meta:
        usage["prompt_tokens"] = int(meta["promptTokenCount"])
    if "candidatesTokenCount" in meta:
        usage["completion_tokens"] = int(meta["candidatesTokenCount"])
    return AIResponse(
        ok=bool(text),
        text=text,
        provider="gemini",
        model=model,
        status="ok" if text else "error",
        error="" if text else "Gemini returned empty completion",
        usage=usage,
        raw=data if isinstance(data, dict) else {},
    )


async def fetch_embeddings(
    config: AIConfig,
    texts: list[str],
    *,
    provider_override: str | None = None,
    model_override: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> EmbeddingResponse:
    """Fetch dense embeddings from Ollama or OpenAI-compatible/LM Studio endpoints."""
    provider = _resolve_provider(config, provider_override)
    if not config.enabled or provider == AIProviderKind.DISABLED:
        return EmbeddingResponse(ok=False, provider=provider.value, status="disabled",
                                 error="AI provider is disabled")
    clean_texts = [str(t or "")[:4000] for t in texts if str(t or "").strip()]
    if not clean_texts:
        return EmbeddingResponse(ok=False, provider=provider.value, status="error",
                                 error="No non-empty texts provided")

    try:
        async with _make_async_client(config, transport=transport) as client:
            if provider == AIProviderKind.OLLAMA:
                model = (model_override or config.ollama_embedding_model).strip()
                url = f"{config.ollama_host.rstrip('/')}/api/embeddings"
                keep_alive = _effective_ollama_keep_alive(config)
                vectors: list[list[float]] = []
                for item in clean_texts:
                    emb_payload: dict[str, Any] = {
                        "model": model,
                        "prompt": item,
                    }
                    if keep_alive:
                        emb_payload["keep_alive"] = keep_alive
                    resp = await client.post(url, json=emb_payload)
                    if resp.status_code >= 400:
                        return EmbeddingResponse(
                            ok=False,
                            provider="ollama",
                            model=model,
                            status="unavailable",
                            error=f"Ollama embeddings HTTP {resp.status_code}: {_extract_json_error(resp)}",
                        )
                    vec = resp.json().get("embedding")
                    if not isinstance(vec, list) or not vec:
                        return EmbeddingResponse(
                            ok=False, provider="ollama", model=model, status="error",
                            error="Ollama returned empty embedding",
                        )
                    vectors.append([float(x) for x in vec])
                return EmbeddingResponse(ok=True, vectors=vectors, provider="ollama", model=model)

            if provider in {AIProviderKind.LMSTUDIO, AIProviderKind.OPENAI_COMPAT}:
                base_url = (
                    config.lmstudio_base_url
                    if provider == AIProviderKind.LMSTUDIO
                    else config.openai_base_url
                )
                api_key = "" if provider == AIProviderKind.LMSTUDIO else config.openai_api_key.strip()
                default_model = (
                    config.lmstudio_embedding_model or config.lmstudio_model
                    if provider == AIProviderKind.LMSTUDIO
                    else config.openai_embedding_model
                )
                model = (model_override or default_model).strip()
                headers = {"Content-Type": "application/json"}
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                url = _openai_url(base_url, "embeddings")
                resp = await client.post(
                    url,
                    json={"model": model, "input": clean_texts},
                    headers=headers,
                )
                if resp.status_code >= 400:
                    return EmbeddingResponse(
                        ok=False,
                        provider=provider.value,
                        model=model,
                        status="unavailable",
                        error=f"{provider.value} embeddings HTTP {resp.status_code}: {_extract_json_error(resp)}",
                    )
                rows = resp.json().get("data") or []
                vectors = [
                    [float(x) for x in item.get("embedding", [])]
                    for item in sorted(rows, key=lambda r: int(r.get("index", 0)))
                    if isinstance(item, dict) and isinstance(item.get("embedding"), list)
                ]
                if len(vectors) != len(clean_texts):
                    return EmbeddingResponse(
                        ok=False, provider=provider.value, model=model, status="error",
                        error="Embedding count mismatch",
                    )
                return EmbeddingResponse(ok=True, vectors=vectors, provider=provider.value, model=model)
    except httpx.TimeoutException:
        return EmbeddingResponse(ok=False, provider=provider.value, status="unavailable",
                                 error="Embedding request timed out")
    except httpx.HTTPError as exc:
        return EmbeddingResponse(ok=False, provider=provider.value, status="unavailable",
                                 error=redact(f"Embedding endpoint unreachable: {exc}"))
    except Exception as exc:  # noqa: BLE001
        return EmbeddingResponse(ok=False, provider=provider.value, status="error",
                                 error=redact(f"Embedding error: {exc}"))

    return EmbeddingResponse(
        ok=False,
        provider=provider.value,
        status="unavailable",
        error=f"Embeddings not supported for provider {provider.value}",
    )


def probe_local_endpoints_sync(
    config: AIConfig,
    *,
    timeout_sec: float = 2.0,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Probe local Ollama and LM Studio health endpoints safely (sync, non-raising)."""
    probes: dict[str, Any] = {}
    client_kwargs: dict[str, Any] = {"timeout": httpx.Timeout(timeout_sec, connect=timeout_sec)}
    if transport is not None:
        client_kwargs["transport"] = transport

    with httpx.Client(**client_kwargs) as client:
        # Ollama /api/tags
        ollama_url = f"{config.ollama_host.rstrip('/')}/api/tags"
        try:
            resp = client.get(ollama_url)
            if resp.status_code == 200:
                models = [
                    str(m.get("name"))
                    for m in (resp.json().get("models") or [])
                    if isinstance(m, dict) and m.get("name")
                ]
                probes["ollama"] = {"reachable": True, "models": models[:20], "url": ollama_url}
            else:
                probes["ollama"] = {"reachable": False, "status_code": resp.status_code, "url": ollama_url}
        except Exception as exc:  # noqa: BLE001
            probes["ollama"] = {"reachable": False, "detail": redact(type(exc).__name__), "url": ollama_url}

        # LM Studio /v1/models
        lms_url = _openai_url(config.lmstudio_base_url, "models")
        try:
            resp = client.get(lms_url)
            if resp.status_code == 200:
                models = [
                    str(m.get("id"))
                    for m in (resp.json().get("data") or [])
                    if isinstance(m, dict) and m.get("id")
                ]
                probes["lmstudio"] = {"reachable": True, "models": models[:20], "url": lms_url}
            else:
                probes["lmstudio"] = {"reachable": False, "status_code": resp.status_code, "url": lms_url}
        except Exception as exc:  # noqa: BLE001
            probes["lmstudio"] = {"reachable": False, "detail": redact(type(exc).__name__), "url": lms_url}

    return probes


def strip_json_fences(text: str) -> str:
    """Remove optional Markdown ```json fences around a JSON payload."""
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return cleaned


def parse_json_object(text: str) -> dict[str, Any]:
    """Parse a JSON object from model text, tolerating surrounding prose."""
    cleaned = strip_json_fences(text)
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        parsed = json.loads(cleaned[start : end + 1])
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("Model response did not contain a valid JSON object")


__all__ = [
    "AIResponse",
    "EmbeddingResponse",
    "chat_completion",
    "fetch_embeddings",
    "probe_local_endpoints_sync",
    "strip_json_fences",
    "parse_json_object",
]
