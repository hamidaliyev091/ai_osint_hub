"""Local embedding correlation with 100% offline deterministic fallback.

When AI is enabled and Ollama/LM Studio/OpenAI embeddings are reachable,
``correlate_texts`` uses dense embedding cosine similarity. When AI is disabled
or offline, it transparently falls back to a deterministic blend of character
n-gram TF-IDF cosine similarity and Jaro-Winkler string similarity.
"""

from __future__ import annotations

import importlib.util
import io
import math
import threading
import unicodedata
from collections import Counter
from typing import Any, Sequence

import httpx

from hub.ai.config import load_ai_config
from hub.ai.models import AIConfig, AIProviderKind
from hub.ai.providers import fetch_embeddings

_FASTEMBED_LOCK = threading.RLock()
_FASTEMBED_TEXT_MODELS: dict[str, Any] = {}
_FASTEMBED_IMAGE_MODELS: dict[str, Any] = {}


def fastembed_availability() -> dict[str, Any]:
    """Check whether optional ``fastembed`` (``[local-ai]``) is installed without loading weights."""
    installed = importlib.util.find_spec("fastembed") is not None
    return {
        "available": installed,
        "text_model": "BAAI/bge-small-en-v1.5",
        "vision_model": "Qdrant/clip-ViT-B-32-vision",
        "install_hint": 'pip install "ai-osint-hub[local-ai]"',
    }


def embed_fastembed_texts(
    texts: Sequence[str],
    *,
    model_name: str = "BAAI/bge-small-en-v1.5",
) -> list[list[float]] | None:
    """Compute dense embeddings via ``fastembed`` if installed; else return ``None``."""
    clean = [str(t or "")[:4000] for t in texts if str(t or "").strip()]
    if not clean:
        return None
    try:
        from fastembed import TextEmbedding
    except ImportError:
        return None
    try:
        with _FASTEMBED_LOCK:
            model = _FASTEMBED_TEXT_MODELS.get(model_name)
            if model is None:
                model = TextEmbedding(model_name=model_name)
                _FASTEMBED_TEXT_MODELS[model_name] = model
        vectors = [list(map(float, vec)) for vec in model.embed(clean)]
        return vectors if len(vectors) == len(clean) else None
    except Exception:  # noqa: BLE001
        return None


def embed_image_bytes(
    raw_bytes: bytes,
    *,
    config: AIConfig | None = None,
    model_name: str = "Qdrant/clip-ViT-B-32-vision",
) -> list[float] | None:
    """Compute a CLIP image embedding via ``fastembed`` when ``local_embedded`` is enabled."""
    cfg = config or load_ai_config()
    if not cfg.enabled or (cfg.provider != AIProviderKind.LOCAL_EMBEDDED and cfg.mode != "local_embedded"):
        return None
    if not raw_bytes:
        return None
    try:
        from fastembed import ImageEmbedding
        from PIL import Image
    except ImportError:
        return None
    try:
        target_model = cfg.local_embedded_vision_model or model_name
        with Image.open(io.BytesIO(raw_bytes)) as img:
            rgb = img.convert("RGB")
            with _FASTEMBED_LOCK:
                model = _FASTEMBED_IMAGE_MODELS.get(target_model)
                if model is None:
                    model = ImageEmbedding(model_name=target_model)
                    _FASTEMBED_IMAGE_MODELS[target_model] = model
            vecs = list(model.embed([rgb]))
            if vecs:
                return [float(x) for x in vecs[0]]
    except Exception:  # noqa: BLE001
        return None
    return None


def cosine_similarity(vec_a: Sequence[float], vec_b: Sequence[float]) -> float:
    """Compute cosine similarity between two dense vectors in [0.0, 1.0] (clamped)."""
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a <= 0.0 or norm_b <= 0.0:
        return 0.0
    return max(-1.0, min(1.0, dot / (norm_a * norm_b)))


def jaro_winkler_similarity(s1: str, s2: str, *, p: float = 0.1) -> float:
    """Deterministic Jaro-Winkler similarity in [0.0, 1.0]."""
    a = unicodedata.normalize("NFKC", (s1 or "").strip().lower())
    b = unicodedata.normalize("NFKC", (s2 or "").strip().lower())
    if a == b:
        return 1.0 if a else 0.0
    if not a or not b:
        return 0.0

    max_dist = max(0, max(len(a), len(b)) // 2 - 1)
    a_matches = [False] * len(a)
    b_matches = [False] * len(b)
    matches = 0
    for i, ch in enumerate(a):
        start = max(0, i - max_dist)
        end = min(len(b), i + max_dist + 1)
        for j in range(start, end):
            if not b_matches[j] and ch == b[j]:
                a_matches[i] = True
                b_matches[j] = True
                matches += 1
                break
    if matches == 0:
        return 0.0

    transpositions = 0
    k = 0
    for i in range(len(a)):
        if not a_matches[i]:
            continue
        while not b_matches[k]:
            k += 1
        if a[i] != b[k]:
            transpositions += 1
        k += 1
    transpositions //= 2

    jaro = (
        (matches / len(a))
        + (matches / len(b))
        + ((matches - transpositions) / matches)
    ) / 3.0

    prefix = 0
    for ch_a, ch_b in zip(a[:4], b[:4]):
        if ch_a == ch_b:
            prefix += 1
        else:
            break
    return min(1.0, jaro + prefix * p * (1.0 - jaro))


def _char_ngrams(text: str, n: int = 3) -> list[str]:
    norm = unicodedata.normalize("NFKC", (text or "").strip().lower())
    if not norm:
        return []
    padded = f"^{norm}$"
    if len(padded) < n:
        return [padded]
    return [padded[i : i + n] for i in range(len(padded) - n + 1)]


def char_ngram_tfidf_vectors(texts: Sequence[str], n: int = 3) -> list[dict[str, float]]:
    """Compute L2-normalized sparse character n-gram TF-IDF vectors."""
    docs = [_char_ngrams(t, n=n) for t in texts]
    num_docs = len(docs)
    if num_docs == 0:
        return []
    df: Counter[str] = Counter()
    for grams in docs:
        df.update(set(grams))

    vectors: list[dict[str, float]] = []
    for grams in docs:
        if not grams:
            vectors.append({})
            continue
        tf = Counter(grams)
        total = float(len(grams))
        vec: dict[str, float] = {}
        for gram, count in tf.items():
            idf = math.log((1.0 + num_docs) / (1.0 + df[gram])) + 1.0
            vec[gram] = (count / total) * idf
        norm = math.sqrt(sum(w * w for w in vec.values()))
        if norm > 0.0:
            vec = {k: v / norm for k, v in vec.items()}
        vectors.append(vec)
    return vectors


def sparse_cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    """Cosine similarity for L2-normalized sparse TF-IDF dicts."""
    if not vec_a or not vec_b:
        return 0.0
    if len(vec_a) > len(vec_b):
        vec_a, vec_b = vec_b, vec_a
    return max(0.0, min(1.0, sum(w * vec_b.get(k, 0.0) for k, w in vec_a.items())))


def deterministic_text_similarity(text_a: str, text_b: str) -> float:
    """Pure offline similarity combining char 3-gram TF-IDF cosine and Jaro-Winkler."""
    vecs = char_ngram_tfidf_vectors([text_a, text_b], n=3)
    tfidf_cos = sparse_cosine_similarity(vecs[0], vecs[1])
    jw = jaro_winkler_similarity(text_a, text_b)
    return round(0.6 * tfidf_cos + 0.4 * jw, 4)


async def embed_texts(
    texts: list[str],
    *,
    config: AIConfig | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[list[list[float]] | None, str]:
    """Return ``(vectors, 'provider')`` when AI embeddings succeed, else ``(None, 'fallback')``."""
    cfg = config or load_ai_config()
    res = await fetch_embeddings(cfg, texts, transport=transport)
    if res.ok and len(res.vectors) == len(texts):
        return res.vectors, f"{res.provider}:{res.model}"
    return None, "fallback"


async def correlate_texts(
    query: str,
    candidates: list[str],
    *,
    config: AIConfig | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """Rank ``candidates`` by similarity to ``query`` (embeddings or offline fallback)."""
    clean_query = (query or "").strip()
    clean_candidates = [str(c or "").strip() for c in candidates if str(c or "").strip()]
    if not clean_query or not clean_candidates:
        return []

    cfg = config or load_ai_config()
    all_texts = [clean_query] + clean_candidates
    vectors, method = await embed_texts(all_texts, config=cfg, transport=transport)

    results: list[dict[str, Any]] = []
    if vectors is not None:
        q_vec = vectors[0]
        for idx, cand in enumerate(clean_candidates):
            score = round(max(0.0, cosine_similarity(q_vec, vectors[idx + 1])), 4)
            results.append({
                "text": cand,
                "score": score,
                "method": method,
                "jaro_winkler": round(jaro_winkler_similarity(clean_query, cand), 4),
            })
    else:
        tfidf_vecs = char_ngram_tfidf_vectors(all_texts, n=3)
        q_vec = tfidf_vecs[0]
        for idx, cand in enumerate(clean_candidates):
            tfidf_score = sparse_cosine_similarity(q_vec, tfidf_vecs[idx + 1])
            jw_score = jaro_winkler_similarity(clean_query, cand)
            blended = round(0.6 * tfidf_score + 0.4 * jw_score, 4)
            results.append({
                "text": cand,
                "score": blended,
                "method": "offline_trigram_jw",
                "tfidf_cosine": round(tfidf_score, 4),
                "jaro_winkler": round(jw_score, 4),
            })

    results.sort(key=lambda item: (-item["score"], item["text"]))
    return results[: max(1, int(top_k))]


__all__ = [
    "fastembed_availability",
    "embed_fastembed_texts",
    "embed_image_bytes",
    "cosine_similarity",
    "jaro_winkler_similarity",
    "char_ngram_tfidf_vectors",
    "sparse_cosine_similarity",
    "deterministic_text_similarity",
    "embed_texts",
    "correlate_texts",
]
