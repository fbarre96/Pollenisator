"""
Embedding management for the AI defect extraction pipeline.

Templates in the "pollenisator" DB are embedded as (title + synthesis) vectors.
Embeddings are stored as a float list directly on the defect template document
under the "embedding" field — no external vector store required.

Cosine similarity is computed in-process with numpy (vectorised matmul over the
entire template matrix: ~0.5 ms for 1000 templates).

Provider flexibility: every call goes through litellm, so OpenAI, Ollama,
Azure OpenAI, Mistral, Anthropic (via proxy), etc. all work by just changing
the settings stored in the global "pollenisator" settings collection.
"""

import threading
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from bson import ObjectId

from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.mongo import DBClient

# ------------------------------------------------------------------
# Setting keys stored in the global pollenisator.settings collection
# ------------------------------------------------------------------
AI_SETTING_KEYS = [
    "ai_api_key",
    "ai_model",
    "ai_base_url",
    "ai_embedding_model",
    "ai_similarity_threshold",
    "ai_prompt_verify_system",
    "ai_prompt_synthesis_system",
]


def get_ai_settings() -> Dict[str, Any]:
    """Read all AI-related settings from the global pollenisator settings collection."""
    dbclient = DBClient.getInstance()
    result: Dict[str, Any] = {}
    for key in AI_SETTING_KEYS:
        rec = dbclient.findInDb("pollenisator", "settings", {"key": key}, False)
        result[key] = rec["value"] if rec else None
    return result


# ------------------------------------------------------------------
# Embedding helpers
# ------------------------------------------------------------------

def embed_texts(texts: List[str], settings: Dict[str, Any]) -> List[List[float]]:
    """
    Embed a list of texts using litellm (any provider).

    Args:
        texts: Strings to embed.
        settings: AI settings dict from get_ai_settings().

    Returns:
        List of float vectors, one per input text.
    """
    from litellm import embedding as litellm_embedding  # lazy import

    model: str = settings.get("ai_embedding_model") or "text-embedding-3-small"
    kwargs: Dict[str, Any] = {
        "model": model,
        "input": texts,
    }
    if settings.get("ai_api_key"):
        kwargs["api_key"] = settings["ai_api_key"]
    if settings.get("ai_base_url"):
        kwargs["api_base"] = settings["ai_base_url"]

    response = litellm_embedding(**kwargs)
    return [item["embedding"] for item in response.data]


# ------------------------------------------------------------------
# Index management
# ------------------------------------------------------------------

def embed_all_templates() -> int:
    """
    (Re)build the embedding index for every defect template in the
    "pollenisator" DB.  Embeddings are stored in-place on each document.

    Returns:
        Number of templates processed.
    """
    dbclient = DBClient.getInstance()
    settings = get_ai_settings()

    templates = list(dbclient.findInDb("pollenisator", "defects", {}, multi=True))
    if not templates:
        return 0

    texts = [
        f"{t.get('title', '')}. {t.get('synthesis', '')}"
        for t in templates
    ]

    # Batch to respect provider limits (OpenAI allows 2048, local models may not)
    BATCH_SIZE = 50
    all_embeddings: List[List[float]] = []
    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i: i + BATCH_SIZE]
        all_embeddings.extend(embed_texts(batch, settings))

    for template, emb in zip(templates, all_embeddings):
        dbclient.updateInDb(
            "pollenisator", "defects",
            {"_id": template["_id"]},
            {"$set": {"embedding": emb}},
            notify=False,
        )

    logger.info(f"AI: embedded {len(templates)} defect templates.")
    return len(templates)


def embed_single_async(template_id: ObjectId) -> None:
    """
    Fire-and-forget: re-embed a single template after it is created/updated.
    Runs in a daemon thread so it never blocks the HTTP request.
    Silently skips if AI is not configured.
    """
    def _do() -> None:
        try:
            settings = get_ai_settings()
            # Skip silently when AI is not yet configured
            if not settings.get("ai_api_key") and not settings.get("ai_base_url"):
                return
            dbclient = DBClient.getInstance()
            template = dbclient.findInDb(
                "pollenisator", "defects", {"_id": template_id}, False
            )
            if template is None:
                return
            text = f"{template.get('title', '')}. {template.get('synthesis', '')}"
            embs = embed_texts([text], settings)
            dbclient.updateInDb(
                "pollenisator", "defects",
                {"_id": template_id},
                {"$set": {"embedding": embs[0]}},
                notify=False,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"AI: failed to embed template {template_id}: {exc}")

    threading.Thread(target=_do, daemon=True).start()


# ------------------------------------------------------------------
# Similarity search
# ------------------------------------------------------------------

def cosine_top_k(
    query_vec: List[float],
    language: str = "",
    k: int = 5,
    threshold: float = 0.60,
) -> List[Tuple[Dict[str, Any], float]]:
    """
    Return the top-k defect templates whose (title + synthesis) embedding is
    most similar to query_vec, filtering by cosine similarity >= threshold.

    Uses a vectorised numpy matmul over all stored embeddings — no external
    vector database required.

    Args:
        query_vec: Query embedding vector.
        language: If non-empty, restrict to templates whose language field
                  contains this string (case-insensitive).
        k: Maximum number of results.
        threshold: Minimum cosine similarity to include in results.

    Returns:
        List of (template_doc, score) tuples, sorted by descending score.
    """
    dbclient = DBClient.getInstance()

    mongo_filter: Dict[str, Any] = {"embedding": {"$exists": True}}
    if language:
        mongo_filter["language"] = {"$regex": language, "$options": "i"}

    templates = list(
        dbclient.findInDb("pollenisator", "defects", mongo_filter, multi=True)
    )
    if not templates:
        return []

    qv = np.array(query_vec, dtype=np.float32)
    qnorm = float(np.linalg.norm(qv))
    if qnorm < 1e-10:
        return []
    qv /= qnorm

    # Build matrix: (N, D)
    all_vecs = np.array(
        [t["embedding"] for t in templates], dtype=np.float32
    )
    norms = np.linalg.norm(all_vecs, axis=1, keepdims=True)
    norms = np.where(norms < 1e-10, 1.0, norms)
    all_vecs /= norms

    # Scores: (N,)
    scores: List[float] = (all_vecs @ qv).tolist()

    scored = [
        (templates[i], scores[i])
        for i in range(len(templates))
        if scores[i] >= threshold
    ]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:k]
