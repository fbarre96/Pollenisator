"""
AI module API handlers.

Endpoints:
  POST /ai/{pentest}/analyze          — start extraction pipeline
  GET  /ai/{pentest}/job/{job_id}     — poll job status
  GET  /ai/{pentest}/synthesis        — latest AI executive synthesis
  POST /ai/admin/embed-templates      — rebuild embedding index (admin)
  GET  /ai/admin/settings             — read AI settings (admin)
  PUT  /ai/admin/settings             — write AI settings (admin)
"""

import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.mongo import DBClient
from pollenisator.server.permission import permission
from pollenisator.server.modules.ai.embedder import (
    AI_SETTING_KEYS,
    embed_all_templates,
    get_ai_settings,
)

ErrorStatus = Tuple[str, int]


# ---------------------------------------------------------------------------
# Pentest-scoped endpoints
# ---------------------------------------------------------------------------

@permission("pentester")
def analyze(
    pentest: str,
    body: Dict[str, Any],
    **kwargs: Any,
) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Start the AI defect extraction pipeline for a pentest.

    Accepts the raw pentest notes and an optional language code.
    Returns a ``job_id`` immediately; poll ``/ai/{pentest}/job/{job_id}``
    for progress.
    """
    from pollenisator.server.modules.ai.pipeline import run_pipeline

    notes: str = body.get("notes", "").strip()
    if not notes:
        return "notes field is required and cannot be empty", 400

    language: str = body.get("language", "en")
    username: str = kwargs["token_info"]["sub"]

    settings = get_ai_settings()
    if not settings.get("ai_api_key") and not settings.get("ai_base_url"):
        return (
            "AI is not configured. "
            "Set ai_api_key (and optionally ai_base_url) via "
            "PUT /ai/admin/settings",
            503,
        )

    job_id = str(uuid.uuid4())
    dbclient = DBClient.getInstance()
    dbclient.updateInDb(
        pentest, "ai_jobs",
        {"job_id": job_id},
        {"$set": {
            "job_id": job_id,
            "pentest": pentest,
            "status": "pending",
            "progress_pct": 0,
            "step": "queued",
            "defects_created": 0,
            "error": None,
            "created_at": datetime.now(),
        }},
        upsert=True, notify=False,
    )

    thread = threading.Thread(
        target=run_pipeline,
        args=(pentest, job_id, notes, language, username),
        daemon=True,
    )
    thread.start()

    return {"job_id": job_id, "status": "pending"}


@permission("pentester")
def get_job(
    pentest: str,
    job_id: str,
    **kwargs: Any,
) -> Union[ErrorStatus, Dict[str, Any]]:
    """Poll the status of an AI extraction job."""
    dbclient = DBClient.getInstance()
    job = dbclient.findInDb(pentest, "ai_jobs", {"job_id": job_id}, False)
    if job is None:
        return "Job not found", 404

    job.pop("_id", None)
    # Serialise datetime fields
    for field in ("created_at", "completed_at"):
        if isinstance(job.get(field), datetime):
            job[field] = job[field].isoformat()
    return job


@permission("pentester")
def get_synthesis(
    pentest: str,
    **kwargs: Any,
) -> Union[ErrorStatus, Dict[str, Any]]:
    """Return the latest AI executive synthesis for a pentest."""
    dbclient = DBClient.getInstance()
    synthesis = dbclient.findInDb(
        pentest, "ai_synthesis", {"type": "synthesis"}, False
    )
    if synthesis is None:
        return "No AI synthesis found for this pentest", 404

    synthesis.pop("_id", None)
    if isinstance(synthesis.get("generated_at"), datetime):
        synthesis["generated_at"] = synthesis["generated_at"].isoformat()
    return synthesis


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@permission("admin")
def embed_templates(**kwargs: Any) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Rebuild the embedding index for all defect templates.

    Call this once after initial setup and whenever templates are bulk-imported.
    Individual template saves auto-trigger incremental re-embedding.
    """
    try:
        count = embed_all_templates()
        return {"embedded": count, "status": "ok"}
    except Exception as exc:  # noqa: BLE001
        logger.exception(f"AI: embed-templates failed: {exc}")
        return f"Embedding failed: {exc}", 500


@permission("admin")
def get_settings(**kwargs: Any) -> Union[ErrorStatus, Dict[str, Any]]:
    """Return current AI settings (API key is masked for security)."""
    settings = get_ai_settings()
    # Mask the key value for display
    key = settings.get("ai_api_key")
    if key:
        settings["ai_api_key"] = (key[:8] + "***") if len(key) > 8 else "***"
    return {k: v for k, v in settings.items() if v is not None}


@permission("admin")
def update_settings(
    body: Dict[str, Any],
    **kwargs: Any,
) -> Union[ErrorStatus, Dict[str, Any]]:
    """
    Persist AI settings to the global pollenisator settings collection.

    Accepted keys: ai_api_key, ai_model, ai_base_url,
                   ai_embedding_model, ai_similarity_threshold.
    Unknown keys are ignored.
    """
    dbclient = DBClient.getInstance()
    allowed = set(AI_SETTING_KEYS)
    updated: List[str] = []
    for key, value in body.items():
        if key not in allowed:
            continue
        dbclient.updateInDb(
            "pollenisator", "settings",
            {"key": key},
            {"$set": {"key": key, "value": value}},
            upsert=True, notify=False,
        )
        updated.append(key)
    return {"updated": updated}
