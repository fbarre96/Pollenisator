"""
AI defect extraction pipeline — 5-stage RAG-anchored analysis.

Stage 0 — Dedup guard       : collect existing pentest defect titles
Stage 1 — Chunk + embed     : split notes into paragraphs, batch-embed
Stage 2 — Candidate retrieval: cosine top-k per chunk, group by template
Stage 3 — LLM verification  : single batched call with JSON-mode output
Stage 4 — Persist defects   : clone confirmed templates into the pentest
Stage 5 — Synthesis         : executive summary from confirmed evidence list

Token budget (typical run with 4 chunks, 5 candidates/chunk):
  - Verification call : ~3 000–6 000 tokens
  - Synthesis call    : ~1 000–1 500 tokens
  - Total             : ~5 000–8 000 tokens

The LLM never writes defect content.  All security-sensitive fields
(title, description, ease, impact, cvss, fixes, …) come verbatim from
pre-validated templates.  The LLM only answers: "confirmed? evidence?"
"""

import json
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId

from pollenisator.core.components.logger_config import logger
from pollenisator.core.components.mongo import DBClient
from pollenisator.core.models.defect import Defect
from pollenisator.server.modules.ai import prompts
from pollenisator.server.modules.ai.embedder import (
    cosine_top_k,
    embed_texts,
    get_ai_settings,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _update_job(pentest: str, job_id: str, data: Dict[str, Any]) -> None:
    """Upsert job status document (no SocketIO notification — polling is used)."""
    dbclient = DBClient.getInstance()
    dbclient.updateInDb(
        pentest, "ai_jobs",
        {"job_id": job_id},
        {"$set": data},
        upsert=True, notify=False,
    )


def _llm_call(messages: List[Dict[str, str]], settings: Dict[str, Any]) -> str:
    """
    Call the configured LLM via litellm.

    response_format=json_object guarantees a parseable JSON response on
    all providers that support it (OpenAI, Mistral, Ollama ≥ 0.3, …).
    Providers that do not support the flag (e.g. some Anthropic models) will
    still usually comply because the system prompt instructs JSON-only output.
    """
    from litellm import completion  # lazy import

    model: str = settings.get("ai_model") or "gpt-4o-mini"
    kwargs: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }
    if settings.get("ai_api_key"):
        kwargs["api_key"] = settings["ai_api_key"]
    if settings.get("ai_base_url"):
        kwargs["api_base"] = settings["ai_base_url"]

    response = completion(**kwargs)
    return response.choices[0].message.content


def _chunk_notes(notes: str) -> List[str]:
    """Split notes by blank lines; discard empty / noise lines."""
    paragraphs = [p.strip() for p in notes.split("\n\n")]
    return [p for p in paragraphs if len(p) > 20]


def _emit_socket(event: str, data: Dict[str, Any]) -> None:
    """Best-effort SocketIO notification (never raises)."""
    try:
        from pollenisator.core.components.socketmanager import SocketManager
        sm = SocketManager.getInstance()
        sm.socketio.emit(event, data)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    pentest: str,
    job_id: str,
    notes: str,
    language: str,
    username: str,
) -> None:
    """
    Execute the full 5-stage pipeline in a background thread.

    Progress is written to the ``ai_jobs`` collection so clients can poll
    ``GET /ai/{pentest}/job/{job_id}``.  SocketIO ``ai_complete`` /
    ``ai_error`` events are emitted as a bonus for real-time UIs.
    """
    dbclient = DBClient.getInstance()
    try:
        settings = get_ai_settings()
        threshold = float(settings.get("ai_similarity_threshold") or 0.65)

        # Resolve system prompts — admin overrides take precedence over module defaults
        verify_system_prompt: str = (
            settings.get("ai_prompt_verify_system") or prompts.VERIFY_SYSTEM
        )
        synthesis_system_prompt: str = (
            settings.get("ai_prompt_synthesis_system") or prompts.SYNTHESIS_SYSTEM
        )

        # ----------------------------------------------------------------
        # Stage 0 — Dedup guard
        # ----------------------------------------------------------------
        _update_job(pentest, job_id, {
            "status": "running", "progress_pct": 5, "step": "dedup",
        })
        existing_docs = list(dbclient.findInDb(
            pentest, "defects",
            {"target_id": None, "is_remark": {"$ne": True}},
            multi=True,
        ))
        existing_titles: List[str] = [d.get("title", "") for d in existing_docs]

        # ----------------------------------------------------------------
        # Stage 1 — Chunk + embed notes
        # ----------------------------------------------------------------
        _update_job(pentest, job_id, {"progress_pct": 15, "step": "embedding_notes"})
        chunks = _chunk_notes(notes)
        if not chunks:
            _update_job(pentest, job_id, {
                "status": "completed", "progress_pct": 100,
                "defects_created": 0, "step": "done",
                "error": "No usable text paragraphs found in notes.",
                "completed_at": datetime.now(),
            })
            return

        chunk_embeddings = embed_texts(chunks, settings)

        # ----------------------------------------------------------------
        # Stage 2 — Candidate retrieval (cosine top-k per chunk)
        # ----------------------------------------------------------------
        _update_job(pentest, job_id, {"progress_pct": 35, "step": "retrieving_candidates"})

        # template_id → {template_doc, chunks[], scores[]}
        candidate_map: Dict[str, Dict[str, Any]] = {}
        for chunk_text, chunk_vec in zip(chunks, chunk_embeddings):
            top_k = cosine_top_k(
                chunk_vec, language=language, k=4, threshold=threshold
            )
            for template, score in top_k:
                tid = str(template["_id"])
                if tid not in candidate_map:
                    candidate_map[tid] = {
                        "template": template, "chunks": [], "scores": [],
                    }
                # Deduplicate identical chunk text
                if chunk_text not in candidate_map[tid]["chunks"]:
                    candidate_map[tid]["chunks"].append(chunk_text)
                candidate_map[tid]["scores"].append(score)

        if not candidate_map:
            _update_job(pentest, job_id, {
                "status": "completed", "progress_pct": 100,
                "defects_created": 0, "step": "done",
                "error": (
                    "No matching templates found. "
                    "Run POST /ai/admin/embed-templates to build the index."
                ),
                "completed_at": datetime.now(),
            })
            return

        # ----------------------------------------------------------------
        # Stage 3 — Single batched LLM verification call
        # ----------------------------------------------------------------
        _update_job(pentest, job_id, {"progress_pct": 55, "step": "llm_verification"})

        candidates_payload: List[Dict[str, Any]] = []
        for tid, entry in candidate_map.items():
            t = entry["template"]
            candidates_payload.append({
                "id": tid,
                "title": t.get("title", ""),
                "synthesis": t.get("synthesis", ""),
                # Cap at 3 chunks per candidate to limit token usage
                "chunks": entry["chunks"][:3],
            })

        # Truncate notes excerpt to ~3000 chars (fits in ~750 tokens)
        notes_excerpt = notes[:3000]
        existing_titles_str = (
            ", ".join(existing_titles[:30]) if existing_titles else "None"
        )

        verify_user_msg = prompts.VERIFY_USER.format(
            notes_excerpt=notes_excerpt,
            candidates_json=json.dumps(
                candidates_payload, ensure_ascii=False, indent=2
            ),
            existing_titles=existing_titles_str,
        )
        verify_messages = [
            {"role": "system", "content": verify_system_prompt},
            {"role": "user",   "content": verify_user_msg},
        ]
        raw_verification = _llm_call(verify_messages, settings)
        verification_data = json.loads(raw_verification)
        results: List[Dict[str, Any]] = verification_data.get("results", [])

        # ----------------------------------------------------------------
        # Stage 4 — Persist confirmed defects
        # ----------------------------------------------------------------
        _update_job(pentest, job_id, {"progress_pct": 75, "step": "persisting_defects"})

        confirmed_findings: List[Dict[str, Any]] = []
        defects_created = 0

        for result in results:
            if not result.get("confirmed", False):
                continue

            tid = result.get("id", "")
            evidence: str = result.get("evidence", "")
            entry = candidate_map.get(tid)
            if entry is None:
                continue

            template = entry["template"]
            title: str = template.get("title", "")

            # Track for synthesis even if already documented
            confirmed_findings.append({
                "title": title,
                "risk": template.get("risk", "N/A"),
                "evidence": evidence,
            })

            # Skip creation if an identical defect already exists in this pentest
            if title in existing_titles:
                logger.info(f"AI: '{title}' already in pentest — skipping creation.")
                continue

            # Clone template fields, override pentest-specific ones
            data: Dict[str, Any] = dict(template)
            data.pop("_id", None)
            data.pop("embedding", None)
            data["notes"] = evidence
            data["redacted_state"] = "New"
            data["target_id"] = None
            data["target_type"] = ""
            data["redactor"] = username
            data["editor"] = username
            # Force new identity for this pentest instance
            data["defect_id"] = None
            data["common_translation_id"] = None

            # Tag as AI-generated so pentesters can filter/review
            existing_type: List[str] = data.get("type") or []
            if isinstance(existing_type, str):
                existing_type = [existing_type]
            if "ai-generated" not in existing_type:
                existing_type = existing_type + ["ai-generated"]
            data["type"] = existing_type

            defect = Defect(pentest, data)
            defect.addInDb()
            defects_created += 1
            existing_titles.append(title)  # prevent duplicates within the same run

        # ----------------------------------------------------------------
        # Stage 5 — Executive synthesis
        # ----------------------------------------------------------------
        _update_job(pentest, job_id, {"progress_pct": 88, "step": "synthesis"})

        synthesis = ""
        if confirmed_findings:
            findings_lines = "\n".join(
                f"- {f['title']} ({f.get('risk', 'N/A')}): {f.get('evidence', '')}"
                for f in confirmed_findings
            )
            synthesis_messages = [
                {
                    "role": "system",
                    "content": synthesis_system_prompt.format(
                        language=language or "English"
                    ) if "{language}" in synthesis_system_prompt else synthesis_system_prompt,
                },
                {
                    "role": "user",
                    "content": prompts.SYNTHESIS_USER.format(
                        findings_lines=findings_lines
                    ),
                },
            ]
            raw_synthesis = _llm_call(synthesis_messages, settings)
            synthesis_data = json.loads(raw_synthesis)
            synthesis = synthesis_data.get("synthesis", "")

        # Persist synthesis: one doc per pentest, replaced on each run
        if synthesis:
            dbclient.updateInDb(
                pentest, "ai_synthesis",
                {"type": "synthesis"},
                {"$set": {
                    "type": "synthesis",
                    "content": synthesis,
                    "language": language,
                    "generated_at": datetime.now(),
                    "job_id": job_id,
                    "findings": confirmed_findings,
                }},
                upsert=True, notify=False,
            )

        # ----------------------------------------------------------------
        # Done
        # ----------------------------------------------------------------
        _update_job(pentest, job_id, {
            "status": "completed",
            "progress_pct": 100,
            "step": "done",
            "defects_created": defects_created,
            "completed_at": datetime.now(),
        })
        _emit_socket("ai_complete", {
            "pentest": pentest,
            "job_id": job_id,
            "defects_created": defects_created,
        })

    except Exception as exc:  # noqa: BLE001
        logger.exception(f"AI pipeline failed for job {job_id}: {exc}")
        _update_job(pentest, job_id, {
            "status": "failed",
            "progress_pct": 0,
            "step": "error",
            "error": str(exc),
            "completed_at": datetime.now(),
        })
        _emit_socket("ai_error", {
            "pentest": pentest,
            "job_id": job_id,
            "error": str(exc),
        })
