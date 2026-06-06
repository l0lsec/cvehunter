"""Auth-free business logic for launching and steering pipeline runs.

Both the authenticated REST endpoints (``api/routes.py``) and the server-side
dashboard handlers (``dashboard/routes.py``) call these helpers, so the browser
never has to send an API key to mutate runs. Errors are raised as
``RunServiceError`` and translated to HTTP/HTML by the caller.

This module also owns the background coroutines that actually run the pipeline,
collector, and resume flows, including the HITL-interrupt detection that marks a
paused run as ``hitl_paused`` and the terminal-status normalisation that turns
the Judge's ``judged`` status into the user-facing ``completed``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import BackgroundTasks

from cvehunter.agents.collector import run_collector
from cvehunter.api import task_registry
from cvehunter.api.database import (
    create_run,
    get_run,
    has_running_run,
    reset_checkpoint,
    update_run,
)
from cvehunter.api.errors import ErrorCode
from cvehunter.config import settings
from cvehunter.pipeline import checkpoint_db_path, resume_pipeline, run_pipeline
from cvehunter.tools.docker_ops import cleanup_cve_environments

logger = structlog.get_logger(__name__)

# Statuses that represent an active / in-flight run.
ACTIVE_STATUSES = {"running", "resuming", "cancelling"}

# Terminal statuses that already render correctly in the UI and should pass
# through unchanged. The Judge's "judged" status is normalised to "completed".
_TERMINAL_PASSTHROUGH = {
    "completed",
    "judged_partial",
    "approved_by_human",
    "rejected_by_human",
    "collected",
    "collected_incomplete",
    "error",
    "cancelled",
}


class RunServiceError(Exception):
    """A business-rule failure that maps to a specific API error code."""

    def __init__(self, code: ErrorCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _map_terminal_status(raw: str | None) -> str:
    """Normalise the pipeline's final status into a user-facing terminal status."""
    if raw == "judged":
        return "completed"
    if raw in _TERMINAL_PASSTHROUGH:
        return raw
    # The pipeline always ends at the judge/cleanup nodes, so any other value
    # means a clean end-to-END run — present it as completed.
    return raw or "completed"


def _is_interrupted(result: Any) -> bool:
    """True if a pipeline result paused at a LangGraph interrupt (HITL gate)."""
    return isinstance(result, dict) and bool(result.get("__interrupt__"))


# ── Background coroutines ──


async def _execute_run(cve_id: str, simple_researcher: bool = False) -> None:
    """Run the full pipeline as a cancellable background task.

    When ``simple_researcher`` is set we temporarily flip the process-global
    swarm flag for the duration of the run (the researcher fn is bound when the
    graph is built at the start of ``run_pipeline``). This mirrors what the CLI
    ``--simple-researcher`` flag already does; concurrent runs requesting
    different values would race on the global, which is an accepted limitation.
    """
    prev_swarm = settings.researcher_swarm_enabled
    if simple_researcher:
        settings.researcher_swarm_enabled = False

    task = asyncio.create_task(run_pipeline(cve_id))
    task_registry.register(cve_id, task)
    try:
        result = await task

        if _is_interrupted(result):
            judgement = result.get("judgement")
            await update_run(
                cve_id,
                status="hitl_paused",
                exploitability_score=judgement.exploitability_score if judgement else None,
                summary=judgement.summary if judgement else "Awaiting human review",
                full_result_json=result,
            )
            return

        judgement = result.get("judgement")
        await update_run(
            cve_id,
            status=_map_terminal_status(result.get("status")),
            completed_at=_now_iso(),
            exploitability_score=judgement.exploitability_score if judgement else None,
            summary=judgement.summary if judgement else None,
            full_result_json=result,
        )
    except asyncio.CancelledError:
        logger.info("pipeline_cancelled", cve_id=cve_id)
        try:
            await cleanup_cve_environments(cve_id)
        except Exception:
            logger.exception("cleanup_after_cancel_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="cancelled",
            completed_at=_now_iso(),
            summary="Run cancelled by user",
        )
    except Exception as e:
        logger.exception("pipeline_background_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="error",
            completed_at=_now_iso(),
            error_code=ErrorCode.PIPELINE_FAILED.value,
            summary=str(e),
        )
    finally:
        task_registry.pop(cve_id)
        if simple_researcher:
            settings.researcher_swarm_enabled = prev_swarm


async def _execute_resume(cve_id: str, human_response: dict[str, Any] | None) -> None:
    """Resume a paused/failed run from its checkpoint as a background task."""
    task = asyncio.create_task(resume_pipeline(cve_id, human_response=human_response))
    task_registry.register(cve_id, task)
    try:
        result = await task

        if _is_interrupted(result):
            judgement = result.get("judgement")
            await update_run(
                cve_id,
                status="hitl_paused",
                exploitability_score=judgement.exploitability_score if judgement else None,
                summary=judgement.summary if judgement else "Awaiting human review",
                full_result_json=result,
            )
            return

        judgement = result.get("judgement")
        await update_run(
            cve_id,
            status=_map_terminal_status(result.get("status")),
            completed_at=_now_iso(),
            exploitability_score=judgement.exploitability_score if judgement else None,
            summary=judgement.summary if judgement else None,
            full_result_json=result,
        )
    except asyncio.CancelledError:
        logger.info("pipeline_resume_cancelled", cve_id=cve_id)
        try:
            await cleanup_cve_environments(cve_id)
        except Exception:
            logger.exception("cleanup_after_cancel_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="cancelled",
            completed_at=_now_iso(),
            summary="Run cancelled by user",
        )
    except Exception as e:
        logger.exception("pipeline_resume_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="error",
            completed_at=_now_iso(),
            error_code=ErrorCode.PIPELINE_FAILED.value,
            summary=str(e),
        )
    finally:
        task_registry.pop(cve_id)


async def _execute_collect(cve_id: str) -> None:
    """Run only the Collector agent as a cancellable background task."""
    task = asyncio.create_task(run_collector({"cve_id": cve_id}))
    task_registry.register(cve_id, task)
    try:
        result = await task
        cve_package = result.get("cve_package")
        await update_run(
            cve_id,
            status=result.get("status", "collected") if cve_package else "error",
            completed_at=_now_iso(),
            summary=(
                cve_package.description[:200]
                if cve_package
                else "Collector produced no CVE package"
            ),
            full_result_json={
                "cve_package": cve_package,
                "status": result.get("status", "collected"),
                "errors": result.get("errors", []),
            },
        )
    except asyncio.CancelledError:
        logger.info("collect_cancelled", cve_id=cve_id)
        await update_run(
            cve_id,
            status="cancelled",
            completed_at=_now_iso(),
            summary="Collection cancelled by user",
        )
    except Exception as e:
        logger.exception("collect_background_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="error",
            completed_at=_now_iso(),
            error_code=ErrorCode.PIPELINE_FAILED.value,
            summary=str(e),
        )
    finally:
        task_registry.pop(cve_id)


# ── Service helpers (auth-free) ──


def _validate_keys() -> None:
    try:
        settings.validate_keys()
    except ValueError as e:
        raise RunServiceError(ErrorCode.VALIDATION_ERROR, str(e)) from e


async def launch_run(
    cve_id: str,
    background_tasks: BackgroundTasks,
    *,
    simple_researcher: bool = False,
) -> dict[str, Any]:
    """Validate, guard against duplicates, and schedule a full pipeline run."""
    _validate_keys()
    cve_id = cve_id.strip().upper()
    if not cve_id:
        raise RunServiceError(ErrorCode.VALIDATION_ERROR, "CVE ID is required")
    if await has_running_run(cve_id) or task_registry.is_running(cve_id):
        raise RunServiceError(
            ErrorCode.CVE_ALREADY_RUNNING, f"{cve_id} is already being processed"
        )
    row = await create_run(cve_id)
    background_tasks.add_task(_execute_run, cve_id, simple_researcher)
    return row


async def collect_only(
    cve_id: str, background_tasks: BackgroundTasks
) -> dict[str, Any]:
    """Validate and schedule a collector-only run (CLI ``collect`` parity)."""
    _validate_keys()
    cve_id = cve_id.strip().upper()
    if not cve_id:
        raise RunServiceError(ErrorCode.VALIDATION_ERROR, "CVE ID is required")
    if await has_running_run(cve_id) or task_registry.is_running(cve_id):
        raise RunServiceError(
            ErrorCode.CVE_ALREADY_RUNNING, f"{cve_id} is already being processed"
        )
    row = await create_run(cve_id)
    background_tasks.add_task(_execute_collect, cve_id)
    return row


async def cancel_run(cve_id: str) -> dict[str, Any]:
    """Cancel an in-flight run by cancelling its asyncio task."""
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        raise RunServiceError(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")
    task = task_registry.get(cve_id)
    if task is None or task.done():
        raise RunServiceError(
            ErrorCode.RUN_NOT_RUNNING, f"{cve_id} has no in-flight task in this process"
        )
    await update_run(cve_id, status="cancelling")
    task.cancel()
    return await get_run(cve_id) or row


async def retry_run(cve_id: str, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Reset the checkpoint and start a fresh pipeline run for a CVE."""
    _validate_keys()
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        raise RunServiceError(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")
    status = row.get("status", "")
    if status in ACTIVE_STATUSES or task_registry.is_running(cve_id):
        raise RunServiceError(
            ErrorCode.RUN_NOT_RETRYABLE,
            f"{cve_id} is currently {status}; cancel it before retrying",
        )
    await reset_checkpoint(checkpoint_db_path(), cve_id)
    new_row = await create_run(cve_id)
    background_tasks.add_task(_execute_run, cve_id, False)
    return new_row


async def resume_run(
    cve_id: str,
    background_tasks: BackgroundTasks,
    human_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resume a paused/failed run from its last checkpoint."""
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        raise RunServiceError(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")
    await update_run(cve_id, status="resuming")
    background_tasks.add_task(_execute_resume, cve_id, human_response)
    return await get_run(cve_id) or row


async def hitl_respond(
    cve_id: str,
    background_tasks: BackgroundTasks,
    action: str,
    notes: str = "",
) -> dict[str, Any]:
    """Respond to a human-in-the-loop gate (approve/reject) by resuming."""
    return await resume_run(
        cve_id, background_tasks, {"action": action, "notes": notes}
    )
