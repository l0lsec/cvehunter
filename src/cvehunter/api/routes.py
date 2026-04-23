"""API routes for the CVEHunter pipeline."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from cvehunter.api import task_registry
from cvehunter.api.auth import require_api_key
from cvehunter.api.database import (
    create_run,
    get_run,
    has_running_run,
    list_runs,
    reset_checkpoint,
    update_run,
)
from cvehunter.api.errors import ErrorCode, ErrorResponse, HTTP_STATUS_MAP
from cvehunter.config import settings
from cvehunter.llm_status import LLMStatusReport, build_report
from cvehunter.pipeline import checkpoint_db_path, resume_pipeline, run_pipeline
from cvehunter.tools.docker_ops import cleanup_environment

logger = structlog.get_logger(__name__)

router = APIRouter()

# Status values that represent an active or in-flight run.
_ACTIVE_STATUSES = {"running", "resuming", "cancelling"}


class RunRequest(BaseModel):
    cve_id: str


class RunStatus(BaseModel):
    id: str | None = None
    cve_id: str
    status: str
    error_code: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    exploitability_score: float | None = None
    summary: str | None = None
    current_stage: str | None = None
    stages_completed: list[str] | None = None
    cost_usd_live: float | None = None


class RunDetail(RunStatus):
    full_result: dict[str, Any] | None = None


def _raise(code: ErrorCode, detail: str) -> None:
    err = ErrorResponse.from_code(code, detail)
    raise HTTPException(
        status_code=HTTP_STATUS_MAP[code],
        detail=err.model_dump(mode="json"),
    )


def _parse_stages(raw: Any) -> list[str] | None:
    if not raw:
        return None
    if isinstance(raw, list):
        return [str(x) for x in raw]
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    return [str(x) for x in parsed] if isinstance(parsed, list) else None


def _row_to_status(row: dict[str, Any]) -> RunStatus:
    return RunStatus(
        id=row.get("id"),
        cve_id=row["cve_id"],
        status=row.get("status", "unknown"),
        error_code=row.get("error_code"),
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        exploitability_score=row.get("exploitability_score"),
        summary=row.get("summary"),
        current_stage=row.get("current_stage"),
        stages_completed=_parse_stages(row.get("stages_completed")),
        cost_usd_live=row.get("cost_usd_live"),
    )


@router.post("/run", response_model=RunStatus, dependencies=[Depends(require_api_key)])
async def start_run(request: RunRequest, background_tasks: BackgroundTasks) -> RunStatus:
    """Submit a CVE for exploitation analysis."""
    try:
        settings.validate_keys()
    except ValueError as e:
        _raise(ErrorCode.VALIDATION_ERROR, str(e))

    cve_id = request.cve_id.upper()
    if await has_running_run(cve_id) or task_registry.is_running(cve_id):
        _raise(ErrorCode.CVE_ALREADY_RUNNING, f"{cve_id} is already being processed")

    row = await create_run(cve_id)
    background_tasks.add_task(_execute_run, cve_id)
    return _row_to_status(row)


@router.post(
    "/run/{cve_id}/cancel",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def cancel_run(cve_id: str) -> RunStatus:
    """Cancel an in-flight run by cancelling its asyncio task."""
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        _raise(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")

    task = task_registry.get(cve_id)
    if task is None or task.done():
        _raise(
            ErrorCode.RUN_NOT_RUNNING,
            f"{cve_id} has no in-flight task in this process",
        )

    await update_run(cve_id, status="cancelling")
    task.cancel()
    row = await get_run(cve_id)
    return _row_to_status(row)


@router.post(
    "/run/{cve_id}/retry",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def retry_run(cve_id: str, background_tasks: BackgroundTasks) -> RunStatus:
    """Start a fresh pipeline run for a CVE that is not currently running."""
    try:
        settings.validate_keys()
    except ValueError as e:
        _raise(ErrorCode.VALIDATION_ERROR, str(e))

    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        _raise(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")

    status = row.get("status", "")
    if status in _ACTIVE_STATUSES or task_registry.is_running(cve_id):
        _raise(
            ErrorCode.RUN_NOT_RETRYABLE,
            f"{cve_id} is currently {status}; cancel it before retrying",
        )

    await reset_checkpoint(checkpoint_db_path(), cve_id)
    new_row = await create_run(cve_id)
    background_tasks.add_task(_execute_run, cve_id)
    return _row_to_status(new_row)


@router.get("/run/{cve_id}", response_model=RunDetail)
async def get_run_status(cve_id: str) -> RunDetail:
    """Get the status of a CVE run."""
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        _raise(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")

    full_result = None
    if row.get("full_result_json"):
        try:
            full_result = json.loads(row["full_result_json"])
        except (json.JSONDecodeError, TypeError):
            full_result = None

    return RunDetail(
        id=row.get("id"),
        cve_id=row["cve_id"],
        status=row.get("status", "unknown"),
        error_code=row.get("error_code"),
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        exploitability_score=row.get("exploitability_score"),
        summary=row.get("summary"),
        current_stage=row.get("current_stage"),
        stages_completed=_parse_stages(row.get("stages_completed")),
        cost_usd_live=row.get("cost_usd_live"),
        full_result=full_result,
    )


@router.get("/runs", response_model=list[RunStatus])
async def list_all_runs() -> list[RunStatus]:
    """List all CVE runs."""
    rows = await list_runs()
    return [_row_to_status(r) for r in rows]


@router.get(
    "/llms",
    response_model=LLMStatusReport,
    dependencies=[Depends(require_api_key)],
)
async def get_llm_status() -> LLMStatusReport:
    """Report active LLMs, live provider balances, and local spend-to-date."""
    return await build_report(live=True)


class HITLRequest(BaseModel):
    action: str  # "approve" or "reject"
    notes: str = ""


@router.post(
    "/resume/{cve_id}",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def resume_run(cve_id: str, background_tasks: BackgroundTasks) -> RunStatus:
    """Resume a paused or failed pipeline run from its last checkpoint."""
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        _raise(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")

    await update_run(cve_id, status="resuming")
    background_tasks.add_task(_execute_resume, cve_id, None)
    row = await get_run(cve_id)
    return _row_to_status(row)


@router.post(
    "/hitl/{cve_id}",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def hitl_respond(cve_id: str, request: HITLRequest, background_tasks: BackgroundTasks) -> RunStatus:
    """Respond to a human-in-the-loop gate (approve or reject)."""
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        _raise(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")

    human_response = {"action": request.action, "notes": request.notes}
    await update_run(cve_id, status="resuming")
    background_tasks.add_task(_execute_resume, cve_id, human_response)
    row = await get_run(cve_id)
    return _row_to_status(row)


async def _execute_resume(cve_id: str, human_response: dict[str, Any] | None) -> None:
    """Background task to resume a pipeline from its last checkpoint."""
    task = asyncio.create_task(resume_pipeline(cve_id, human_response=human_response))
    task_registry.register(cve_id, task)
    try:
        result = await task
        judgement = result.get("judgement")
        await update_run(
            cve_id,
            status=result.get("status", "completed"),
            exploitability_score=judgement.exploitability_score if judgement else None,
            summary=judgement.summary if judgement else None,
            full_result_json=result,
        )
    except asyncio.CancelledError:
        logger.info("pipeline_resume_cancelled", cve_id=cve_id)
        project = f"cvehunter-{cve_id.lower().replace('-', '_')}"
        try:
            await cleanup_environment(project)
            await cleanup_environment(f"{project}-patched")
        except Exception:
            logger.exception("cleanup_after_cancel_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="cancelled",
            summary="Run cancelled by user",
        )
    except Exception as e:
        logger.exception("pipeline_resume_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="error",
            error_code=ErrorCode.PIPELINE_FAILED.value,
            summary=str(e),
        )
    finally:
        task_registry.pop(cve_id)


async def _execute_run(cve_id: str) -> None:
    """Background task to execute the full pipeline.

    Wraps ``run_pipeline`` in an ``asyncio.Task`` so the cancel endpoint can
    interrupt it. Registers the task so the cancel handler can find it; on
    ``CancelledError`` we tear down any Docker environments the run created
    and mark the DB row as ``cancelled``.
    """
    task = asyncio.create_task(run_pipeline(cve_id))
    task_registry.register(cve_id, task)
    try:
        result = await task
        judgement = result.get("judgement")
        await update_run(
            cve_id,
            status=result.get("status", "completed"),
            exploitability_score=judgement.exploitability_score if judgement else None,
            summary=judgement.summary if judgement else None,
            full_result_json=result,
        )
    except asyncio.CancelledError:
        logger.info("pipeline_cancelled", cve_id=cve_id)
        project = f"cvehunter-{cve_id.lower().replace('-', '_')}"
        try:
            await cleanup_environment(project)
            await cleanup_environment(f"{project}-patched")
        except Exception:
            logger.exception("cleanup_after_cancel_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="cancelled",
            summary="Run cancelled by user",
        )
    except Exception as e:
        logger.exception("pipeline_background_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="error",
            error_code=ErrorCode.PIPELINE_FAILED.value,
            summary=str(e),
        )
    finally:
        task_registry.pop(cve_id)
