"""API routes for the CVEHunter pipeline."""

from __future__ import annotations

import json
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from cvehunter.api.auth import require_api_key
from cvehunter.api.database import create_run, get_run, has_running_run, list_runs, update_run
from cvehunter.api.errors import ErrorCode, ErrorResponse, HTTP_STATUS_MAP
from cvehunter.config import settings
from cvehunter.llm_status import LLMStatusReport, build_report
from cvehunter.pipeline import resume_pipeline, run_pipeline

logger = structlog.get_logger(__name__)

router = APIRouter()


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


class RunDetail(RunStatus):
    full_result: dict[str, Any] | None = None


def _raise(code: ErrorCode, detail: str) -> None:
    err = ErrorResponse.from_code(code, detail)
    raise HTTPException(
        status_code=HTTP_STATUS_MAP[code],
        detail=err.model_dump(mode="json"),
    )


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
    )


@router.post("/run", response_model=RunStatus, dependencies=[Depends(require_api_key)])
async def start_run(request: RunRequest, background_tasks: BackgroundTasks) -> RunStatus:
    """Submit a CVE for exploitation analysis."""
    try:
        settings.validate_keys()
    except ValueError as e:
        _raise(ErrorCode.VALIDATION_ERROR, str(e))

    cve_id = request.cve_id.upper()
    if await has_running_run(cve_id):
        _raise(ErrorCode.CVE_ALREADY_RUNNING, f"{cve_id} is already being processed")

    row = await create_run(cve_id)
    background_tasks.add_task(_execute_run, cve_id)
    return _row_to_status(row)


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
    """Background task to resume a pipeline."""
    try:
        result = await resume_pipeline(cve_id, human_response=human_response)
        judgement = result.get("judgement")
        await update_run(
            cve_id,
            status=result.get("status", "completed"),
            exploitability_score=judgement.exploitability_score if judgement else None,
            summary=judgement.summary if judgement else None,
            full_result_json=result,
        )
    except Exception as e:
        logger.exception("pipeline_resume_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="error",
            error_code=ErrorCode.PIPELINE_FAILED.value,
            summary=str(e),
        )


async def _execute_run(cve_id: str) -> None:
    """Background task to execute the full pipeline."""
    try:
        result = await run_pipeline(cve_id)
        judgement = result.get("judgement")
        await update_run(
            cve_id,
            status=result.get("status", "completed"),
            exploitability_score=judgement.exploitability_score if judgement else None,
            summary=judgement.summary if judgement else None,
            full_result_json=result,
        )
    except Exception as e:
        logger.exception("pipeline_background_failed", cve_id=cve_id)
        await update_run(
            cve_id,
            status="error",
            error_code=ErrorCode.PIPELINE_FAILED.value,
            summary=str(e),
        )
