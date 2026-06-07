"""REST API routes for the CVEHunter pipeline.

These endpoints are thin, authenticated wrappers over the auth-free helpers in
``api/run_service.py`` (which the dashboard calls server-side without auth).
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from cvehunter.api import run_service
from cvehunter.api.auth import require_api_key
from cvehunter.api.database import get_run, list_runs
from cvehunter.api.errors import HTTP_STATUS_MAP, ErrorCode, ErrorResponse
from cvehunter.api.run_service import RunServiceError
from cvehunter.llm_status import LLMStatusReport, build_report

logger = structlog.get_logger(__name__)

router = APIRouter()


class RunRequest(BaseModel):
    cve_id: str
    simple_researcher: bool = False


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


class HITLRequest(BaseModel):
    action: str  # "approve" or "reject"
    notes: str = ""


def _http_error(code: ErrorCode, detail: str) -> HTTPException:
    err = ErrorResponse.from_code(code, detail)
    return HTTPException(
        status_code=HTTP_STATUS_MAP[code],
        detail=err.model_dump(mode="json"),
    )


def _service_error(err: RunServiceError) -> HTTPException:
    return _http_error(err.code, err.detail)


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
    """Submit a CVE for full exploitation analysis."""
    try:
        row = await run_service.launch_run(
            request.cve_id,
            background_tasks,
            simple_researcher=request.simple_researcher,
        )
    except RunServiceError as e:
        raise _service_error(e) from e
    return _row_to_status(row)


@router.post(
    "/collect", response_model=RunStatus, dependencies=[Depends(require_api_key)]
)
async def start_collect(
    request: RunRequest, background_tasks: BackgroundTasks
) -> RunStatus:
    """Run only the Collector agent for a CVE (CLI ``collect`` parity)."""
    try:
        row = await run_service.collect_only(request.cve_id, background_tasks)
    except RunServiceError as e:
        raise _service_error(e) from e
    return _row_to_status(row)


@router.post(
    "/run/{cve_id}/cancel",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def cancel_run(cve_id: str) -> RunStatus:
    """Cancel an in-flight run by cancelling its asyncio task."""
    try:
        row = await run_service.cancel_run(cve_id)
    except RunServiceError as e:
        raise _service_error(e) from e
    return _row_to_status(row)


@router.post(
    "/run/{cve_id}/retry",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def retry_run(cve_id: str, background_tasks: BackgroundTasks) -> RunStatus:
    """Start a fresh pipeline run for a CVE that is not currently running."""
    try:
        row = await run_service.retry_run(cve_id, background_tasks)
    except RunServiceError as e:
        raise _service_error(e) from e
    return _row_to_status(row)


@router.get("/run/{cve_id}", response_model=RunDetail)
async def get_run_status(cve_id: str) -> RunDetail:
    """Get the status of a CVE run."""
    cve_id = cve_id.upper()
    row = await get_run(cve_id)
    if row is None:
        raise _http_error(ErrorCode.RUN_NOT_FOUND, f"No run found for {cve_id}")

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


@router.post(
    "/resume/{cve_id}",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def resume_run(cve_id: str, background_tasks: BackgroundTasks) -> RunStatus:
    """Resume a paused or failed pipeline run from its last checkpoint."""
    try:
        row = await run_service.resume_run(cve_id, background_tasks)
    except RunServiceError as e:
        raise _service_error(e) from e
    return _row_to_status(row)


@router.post(
    "/hitl/{cve_id}",
    response_model=RunStatus,
    dependencies=[Depends(require_api_key)],
)
async def hitl_respond(
    cve_id: str, request: HITLRequest, background_tasks: BackgroundTasks
) -> RunStatus:
    """Respond to a human-in-the-loop gate (approve or reject)."""
    try:
        row = await run_service.hitl_respond(
            cve_id, background_tasks, request.action, request.notes
        )
    except RunServiceError as e:
        raise _service_error(e) from e
    return _row_to_status(row)
