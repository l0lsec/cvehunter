"""API routes for the MOAK-Lite dashboard."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from moak.pipeline import run_pipeline

router = APIRouter()

# In-memory store for MVP (replace with database later)
_runs: dict[str, dict] = {}


class RunRequest(BaseModel):
    cve_id: str


class RunStatus(BaseModel):
    cve_id: str
    status: str
    exploitability_score: float | None = None
    summary: str | None = None


@router.post("/run", response_model=RunStatus)
async def start_run(request: RunRequest, background_tasks: BackgroundTasks) -> RunStatus:
    """Submit a CVE for exploitation analysis."""
    cve_id = request.cve_id.upper()
    if cve_id in _runs and _runs[cve_id].get("status") == "running":
        raise HTTPException(status_code=409, detail=f"{cve_id} is already being processed")

    _runs[cve_id] = {"status": "running"}
    background_tasks.add_task(_execute_run, cve_id)

    return RunStatus(cve_id=cve_id, status="running")


@router.get("/run/{cve_id}", response_model=RunStatus)
async def get_run_status(cve_id: str) -> RunStatus:
    """Get the status of a CVE run."""
    cve_id = cve_id.upper()
    if cve_id not in _runs:
        raise HTTPException(status_code=404, detail=f"No run found for {cve_id}")

    run = _runs[cve_id]
    return RunStatus(
        cve_id=cve_id,
        status=run.get("status", "unknown"),
        exploitability_score=run.get("exploitability_score"),
        summary=run.get("summary"),
    )


@router.get("/runs")
async def list_runs() -> list[RunStatus]:
    """List all CVE runs."""
    return [
        RunStatus(
            cve_id=cve_id,
            status=run.get("status", "unknown"),
            exploitability_score=run.get("exploitability_score"),
            summary=run.get("summary"),
        )
        for cve_id, run in _runs.items()
    ]


async def _execute_run(cve_id: str) -> None:
    """Background task to execute the full pipeline."""
    try:
        result = await run_pipeline(cve_id)
        judgement = result.get("judgement")
        _runs[cve_id] = {
            "status": result.get("status", "completed"),
            "exploitability_score": judgement.exploitability_score if judgement else None,
            "summary": judgement.summary if judgement else None,
            "full_result": result,
        }
    except Exception as e:
        _runs[cve_id] = {"status": "error", "summary": str(e)}
