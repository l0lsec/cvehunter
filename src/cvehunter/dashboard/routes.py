"""Dashboard routes serving Jinja2/HTMX pages."""

from __future__ import annotations

import html
import json
from typing import Any

import structlog
from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from cvehunter.api import run_service
from cvehunter.api.database import get_run, list_runs
from cvehunter.api.run_service import RunServiceError
from cvehunter.graph_viz import primitives_to_mermaid
from cvehunter.llm_status import build_report
from cvehunter.pipeline import CANONICAL_STAGES, checkpoint_db_path
from cvehunter.schemas import PrimitivesGraph

logger = structlog.get_logger(__name__)


def _extract_mermaid(full_result: dict | None) -> str:
    """Pull the primitives graph from a full result dict and render as Mermaid."""
    if not full_result:
        return ""
    recipe = full_result.get("exploit_recipe")
    if not isinstance(recipe, dict):
        return ""
    pg = recipe.get("primitives_graph")
    if not isinstance(pg, dict):
        return ""
    try:
        graph = PrimitivesGraph.model_validate(pg)
        return primitives_to_mermaid(graph)
    except Exception:
        return ""


def _enrich_row(row: dict | None) -> dict | None:
    """Parse JSON-encoded progress fields into native types for template use."""
    if row is None:
        return None
    raw = row.get("stages_completed")
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            row["stages_completed"] = parsed if isinstance(parsed, list) else []
        except (TypeError, json.JSONDecodeError):
            row["stages_completed"] = []
    elif not raw:
        row["stages_completed"] = []
    return row


async def _live_checkpoint_values(cve_id: str) -> dict[str, Any]:
    """Best-effort pull of current LangGraph state for a running thread.

    Returns an empty dict if no checkpoint exists or the saver can't be opened.
    Never raises; rendering must degrade gracefully when progress data is missing.
    """
    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
    except Exception:
        return {}

    config = {"configurable": {"thread_id": cve_id}}
    try:
        async with AsyncSqliteSaver.from_conn_string(checkpoint_db_path()) as saver:
            tup = await saver.aget_tuple(config)
            if tup is None or tup.checkpoint is None:
                return {}
            values = tup.checkpoint.get("channel_values") or {}
            return values if isinstance(values, dict) else {}
    except Exception:
        logger.exception("live_checkpoint_fetch_failed", cve_id=cve_id)
        return {}


def _progress_context(run: dict, live: dict[str, Any]) -> dict[str, Any]:
    """Build the template context for the progress partial."""
    stages_completed_raw = run.get("stages_completed") or "[]"
    try:
        stages_completed = json.loads(stages_completed_raw)
        if not isinstance(stages_completed, list):
            stages_completed = []
    except (TypeError, json.JSONDecodeError):
        stages_completed = []

    current_stage = run.get("current_stage")

    steps = []
    completed_set = set(stages_completed)
    active_seen = False
    for stage in CANONICAL_STAGES:
        if stage in completed_set:
            state = "done"
        elif stage == current_stage:
            state = "active"
            active_seen = True
        elif active_seen or current_stage is None:
            state = "pending"
        else:
            state = "pending"
        steps.append({"name": stage, "state": state})

    exploit_result = live.get("exploit_result") if isinstance(live, dict) else None
    exploit_attempts = None
    if isinstance(exploit_result, dict):
        exploit_attempts = exploit_result.get("total_attempts")

    errors = live.get("errors") if isinstance(live, dict) else None
    recent_errors = []
    if isinstance(errors, list):
        recent_errors = [str(e) for e in errors[-3:]]

    return {
        "run": run,
        "steps": steps,
        "current_stage": current_stage,
        "cost": run.get("cost_usd_live") or 0.0,
        "researcher_attempts": live.get("researcher_attempts") if isinstance(live, dict) else None,
        "exploit_attempts": exploit_attempts,
        "recent_errors": recent_errors,
        "is_active": run.get("status") in ("running", "resuming", "cancelling"),
    }


def build_dashboard_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(prefix="/dashboard", default_response_class=HTMLResponse)

    @router.get("/")
    async def dashboard_index(request: Request) -> HTMLResponse:
        runs = [_enrich_row(r) for r in await list_runs()]
        return templates.TemplateResponse(request, "index.html", {"runs": runs})

    @router.get("/partials/runs-table")
    async def runs_table_partial(request: Request) -> HTMLResponse:
        runs = [_enrich_row(r) for r in await list_runs()]
        return templates.TemplateResponse(request, "partials/runs_table.html", {"runs": runs})

    @router.get("/llms")
    async def dashboard_llms(request: Request) -> HTMLResponse:
        report = await build_report(live=True)
        return templates.TemplateResponse(
            request,
            "llms.html",
            {"report": report},
        )

    @router.get("/partials/run-status/{cve_id}")
    async def run_status_partial(request: Request, cve_id: str) -> HTMLResponse:
        cve_id = cve_id.upper()
        run = _enrich_row(await get_run(cve_id))
        if run is None:
            return HTMLResponse("<tr><td colspan='7'>Not found</td></tr>")
        return templates.TemplateResponse(request, "partials/run_row.html", {"run": run})

    @router.get("/partials/run-progress/{cve_id}")
    async def run_progress_partial(request: Request, cve_id: str) -> HTMLResponse:
        cve_id = cve_id.upper()
        run = await get_run(cve_id)
        if run is None:
            return HTMLResponse("<p>Not found</p>")
        live = await _live_checkpoint_values(cve_id)
        context = _progress_context(run, live)
        return templates.TemplateResponse(
            request, "partials/run_progress.html", context
        )

    async def _respond_with_row(request: Request, cve_id: str) -> HTMLResponse:
        run = _enrich_row(await get_run(cve_id))
        if run is None:
            return HTMLResponse("<tr><td colspan='7'>Not found</td></tr>")
        return templates.TemplateResponse(
            request, "partials/run_row.html", {"run": run}
        )

    def _result_card(message: str, *, error: bool = False) -> HTMLResponse:
        cls = "status-error" if error else "status-completed"
        return HTMLResponse(
            f'<article class="{cls}"><small>{html.escape(message)}</small></article>'
        )

    @router.post("/actions/submit")
    async def action_submit(
        request: Request, background_tasks: BackgroundTasks
    ) -> HTMLResponse:
        form = await request.form()
        cve_id = str(form.get("cve_id", "")).strip().upper()
        simple = str(form.get("simple_researcher", "")) in ("on", "true", "1")
        try:
            await run_service.launch_run(
                cve_id, background_tasks, simple_researcher=simple
            )
        except RunServiceError as exc:
            return _result_card(exc.detail, error=True)
        except Exception:
            logger.exception("dashboard_submit_failed", cve_id=cve_id)
            return _result_card("Failed to start run; check server logs.", error=True)
        return _result_card(f"Started analysis for {cve_id}. It will appear below.")

    @router.post("/actions/collect")
    async def action_collect(
        request: Request, background_tasks: BackgroundTasks
    ) -> HTMLResponse:
        form = await request.form()
        cve_id = str(form.get("cve_id", "")).strip().upper()
        try:
            await run_service.collect_only(cve_id, background_tasks)
        except RunServiceError as exc:
            return _result_card(exc.detail, error=True)
        except Exception:
            logger.exception("dashboard_collect_failed", cve_id=cve_id)
            return _result_card("Failed to start collector; check server logs.", error=True)
        return _result_card(f"Collecting CVE data for {cve_id}. It will appear below.")

    @router.post("/actions/cancel/{cve_id}")
    async def action_cancel(request: Request, cve_id: str) -> HTMLResponse:
        cve_id = cve_id.upper()
        try:
            await run_service.cancel_run(cve_id)
        except RunServiceError as exc:
            logger.info("dashboard_cancel_noop", cve_id=cve_id, detail=exc.detail)
        except Exception:
            logger.exception("dashboard_cancel_failed", cve_id=cve_id)
        return await _respond_with_row(request, cve_id)

    @router.post("/actions/retry/{cve_id}")
    async def action_retry(
        request: Request,
        cve_id: str,
        background_tasks: BackgroundTasks,
    ) -> HTMLResponse:
        cve_id = cve_id.upper()
        try:
            await run_service.retry_run(cve_id, background_tasks)
        except RunServiceError as exc:
            logger.info("dashboard_retry_noop", cve_id=cve_id, detail=exc.detail)
        except Exception:
            logger.exception("dashboard_retry_failed", cve_id=cve_id)
        return await _respond_with_row(request, cve_id)

    @router.post("/actions/resume/{cve_id}")
    async def action_resume(
        request: Request,
        cve_id: str,
        background_tasks: BackgroundTasks,
    ) -> HTMLResponse:
        cve_id = cve_id.upper()
        try:
            await run_service.resume_run(cve_id, background_tasks)
        except RunServiceError as exc:
            logger.info("dashboard_resume_noop", cve_id=cve_id, detail=exc.detail)
        except Exception:
            logger.exception("dashboard_resume_failed", cve_id=cve_id)
        return await _respond_with_row(request, cve_id)

    @router.post("/actions/hitl/{cve_id}")
    async def action_hitl(
        request: Request,
        cve_id: str,
        background_tasks: BackgroundTasks,
    ) -> HTMLResponse:
        cve_id = cve_id.upper()
        form = await request.form()
        action = str(form.get("action", "approve"))
        notes = str(form.get("notes", ""))
        try:
            await run_service.hitl_respond(cve_id, background_tasks, action, notes)
        except RunServiceError as exc:
            logger.info("dashboard_hitl_noop", cve_id=cve_id, detail=exc.detail)
        except Exception:
            logger.exception("dashboard_hitl_failed", cve_id=cve_id)
        return await _respond_with_row(request, cve_id)

    @router.get("/status")
    async def dashboard_status(request: Request) -> HTMLResponse:
        from cvehunter.config import AGENT_MODEL_MAPPING, MODELS, settings

        keys = {
            "Anthropic": bool(settings.anthropic_api_key),
            "DeepSeek (optional)": bool(settings.deepseek_api_key),
            "Google (optional)": bool(settings.google_api_key),
            "OpenAI (optional)": bool(settings.openai_api_key),
            "NVD": bool(settings.nvd_api_key),
            "GitHub": bool(settings.github_token),
        }
        agent_models = [
            {
                "agent": agent,
                "tier": tier.value,
                "model": MODELS[tier].model_name,
                "cost_in": MODELS[tier].cost_per_1m_input,
                "cost_out": MODELS[tier].cost_per_1m_output,
            }
            for agent, tier in AGENT_MODEL_MAPPING.items()
        ]
        return templates.TemplateResponse(
            request,
            "status.html",
            {
                "settings": settings,
                "keys": keys,
                "agent_models": agent_models,
            },
        )

    @router.get("/{cve_id}")
    async def dashboard_detail(request: Request, cve_id: str) -> HTMLResponse:
        cve_id = cve_id.upper()
        run = await get_run(cve_id)
        if run is None:
            return HTMLResponse("<h2>Run not found</h2><p><a href='/dashboard/'>Back</a></p>")

        full_result = None
        if run.get("full_result_json"):
            try:
                full_result = json.loads(run["full_result_json"])
            except (json.JSONDecodeError, TypeError):
                pass

        mermaid_code = _extract_mermaid(full_result)

        return templates.TemplateResponse(
            request,
            "detail.html",
            {"run": run, "full_result": full_result, "mermaid_code": mermaid_code},
        )

    return router
