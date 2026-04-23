"""Dashboard routes serving Jinja2/HTMX pages."""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from cvehunter.api.database import get_run, list_runs
from cvehunter.graph_viz import primitives_to_mermaid
from cvehunter.llm_status import build_report
from cvehunter.schemas import PrimitivesGraph


def _extract_mermaid(full_result: dict | None) -> str:
    """Pull the primitives graph from a full result dict and render as Mermaid."""
    if not full_result:
        return ""
    recipe = full_result.get("exploit_recipe")
    if not recipe:
        return ""
    pg = recipe.get("primitives_graph")
    if not pg:
        return ""
    try:
        graph = PrimitivesGraph.model_validate(pg)
        return primitives_to_mermaid(graph)
    except Exception:
        return ""


def build_dashboard_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(prefix="/dashboard", default_response_class=HTMLResponse)

    @router.get("/")
    async def dashboard_index(request: Request) -> HTMLResponse:
        runs = await list_runs()
        return templates.TemplateResponse(request, "index.html", {"runs": runs})

    @router.get("/partials/runs-table")
    async def runs_table_partial(request: Request) -> HTMLResponse:
        runs = await list_runs()
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
        run = await get_run(cve_id)
        if run is None:
            return HTMLResponse("<tr><td colspan='5'>Not found</td></tr>")
        return templates.TemplateResponse(request, "partials/run_row.html", {"run": run})

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
