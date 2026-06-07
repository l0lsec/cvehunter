"""FastAPI application entry point."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cvehunter.api.database import init_db
from cvehunter.api.errors import ErrorCode, ErrorResponse
from cvehunter.api.routes import router
from cvehunter.config import settings

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    await init_db()
    yield


app = FastAPI(
    title="CVEHunter",
    description="Autonomous CVE exploitation pipeline API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")


@app.exception_handler(Exception)
async def global_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    body = ErrorResponse.from_code(ErrorCode.INTERNAL_ERROR, detail=str(exc))
    return JSONResponse(status_code=500, content=body.model_dump(mode="json"))


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}


def mount_dashboard() -> None:
    """Attach dashboard templates and routes (called after all API routes)."""
    from cvehunter.dashboard.routes import build_dashboard_router

    templates_dir = _DASHBOARD_DIR / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))
    dashboard_router = build_dashboard_router(templates)
    app.include_router(dashboard_router)

    static_dir = _DASHBOARD_DIR / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


mount_dashboard()
