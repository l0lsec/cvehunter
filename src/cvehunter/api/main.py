"""FastAPI application entry point."""

from __future__ import annotations

from fastapi import FastAPI

from moak.api.routes import router

app = FastAPI(
    title="MOAK-Lite",
    description="Autonomous CVE exploitation pipeline API",
    version="0.1.0",
)

app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok"}
