"""SQLite persistence layer for pipeline runs using aiosqlite."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from cvehunter.config import settings

_CREATE_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS runs (
    id            TEXT PRIMARY KEY,
    cve_id        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'running',
    error_code    TEXT,
    started_at    TEXT NOT NULL,
    completed_at  TEXT,
    exploitability_score REAL,
    summary       TEXT,
    full_result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_cve_id ON runs (cve_id);
"""


def _db_path() -> str:
    url = settings.database_url
    if url.startswith("sqlite:///"):
        return url[len("sqlite:///"):]
    return url


async def init_db() -> None:
    async with aiosqlite.connect(_db_path()) as db:
        await db.executescript(_CREATE_RUNS_TABLE)
        await db.commit()


async def create_run(cve_id: str) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_db_path()) as db:
        await db.execute(
            "INSERT INTO runs (id, cve_id, status, started_at) VALUES (?, ?, ?, ?)",
            (run_id, cve_id, "running", now),
        )
        await db.commit()
    return {"id": run_id, "cve_id": cve_id, "status": "running", "started_at": now}


async def get_run(cve_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM runs WHERE cve_id = ? ORDER BY started_at DESC LIMIT 1",
            (cve_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)


async def get_run_by_id(run_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)


async def list_runs() -> list[dict[str, Any]]:
    async with aiosqlite.connect(_db_path()) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM runs ORDER BY started_at DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def update_run(cve_id: str, **fields: Any) -> None:
    if "full_result_json" in fields and not isinstance(fields["full_result_json"], str):
        fields["full_result_json"] = json.dumps(fields["full_result_json"], default=str)
    if "completed_at" not in fields:
        fields["completed_at"] = datetime.now(timezone.utc).isoformat()

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [cve_id]
    async with aiosqlite.connect(_db_path()) as db:
        await db.execute(
            f"UPDATE runs SET {set_clause} WHERE cve_id = ? "  # noqa: S608
            "AND id = (SELECT id FROM runs WHERE cve_id = ? ORDER BY started_at DESC LIMIT 1)",
            values + [cve_id],
        )
        await db.commit()


async def has_running_run(cve_id: str) -> bool:
    async with aiosqlite.connect(_db_path()) as db:
        cursor = await db.execute(
            "SELECT 1 FROM runs WHERE cve_id = ? AND status = 'running' LIMIT 1",
            (cve_id,),
        )
        return await cursor.fetchone() is not None
