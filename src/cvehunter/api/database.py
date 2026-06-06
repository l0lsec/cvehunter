"""SQLite persistence layer for pipeline runs using aiosqlite."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import aiosqlite
from pydantic import BaseModel

from cvehunter.config import settings


def _json_default(obj: Any) -> Any:
    """Serialize Pydantic models as dicts; fall back to ``str`` for everything else.

    Using bare ``default=str`` collapses Pydantic models into their repr
    (``field='value' ...``), which round-trips as a string instead of a dict
    and breaks downstream consumers that expect nested JSON objects.
    """
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return str(obj)

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
    full_result_json TEXT,
    current_stage TEXT,
    stages_completed TEXT,
    cost_usd_live REAL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_runs_cve_id ON runs (cve_id);
"""

# Columns added after the initial schema; applied idempotently on startup so
# existing local DBs pick up the new progress-tracking fields without a manual
# migration step.
_RUNS_EXTRA_COLUMNS: list[tuple[str, str]] = [
    ("current_stage", "TEXT"),
    ("stages_completed", "TEXT"),
    ("cost_usd_live", "REAL DEFAULT 0.0"),
]


def _db_path() -> str:
    url = settings.database_url
    if url.startswith("sqlite:///"):
        return url[len("sqlite:///"):]
    return url


async def _apply_migrations(db: aiosqlite.Connection) -> None:
    cursor = await db.execute("PRAGMA table_info(runs)")
    existing = {row[1] for row in await cursor.fetchall()}
    for name, type_clause in _RUNS_EXTRA_COLUMNS:
        if name not in existing:
            await db.execute(f"ALTER TABLE runs ADD COLUMN {name} {type_clause}")


async def init_db() -> None:
    async with aiosqlite.connect(_db_path()) as db:
        await db.executescript(_CREATE_RUNS_TABLE)
        await _apply_migrations(db)
        await db.commit()


async def create_run(cve_id: str) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
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
    """Update columns on the latest run row for a CVE.

    Callers that represent a *terminal* state must pass ``completed_at``
    explicitly (use ``datetime.now(timezone.utc).isoformat()``). In-flight
    status changes (``running``/``resuming``/``cancelling``/``hitl_paused``)
    intentionally omit it so the UI doesn't mislabel a live run as finished.
    """
    if "full_result_json" in fields and not isinstance(fields["full_result_json"], str):
        fields["full_result_json"] = json.dumps(
            fields["full_result_json"], default=_json_default
        )

    if not fields:
        return

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
            "SELECT 1 FROM runs WHERE cve_id = ? "
            "AND status IN ('running', 'resuming', 'cancelling') LIMIT 1",
            (cve_id,),
        )
        return await cursor.fetchone() is not None


async def update_run_progress(
    cve_id: str,
    *,
    current_stage: str | None = None,
    cost_usd_live: float | None = None,
    append_completed: str | None = None,
    clear_current_stage: bool = False,
) -> None:
    """Update progress fields without touching ``completed_at``.

    ``update_run`` always stamps ``completed_at`` as a side-effect, which would
    mislead the UI into treating an in-flight run as finished. This helper is
    the narrow mid-pipeline alternative.
    """
    sets: list[str] = []
    values: list[Any] = []

    if current_stage is not None or clear_current_stage:
        sets.append("current_stage = ?")
        values.append(current_stage)

    if cost_usd_live is not None:
        sets.append("cost_usd_live = ?")
        values.append(cost_usd_live)

    if append_completed is not None:
        row = await get_run(cve_id)
        completed: list[str] = []
        if row and row.get("stages_completed"):
            try:
                parsed = json.loads(row["stages_completed"])
                if isinstance(parsed, list):
                    completed = [str(x) for x in parsed]
            except (json.JSONDecodeError, TypeError):
                completed = []
        if append_completed not in completed:
            completed.append(append_completed)
        sets.append("stages_completed = ?")
        values.append(json.dumps(completed))

    if not sets:
        return

    values.extend([cve_id, cve_id])
    async with aiosqlite.connect(_db_path()) as db:
        await db.execute(
            f"UPDATE runs SET {', '.join(sets)} WHERE cve_id = ? "  # noqa: S608
            "AND id = (SELECT id FROM runs WHERE cve_id = ? ORDER BY started_at DESC LIMIT 1)",
            values,
        )
        await db.commit()


async def reset_checkpoint(checkpoint_db_path: str, thread_id: str) -> None:
    """Delete LangGraph checkpoints for a given thread_id so a retry starts fresh.

    LangGraph's ``AsyncSqliteSaver`` stores per-thread state in ``checkpoints``
    and ``writes`` tables. Without clearing them, a re-invocation with the same
    ``thread_id`` would silently resume instead of re-running from scratch.
    """
    import os

    if not os.path.exists(checkpoint_db_path):
        return

    async with aiosqlite.connect(checkpoint_db_path) as db:
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in await cursor.fetchall()}
        for table in ("checkpoints", "writes", "checkpoint_writes", "checkpoint_blobs"):
            if table in tables:
                await db.execute(
                    f"DELETE FROM {table} WHERE thread_id = ?",  # noqa: S608
                    (thread_id,),
                )
        await db.commit()
