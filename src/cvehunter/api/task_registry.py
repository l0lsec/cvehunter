"""In-process registry of running pipeline asyncio tasks keyed by CVE ID.

Used to support hard-cancellation of in-flight runs: when the user clicks
Cancel, we look up the task here and call ``.cancel()`` on it. The registry
is intentionally process-local; on server restart any entries are lost (and
the corresponding DB rows stay stuck at ``running`` until a future
reconciliation pass cleans them up).
"""

from __future__ import annotations

import asyncio

_tasks: dict[str, asyncio.Task] = {}


def register(cve_id: str, task: asyncio.Task) -> None:
    _tasks[cve_id] = task


def get(cve_id: str) -> asyncio.Task | None:
    return _tasks.get(cve_id)


def pop(cve_id: str) -> asyncio.Task | None:
    return _tasks.pop(cve_id, None)


def is_running(cve_id: str) -> bool:
    task = _tasks.get(cve_id)
    return task is not None and not task.done()
