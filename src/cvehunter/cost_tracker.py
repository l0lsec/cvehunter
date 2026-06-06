"""Cost tracking and limit enforcement for pipeline runs."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from cvehunter.config import settings

_SPEND_FILE = settings.artifact_dir / ".monthly_spend.json"


def load_monthly_spend() -> float:
    """Load the accumulated monthly spend from disk."""
    if not _SPEND_FILE.exists():
        return 0.0
    try:
        data = json.loads(_SPEND_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return 0.0
    current_month = datetime.now(UTC).strftime("%Y-%m")
    if data.get("month") != current_month:
        return 0.0
    return data.get("total", 0.0)


def save_monthly_spend(total: float) -> None:
    """Persist the accumulated monthly spend to disk."""
    _SPEND_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SPEND_FILE.write_text(
        json.dumps(
            {
                "month": datetime.now(UTC).strftime("%Y-%m"),
                "total": round(total, 6),
            }
        )
    )


def check_cost_limits(run_cost: float) -> str | None:
    """Return an error message if any cost limit is exceeded, else None."""
    if run_cost > settings.max_cost_per_cve:
        return (
            f"Per-CVE cost limit exceeded: ${run_cost:.2f} > "
            f"${settings.max_cost_per_cve:.2f}"
        )
    monthly = load_monthly_spend()
    if monthly + run_cost > settings.max_monthly_spend:
        return (
            f"Monthly spend limit exceeded: ${monthly + run_cost:.2f} > "
            f"${settings.max_monthly_spend:.2f}"
        )
    return None
