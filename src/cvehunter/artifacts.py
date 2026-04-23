"""Artifact persistence — saves pipeline outputs to disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cvehunter.config import settings

_ARTIFACT_KEYS = {
    "cve_package": "cve_package.json",
    "exploit_recipe": "exploit_recipe.json",
    "environment": "environment_spec.json",
    "exploit_result": "exploit_result.json",
    "judgement": "judgement_report.json",
}


def save_artifacts(cve_id: str, state: dict[str, Any]) -> Path:
    """Write all pipeline artifacts for a CVE run to the artifact directory."""
    out_dir = settings.artifact_dir / cve_id
    out_dir.mkdir(parents=True, exist_ok=True)

    for key, filename in _ARTIFACT_KEYS.items():
        obj = state.get(key)
        if obj is None:
            continue
        data = (
            obj.model_dump_json(indent=2)
            if hasattr(obj, "model_dump_json")
            else json.dumps(obj, indent=2, default=str)
        )
        (out_dir / filename).write_text(data)

    (out_dir / "run_metadata.json").write_text(
        json.dumps(
            {
                "cve_id": cve_id,
                "status": state.get("status"),
                "total_cost_usd": state.get("total_cost_usd", 0.0),
                "errors": state.get("errors", []),
            },
            indent=2,
        )
    )

    return out_dir
