"""Tests for the run-service layer: structured_call, HITL/terminal status, and
the auth-free dashboard submit path."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from cvehunter.config import ModelTier
from cvehunter.llm_router import structured_call
from cvehunter.schemas import CVEPackage, JudgementReport


def _cve_package() -> CVEPackage:
    return CVEPackage(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        affected_software="Apache Log4j",
        language="java",
    )


class _FakeStructured:
    def __init__(self, result):
        self._result = result

    async def ainvoke(self, _messages):
        return self._result


class _FakeLLM:
    def __init__(self, result):
        self._result = result
        self.kwargs = None

    def with_structured_output(self, _schema, **kwargs):
        self.kwargs = kwargs
        return _FakeStructured(self._result)


@pytest.mark.asyncio
async def test_structured_call_returns_parsed_and_cost(mock_ai_message):
    raw = mock_ai_message(input_tokens=100, output_tokens=50)
    parsed = _cve_package()
    llm = _FakeLLM({"raw": raw, "parsed": parsed, "parsing_error": None})

    result, cost = await structured_call(llm, CVEPackage, [], ModelTier.SMART)

    assert result is parsed
    # 100/1e6*3 + 50/1e6*15 = 0.00105 — proves cost is captured from the raw msg.
    assert cost == pytest.approx(0.00105)
    assert llm.kwargs.get("include_raw") is True


@pytest.mark.asyncio
async def test_structured_call_parse_error_returns_none(mock_ai_message):
    raw = mock_ai_message(input_tokens=10, output_tokens=5)
    llm = _FakeLLM({"raw": raw, "parsed": None, "parsing_error": ValueError("bad")})

    result, cost = await structured_call(llm, CVEPackage, [], ModelTier.SMART)

    assert result is None
    # Cost is still charged for the failed call: 10/1e6*3 + 5/1e6*15.
    assert cost == pytest.approx(0.000105)


@pytest.mark.asyncio
async def test_execute_run_interrupt_sets_hitl_paused():
    from cvehunter.api import run_service

    captured: dict = {}

    async def fake_pipeline(_cve_id):
        return {
            "__interrupt__": [{"reason": "review"}],
            "judgement": JudgementReport(
                cve_id="CVE-X", exploitability_score=5.0, summary="pending"
            ),
            "status": "judged",
        }

    async def fake_update(_cve_id, **kwargs):
        captured.update(kwargs)

    with (
        patch.object(run_service, "run_pipeline", fake_pipeline),
        patch.object(run_service, "update_run", fake_update),
    ):
        await run_service._execute_run("CVE-X")

    assert captured["status"] == "hitl_paused"
    assert "completed_at" not in captured  # paused runs are not finished


@pytest.mark.asyncio
async def test_execute_run_judged_maps_to_completed():
    from cvehunter.api import run_service

    captured: dict = {}

    async def fake_pipeline(_cve_id):
        return {
            "judgement": JudgementReport(
                cve_id="CVE-X", exploitability_score=8.0, summary="done"
            ),
            "status": "judged",
        }

    async def fake_update(_cve_id, **kwargs):
        captured.update(kwargs)

    with (
        patch.object(run_service, "run_pipeline", fake_pipeline),
        patch.object(run_service, "update_run", fake_update),
    ):
        await run_service._execute_run("CVE-X")

    assert captured["status"] == "completed"
    assert captured["completed_at"]


def test_map_terminal_status():
    from cvehunter.api.run_service import _map_terminal_status

    assert _map_terminal_status("judged") == "completed"
    assert _map_terminal_status("judged_partial") == "judged_partial"
    assert _map_terminal_status("approved_by_human") == "approved_by_human"
    assert _map_terminal_status(None) == "completed"


def test_dashboard_submit_bypasses_api_key(monkeypatch):
    """The dashboard submit handler must work even when CVEHUNTER_API_KEY is set."""
    from cvehunter.api import run_service
    from cvehunter.api.main import app
    from cvehunter.config import settings

    monkeypatch.setattr(settings, "api_key", "secret")  # auth ON for /api/v1/*

    async def fake_launch(cve_id, _bg, *, simple_researcher=False):
        return {"id": "1", "cve_id": cve_id, "status": "running", "started_at": "now"}

    monkeypatch.setattr(run_service, "launch_run", AsyncMock(side_effect=fake_launch))

    client = TestClient(app)
    resp = client.post("/dashboard/actions/submit", data={"cve_id": "CVE-2021-44228"})

    assert resp.status_code == 200
    assert "Started analysis" in resp.text
