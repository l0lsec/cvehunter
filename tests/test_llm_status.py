"""Tests for the LLM status / balance reporter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from cvehunter import llm_status
from cvehunter.llm_status import (
    BILLING_URLS,
    LLMStatusReport,
    ProviderBalance,
    build_report,
    fetch_deepseek_balance,
)


def _mock_async_client(json_payload=None, status_code: int = 200):
    """Build a MagicMock suitable for patching httpx.AsyncClient."""
    response = MagicMock()
    response.status_code = status_code
    response.json = MagicMock(return_value=json_payload or {})
    if status_code >= 400:
        request = httpx.Request("GET", "https://api.deepseek.com/user/balance")
        response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "error", request=request, response=httpx.Response(status_code, request=request)
            )
        )
    else:
        response.raise_for_status = MagicMock(return_value=None)

    client = MagicMock()
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


@pytest.mark.asyncio
async def test_fetch_deepseek_balance_live_success():
    payload = {
        "is_available": True,
        "balance_infos": [
            {
                "currency": "USD",
                "total_balance": "12.3456",
                "granted_balance": "10.0",
                "topped_up_balance": "2.3456",
            }
        ],
    }
    client = _mock_async_client(json_payload=payload)
    with patch("cvehunter.llm_status.httpx.AsyncClient", return_value=client):
        balance = await fetch_deepseek_balance("fake-key")
    assert balance.source == "live"
    assert balance.currency == "USD"
    assert balance.total == pytest.approx(12.3456)
    assert balance.granted == pytest.approx(10.0)
    assert balance.topped_up == pytest.approx(2.3456)
    assert balance.note is None


@pytest.mark.asyncio
async def test_fetch_deepseek_balance_no_key():
    balance = await fetch_deepseek_balance("")
    assert balance.source == "unavailable"
    assert balance.note == "no api key configured"


@pytest.mark.asyncio
async def test_fetch_deepseek_balance_http_error():
    client = _mock_async_client(status_code=401)
    with patch("cvehunter.llm_status.httpx.AsyncClient", return_value=client):
        balance = await fetch_deepseek_balance("bad-key")
    assert balance.source == "unavailable"
    assert "401" in (balance.note or "")


@pytest.mark.asyncio
async def test_fetch_deepseek_balance_network_failure():
    client = MagicMock()
    client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    with patch("cvehunter.llm_status.httpx.AsyncClient", return_value=client):
        balance = await fetch_deepseek_balance("fake-key")
    assert balance.source == "unavailable"
    assert balance.note is not None


@pytest.mark.asyncio
async def test_build_report_respects_keys_and_wiring(monkeypatch):
    monkeypatch.setattr(llm_status.settings, "anthropic_api_key", "sk-ant-test")
    monkeypatch.setattr(llm_status.settings, "deepseek_api_key", "sk-ds-test")
    monkeypatch.setattr(llm_status.settings, "google_api_key", "")
    monkeypatch.setattr(llm_status.settings, "openai_api_key", "sk-oai-test")
    monkeypatch.setattr(llm_status.settings, "max_monthly_spend", 200.0)
    monkeypatch.setattr(llm_status.settings, "max_cost_per_cve", 25.0)
    monkeypatch.setattr(llm_status, "load_monthly_spend", lambda: 12.5)

    async def _fake_fetch(_key: str) -> ProviderBalance:
        return ProviderBalance(
            currency="USD",
            total=7.77,
            granted=5.0,
            topped_up=2.77,
            source="live",
        )

    monkeypatch.setattr(llm_status, "fetch_deepseek_balance", _fake_fetch)

    report = await build_report(live=True)

    assert isinstance(report, LLMStatusReport)

    by_tier = {m.tier: m for m in report.models}

    cheap = by_tier["cheap"]
    assert cheap.provider == "deepseek"
    assert cheap.active is True
    assert cheap.balance is not None
    assert cheap.balance.source == "live"
    assert cheap.balance.total == pytest.approx(7.77)
    assert cheap.billing_url == BILLING_URLS["deepseek"]
    assert "collector" in cheap.assigned_agents
    assert "builder" in cheap.assigned_agents
    assert "judge" in cheap.assigned_agents

    smart = by_tier["smart"]
    assert smart.provider == "anthropic"
    assert smart.active is True
    assert smart.balance is not None
    assert smart.balance.source == "unavailable"
    assert "researcher" in smart.assigned_agents
    assert "exploiter" in smart.assigned_agents

    heavy = by_tier["heavy"]
    assert heavy.provider == "anthropic"
    assert heavy.active is True
    assert heavy.assigned_agents == []

    gemini = by_tier["gemini"]
    assert gemini.provider == "google"
    assert gemini.active is False
    assert gemini.balance is None

    unused = by_tier.get("unused")
    assert unused is not None, "OpenAI should be reported as configured-but-unused"
    assert unused.provider == "openai"
    assert unused.active is False
    assert unused.balance is not None
    assert "not wired" in (unused.balance.note or "")

    spend = report.spend
    assert spend.monthly_spend_usd == pytest.approx(12.5)
    assert spend.monthly_cap_usd == pytest.approx(200.0)
    assert spend.monthly_remaining_usd == pytest.approx(187.5)
    assert spend.per_cve_cap_usd == pytest.approx(25.0)


@pytest.mark.asyncio
async def test_build_report_remaining_never_negative(monkeypatch):
    monkeypatch.setattr(llm_status.settings, "anthropic_api_key", "x")
    monkeypatch.setattr(llm_status.settings, "deepseek_api_key", "")
    monkeypatch.setattr(llm_status.settings, "google_api_key", "")
    monkeypatch.setattr(llm_status.settings, "openai_api_key", "")
    monkeypatch.setattr(llm_status.settings, "max_monthly_spend", 10.0)
    monkeypatch.setattr(llm_status, "load_monthly_spend", lambda: 42.0)

    report = await build_report(live=False)
    assert report.spend.monthly_remaining_usd == 0.0


def test_api_llms_endpoint_smoke(monkeypatch):
    """GET /api/v1/llms returns the report as JSON."""
    from cvehunter.api import routes as api_routes
    from cvehunter.api.main import app

    fake_report = LLMStatusReport(
        models=[],
        spend={
            "month": "2026-04",
            "monthly_spend_usd": 1.0,
            "monthly_cap_usd": 200.0,
            "monthly_remaining_usd": 199.0,
            "per_cve_cap_usd": 25.0,
        },
    )

    async def _fake_build_report(*, live: bool = True) -> LLMStatusReport:
        return fake_report

    monkeypatch.setattr(api_routes, "build_report", _fake_build_report)
    monkeypatch.setattr(api_routes.settings, "api_key", "")

    client = TestClient(app)
    resp = client.get("/api/v1/llms")
    assert resp.status_code == 200
    body = resp.json()
    assert body["spend"]["monthly_cap_usd"] == 200.0
    assert body["models"] == []
