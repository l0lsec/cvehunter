"""LLM status and balance reporting.

Single source of truth for which LLMs are active, their per-token cost,
live provider balance (where supported), and local spend-to-date against
the configured monthly and per-CVE caps. Consumed by the CLI, the API,
and the dashboard.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import structlog
from pydantic import BaseModel, Field

from cvehunter.config import AGENT_MODEL_MAPPING, MODELS, ModelTier, settings
from cvehunter.cost_tracker import load_monthly_spend

logger = structlog.get_logger(__name__)


BILLING_URLS: dict[str, str] = {
    "deepseek": "https://platform.deepseek.com/usage",
    "anthropic": "https://console.anthropic.com/settings/billing",
    "openai": "https://platform.openai.com/usage",
    "google": "https://aistudio.google.com/app/apikey",
}

_DEEPSEEK_BALANCE_URL = "https://api.deepseek.com/user/balance"
_HTTP_TIMEOUT_SECONDS = 5.0


class ProviderBalance(BaseModel):
    currency: str | None = None
    total: float | None = None
    granted: float | None = None
    topped_up: float | None = None
    source: str = "unavailable"
    note: str | None = None


class LLMStatus(BaseModel):
    tier: str
    provider: str
    model_name: str
    active: bool
    assigned_agents: list[str] = Field(default_factory=list)
    cost_per_1m_input: float
    cost_per_1m_output: float
    balance: ProviderBalance | None = None
    billing_url: str


class SpendSummary(BaseModel):
    month: str
    monthly_spend_usd: float
    monthly_cap_usd: float
    monthly_remaining_usd: float
    per_cve_cap_usd: float


class LLMStatusReport(BaseModel):
    models: list[LLMStatus]
    spend: SpendSummary


def _provider_key(provider: str) -> str:
    return {
        "deepseek": settings.deepseek_api_key,
        "anthropic": settings.anthropic_api_key,
        "openai": settings.openai_api_key,
        "google": settings.google_api_key,
    }.get(provider, "")


def _agents_by_tier() -> dict[ModelTier, list[str]]:
    mapping: dict[ModelTier, list[str]] = {tier: [] for tier in ModelTier}
    for agent, tier in AGENT_MODEL_MAPPING.items():
        mapping.setdefault(tier, []).append(agent)
    return mapping


async def fetch_deepseek_balance(api_key: str) -> ProviderBalance:
    """Fetch live balance from DeepSeek's `/user/balance` endpoint.

    Returns a ProviderBalance with source="live" on success, or
    source="unavailable" with a short note on any failure.
    """
    if not api_key:
        return ProviderBalance(source="unavailable", note="no api key configured")
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                _DEEPSEEK_BALANCE_URL,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            resp.raise_for_status()
            payload = resp.json()
    except httpx.HTTPStatusError as e:
        logger.warning("deepseek_balance_http_error", status=e.response.status_code)
        return ProviderBalance(
            source="unavailable",
            note=f"http {e.response.status_code}",
        )
    except Exception as e:
        logger.warning("deepseek_balance_failed", error=str(e))
        return ProviderBalance(source="unavailable", note=str(e)[:120])

    infos = payload.get("balance_infos") or []
    if not infos:
        return ProviderBalance(source="unavailable", note="empty balance_infos")

    info = infos[0]

    def _f(value: object) -> float | None:
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    return ProviderBalance(
        currency=info.get("currency"),
        total=_f(info.get("total_balance")),
        granted=_f(info.get("granted_balance")),
        topped_up=_f(info.get("topped_up_balance")),
        source="live",
        note=None if payload.get("is_available", True) else "account not available",
    )


async def _balance_for_provider(provider: str, *, live: bool) -> ProviderBalance:
    key = _provider_key(provider)
    if provider == "deepseek" and live:
        return await fetch_deepseek_balance(key)
    if not key:
        return ProviderBalance(source="unavailable", note="no api key configured")
    return ProviderBalance(
        source="unavailable",
        note="provider does not expose a public balance endpoint; see billing dashboard",
    )


def _spend_summary() -> SpendSummary:
    monthly = load_monthly_spend()
    cap = settings.max_monthly_spend
    return SpendSummary(
        month=datetime.now(timezone.utc).strftime("%Y-%m"),
        monthly_spend_usd=round(monthly, 6),
        monthly_cap_usd=cap,
        monthly_remaining_usd=round(max(cap - monthly, 0.0), 6),
        per_cve_cap_usd=settings.max_cost_per_cve,
    )


async def build_report(*, live: bool = True) -> LLMStatusReport:
    """Build the full LLM status report.

    Walks `MODELS` to report every tier, pulls live balance where supported,
    and adds a configured-but-unused OpenAI entry if the key is present but
    no tier maps to OpenAI.
    """
    agents_by_tier = _agents_by_tier()

    statuses: list[LLMStatus] = []
    for tier, cfg in MODELS.items():
        key = _provider_key(cfg.provider)
        active = bool(key)
        balance = await _balance_for_provider(cfg.provider, live=live) if active else None
        statuses.append(
            LLMStatus(
                tier=tier.value,
                provider=cfg.provider,
                model_name=cfg.model_name,
                active=active,
                assigned_agents=sorted(agents_by_tier.get(tier, [])),
                cost_per_1m_input=cfg.cost_per_1m_input,
                cost_per_1m_output=cfg.cost_per_1m_output,
                balance=balance,
                billing_url=BILLING_URLS.get(cfg.provider, ""),
            )
        )

    wired_providers = {cfg.provider for cfg in MODELS.values()}
    if "openai" not in wired_providers and settings.openai_api_key:
        statuses.append(
            LLMStatus(
                tier="unused",
                provider="openai",
                model_name="(not wired)",
                active=False,
                assigned_agents=[],
                cost_per_1m_input=0.0,
                cost_per_1m_output=0.0,
                balance=ProviderBalance(
                    source="unavailable",
                    note="configured but not wired into MODELS",
                ),
                billing_url=BILLING_URLS["openai"],
            )
        )

    return LLMStatusReport(models=statuses, spend=_spend_summary())
