"""Tiered LLM router — selects the right model based on agent role and escalation state."""

from __future__ import annotations

import os
from typing import Any

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from pydantic import BaseModel

from cvehunter.config import (
    AGENT_MODEL_MAPPING,
    MODELS,
    ROTATION_TIERS,
    ModelTier,
    settings,
)

logger = structlog.get_logger(__name__)


def _configure_langsmith() -> None:
    """Set LangSmith tracing env vars if enabled in settings."""
    if settings.langsmith_enabled:
        os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
        os.environ.setdefault("LANGCHAIN_PROJECT", settings.langsmith_project)
        logger.info(
            "langsmith_enabled",
            project=settings.langsmith_project,
        )


_configure_langsmith()


def _build_model(
    model_config: Any,
    *,
    temperature: float = 0.0,
) -> BaseChatModel:
    """Instantiate a LangChain chat model from a ModelConfig."""
    if model_config.provider == "anthropic":
        return ChatAnthropic(
            model=model_config.model_name,
            api_key=settings.anthropic_api_key,
            temperature=temperature,
            max_tokens=8192,
        )
    elif model_config.provider == "deepseek":
        return ChatOpenAI(
            model=model_config.model_name,
            api_key=settings.deepseek_api_key,
            base_url="https://api.deepseek.com/v1",
            temperature=temperature,
            max_tokens=8192,
            extra_body={"thinking": {"type": "disabled"}},
        )
    elif model_config.provider == "openai":
        return ChatOpenAI(
            model=model_config.model_name,
            api_key=settings.openai_api_key,
            temperature=temperature,
            max_tokens=8192,
        )
    elif model_config.provider == "google":
        return ChatGoogleGenerativeAI(
            model=model_config.model_name,
            google_api_key=settings.google_api_key,
            temperature=temperature,
            max_output_tokens=8192,
        )
    else:
        raise ValueError(f"Unknown provider: {model_config.provider}")


def get_model(
    agent_name: str,
    *,
    escalate: bool = False,
    temperature: float = 0.0,
) -> BaseChatModel:
    """Return the appropriate LLM for the given agent.

    If escalate=True and the agent's default tier is SMART, bumps to HEAVY.
    """
    tier = AGENT_MODEL_MAPPING.get(agent_name, ModelTier.SMART)
    if escalate and tier == ModelTier.SMART:
        tier = ModelTier.HEAVY

    model_config = MODELS[tier]
    logger.debug(
        "model_selected",
        agent=agent_name,
        tier=tier.value,
        model=model_config.model_name,
        provider=model_config.provider,
        escalated=escalate,
    )

    return _build_model(model_config, temperature=temperature)


def get_model_by_tier(
    tier: ModelTier,
    *,
    temperature: float = 0.0,
) -> BaseChatModel:
    """Return a model instance for a specific tier."""
    model_config = MODELS[tier]
    return _build_model(model_config, temperature=temperature)


def get_rotation_models(*, temperature: float = 0.0) -> list[tuple[ModelTier, BaseChatModel]]:
    """Return the list of (tier, model) pairs used for researcher swarm rotation.

    Skips tiers whose API keys are not configured.
    """
    available: list[tuple[ModelTier, BaseChatModel]] = []
    for tier in ROTATION_TIERS:
        cfg = MODELS[tier]
        has_key = (
            (cfg.provider == "deepseek" and settings.deepseek_api_key)
            or (cfg.provider == "anthropic" and settings.anthropic_api_key)
            or (cfg.provider == "openai" and settings.openai_api_key)
            or (cfg.provider == "google" and settings.google_api_key)
        )
        if has_key:
            available.append((tier, _build_model(cfg, temperature=temperature)))
    if not available:
        fallback_tier = ModelTier.SMART
        available.append(
            (fallback_tier, _build_model(MODELS[fallback_tier], temperature=temperature))
        )
    return available


def estimate_cost(input_tokens: int, output_tokens: int, tier: ModelTier) -> float:
    """Estimate the cost of an LLM call in USD."""
    model_config = MODELS[tier]
    input_cost = (input_tokens / 1_000_000) * model_config.cost_per_1m_input
    output_cost = (output_tokens / 1_000_000) * model_config.cost_per_1m_output
    return input_cost + output_cost


def get_tier_for_agent(agent_name: str, *, escalate: bool = False) -> ModelTier:
    """Return the ModelTier for the given agent (with optional escalation)."""
    tier = AGENT_MODEL_MAPPING.get(agent_name, ModelTier.SMART)
    if escalate and tier == ModelTier.SMART:
        tier = ModelTier.HEAVY
    return tier


def extract_cost(response: Any, tier: ModelTier) -> float:
    """Extract cost from an LLM response's usage metadata."""
    usage = getattr(response, "usage_metadata", None)
    if not usage:
        return 0.0
    return estimate_cost(
        usage.get("input_tokens", 0),
        usage.get("output_tokens", 0),
        tier,
    )


async def structured_call(
    llm: BaseChatModel,
    schema: type[BaseModel],
    messages: list[BaseMessage],
    tier: ModelTier,
) -> tuple[BaseModel | None, float]:
    """Invoke an LLM for a structured (Pydantic) output and report its cost.

    Uses ``with_structured_output(..., include_raw=True)`` so we can read the
    raw ``AIMessage`` usage metadata (the parsed object alone carries no usage,
    which previously made every structured call report ``$0`` and silently
    defeated the cost limits). Parsing failures are surfaced as a ``None``
    result instead of an unhandled exception that would crash the agent node.

    Returns ``(parsed_model_or_None, cost_usd)``.
    """
    structured_llm = llm.with_structured_output(
        schema, method="function_calling", include_raw=True
    )
    try:
        result = await structured_llm.ainvoke(messages)
    except Exception:
        logger.exception("structured_output_invoke_failed", schema=schema.__name__)
        return None, 0.0

    raw = result.get("raw") if isinstance(result, dict) else None
    parsed = result.get("parsed") if isinstance(result, dict) else result
    parsing_error = result.get("parsing_error") if isinstance(result, dict) else None

    cost = extract_cost(raw, tier) if raw is not None else 0.0

    if parsing_error is not None or parsed is None:
        logger.warning(
            "structured_output_parse_failed",
            schema=schema.__name__,
            error=str(parsing_error) if parsing_error else "no parsed object returned",
        )
        return None, cost

    return parsed, cost
