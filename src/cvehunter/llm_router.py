"""Tiered LLM router — selects the right model based on agent role and escalation state."""

from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI

from moak.config import AGENT_MODEL_MAPPING, MODELS, ModelTier, settings


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
        )
    elif model_config.provider == "openai":
        return ChatOpenAI(
            model=model_config.model_name,
            api_key=settings.openai_api_key,
            temperature=temperature,
            max_tokens=8192,
        )
    else:
        raise ValueError(f"Unknown provider: {model_config.provider}")


def estimate_cost(input_tokens: int, output_tokens: int, tier: ModelTier) -> float:
    """Estimate the cost of an LLM call in USD."""
    model_config = MODELS[tier]
    input_cost = (input_tokens / 1_000_000) * model_config.cost_per_1m_input
    output_cost = (output_tokens / 1_000_000) * model_config.cost_per_1m_output
    return input_cost + output_cost
