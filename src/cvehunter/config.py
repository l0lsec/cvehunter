"""Configuration and environment variable loading."""

from __future__ import annotations

import os
import warnings
from enum import StrEnum
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


class ModelTier(StrEnum):
    CHEAP = "cheap"
    SMART = "smart"
    HEAVY = "heavy"
    GEMINI = "gemini"


class ModelConfig(BaseModel):
    """Configuration for a single LLM model."""

    provider: str
    model_name: str
    tier: ModelTier
    cost_per_1m_input: float
    cost_per_1m_output: float


MODELS: dict[ModelTier, ModelConfig] = {
    ModelTier.CHEAP: ModelConfig(
        provider="anthropic",
        model_name="claude-haiku-4-5",
        tier=ModelTier.CHEAP,
        cost_per_1m_input=1.0,
        cost_per_1m_output=5.0,
    ),
    ModelTier.SMART: ModelConfig(
        provider="anthropic",
        model_name="claude-sonnet-4-6",
        tier=ModelTier.SMART,
        cost_per_1m_input=3.0,
        cost_per_1m_output=15.0,
    ),
    ModelTier.HEAVY: ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-8",
        tier=ModelTier.HEAVY,
        cost_per_1m_input=5.0,
        cost_per_1m_output=25.0,
    ),
    # Dormant: kept so users can opt back into a Gemini tier via config, but no
    # agent maps to it and it is not part of the default Anthropic-only rotation.
    ModelTier.GEMINI: ModelConfig(
        provider="google",
        model_name="gemini-2.5-pro",
        tier=ModelTier.GEMINI,
        cost_per_1m_input=1.25,
        cost_per_1m_output=10.0,
    ),
}

# Anthropic-only researcher-swarm rotation (Sonnet ↔ Opus). The swarm's value
# comes from its four role-diverse sub-agents, not cross-provider diversity.
ROTATION_TIERS: list[ModelTier] = [ModelTier.SMART, ModelTier.HEAVY]

AGENT_MODEL_MAPPING: dict[str, ModelTier] = {
    "collector": ModelTier.CHEAP,
    "researcher": ModelTier.SMART,
    "builder": ModelTier.CHEAP,
    "exploiter": ModelTier.SMART,
    "judge": ModelTier.CHEAP,
}

# Per-agent tier overrides via ``<AGENT>_MODEL_TIER`` env vars (value: a ModelTier
# name like "cheap"/"smart"/"heavy"). The builder is the most fidelity-sensitive
# agent — constructing a correctly-versioned, correctly-misconfigured vulnerable
# lab is hard for the cheap tier — so escalating just the builder (e.g.
# ``BUILDER_MODEL_TIER=smart``) is a common, cost-effective tweak.
_VALID_TIERS = {tier.value: tier for tier in ModelTier}
for _agent in list(AGENT_MODEL_MAPPING):
    _override = os.getenv(f"{_agent.upper()}_MODEL_TIER", "").strip().lower()
    if _override in _VALID_TIERS:
        AGENT_MODEL_MAPPING[_agent] = _VALID_TIERS[_override]


class Settings(BaseModel):
    """Global application settings."""

    anthropic_api_key: str = Field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    deepseek_api_key: str = Field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""))
    openai_api_key: str = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    google_api_key: str = Field(default_factory=lambda: os.getenv("GOOGLE_API_KEY", ""))
    nvd_api_key: str = Field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))
    github_token: str = Field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))

    max_cost_per_cve: float = Field(
        default_factory=lambda: float(os.getenv("MAX_COST_PER_CVE", "25.0"))
    )
    max_monthly_spend: float = Field(
        default_factory=lambda: float(os.getenv("MAX_MONTHLY_SPEND", "200.0"))
    )

    docker_host: str = Field(
        default_factory=lambda: os.getenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    )
    compose_up_timeout_seconds: int = Field(
        default_factory=lambda: int(os.getenv("COMPOSE_UP_TIMEOUT_SECONDS", "600"))
    )
    # When true, a failed network-isolation check (network not internal, or an
    # outbound probe that reached the internet) aborts the build with
    # ``environment_failed`` instead of only logging a warning. compose_up forces
    # ``internal: true`` on project networks, so this should pass by construction;
    # a failure here means the lab can egress and must not run.
    network_isolation_enforced: bool = Field(
        default_factory=lambda: os.getenv("NETWORK_ISOLATION_ENFORCED", "true").lower()
        == "true"
    )
    health_check_attempts: int = Field(
        default_factory=lambda: int(os.getenv("HEALTH_CHECK_ATTEMPTS", "12"))
    )
    health_check_delay_seconds: float = Field(
        default_factory=lambda: float(os.getenv("HEALTH_CHECK_DELAY_SECONDS", "5"))
    )
    artifact_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("ARTIFACT_DIR", "./artifacts"))
    )
    database_url: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./cvehunter.db")
    )
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            o.strip()
            for o in os.getenv(
                "CORS_ORIGINS", "http://localhost:3000,http://localhost:8000"
            ).split(",")
            if o.strip()
        ]
    )
    api_key: str = Field(default_factory=lambda: os.getenv("CVEHUNTER_API_KEY", ""))

    exploiter_max_attempts_smart: int = 10
    exploiter_max_attempts_heavy: int = 5
    exploiter_timeout_seconds: int = 180
    researcher_escalation_threshold: int = 3
    researcher_swarm_enabled: bool = Field(
        default_factory=lambda: os.getenv("RESEARCHER_SWARM_ENABLED", "true").lower() == "true"
    )

    langsmith_enabled: bool = Field(
        default_factory=lambda: os.getenv("LANGCHAIN_TRACING_V2", "").lower() == "true"
    )
    langsmith_project: str = Field(
        default_factory=lambda: os.getenv("LANGCHAIN_PROJECT", "cvehunter")
    )

    def validate_keys(self) -> None:
        """Raise if required API keys are missing; warn for optional ones."""
        missing = []
        if not self.anthropic_api_key:
            missing.append("ANTHROPIC_API_KEY")
        if missing:
            raise ValueError(
                f"Required API keys not set: {', '.join(missing)}. "
                "Set them in your .env file or environment."
            )
        if not self.deepseek_api_key:
            warnings.warn(
                "DEEPSEEK_API_KEY not set; DeepSeek is optional (all tiers default to Anthropic)"
            )
        if not self.nvd_api_key:
            warnings.warn("NVD_API_KEY not set; NVD queries will be rate-limited")
        if not self.github_token:
            warnings.warn("GITHUB_TOKEN not set; GitHub API limited to 60 req/hr")
        if not self.google_api_key:
            warnings.warn(
                "GOOGLE_API_KEY not set; Gemini is optional (not used by default)"
            )


settings = Settings()
