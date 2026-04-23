"""Configuration and environment variable loading."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


class ModelTier(str, Enum):
    CHEAP = "cheap"
    SMART = "smart"
    HEAVY = "heavy"


class ModelConfig(BaseModel):
    """Configuration for a single LLM model."""

    provider: str
    model_name: str
    tier: ModelTier
    cost_per_1m_input: float
    cost_per_1m_output: float


MODELS = {
    ModelTier.CHEAP: ModelConfig(
        provider="deepseek",
        model_name="deepseek-chat",
        tier=ModelTier.CHEAP,
        cost_per_1m_input=0.14,
        cost_per_1m_output=0.28,
    ),
    ModelTier.SMART: ModelConfig(
        provider="anthropic",
        model_name="claude-sonnet-4-20250514",
        tier=ModelTier.SMART,
        cost_per_1m_input=3.0,
        cost_per_1m_output=15.0,
    ),
    ModelTier.HEAVY: ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-20250918",
        tier=ModelTier.HEAVY,
        cost_per_1m_input=15.0,
        cost_per_1m_output=75.0,
    ),
}

AGENT_MODEL_MAPPING: dict[str, ModelTier] = {
    "collector": ModelTier.CHEAP,
    "researcher": ModelTier.SMART,
    "builder": ModelTier.CHEAP,
    "exploiter": ModelTier.SMART,
    "judge": ModelTier.CHEAP,
}


class Settings(BaseModel):
    """Global application settings."""

    anthropic_api_key: str = Field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    deepseek_api_key: str = Field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""))
    openai_api_key: str = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
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
    artifact_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("ARTIFACT_DIR", "./artifacts"))
    )
    database_url: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./moak.db")
    )

    exploiter_max_attempts_smart: int = 10
    exploiter_max_attempts_heavy: int = 5
    researcher_escalation_threshold: int = 3


settings = Settings()
