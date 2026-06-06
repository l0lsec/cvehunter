"""Pydantic models shared across all agents."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TypedDict

from pydantic import BaseModel, Field

# ── Collector Output ──


class CVEPackage(BaseModel):
    """Structured vulnerability data produced by the Collector agent."""

    cve_id: str
    description: str
    cvss_score: float | None = None
    cwe_id: str | None = None
    affected_software: str
    affected_versions: list[str] = Field(default_factory=list)
    language: str
    framework: str | None = None
    patch_diff: str = ""
    vulnerable_code: str | None = None
    patched_code: str | None = None
    repo_url: str | None = None
    patch_commit: str | None = None
    references: list[str] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=datetime.utcnow)


# ── Researcher Output ──


class Primitive(BaseModel):
    """A single exploitation primitive in the vulnerability analysis."""

    id: str
    name: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = ""
    prerequisites: list[str] = Field(default_factory=list)


class PrimitivesGraph(BaseModel):
    """DAG of exploitation primitives and their dependencies."""

    nodes: dict[str, Primitive] = Field(default_factory=dict)
    edges: list[tuple[str, str]] = Field(default_factory=list)
    complete_chains: list[list[str]] = Field(default_factory=list)


class ExploitRecipe(BaseModel):
    """The exploitation strategy produced by the Researcher agent."""

    cve_id: str
    vulnerability_type: str
    attack_vector: str
    primitives_graph: PrimitivesGraph
    exploitation_steps: list[str]
    required_conditions: list[str] = Field(default_factory=list)
    estimated_complexity: str = "medium"
    notes: str = ""


# ── Environment Builder Output ──


class EnvironmentSpec(BaseModel):
    """Specification for the Docker test environment."""

    cve_id: str
    vulnerable_image: str
    patched_image: str
    compose_yaml: str
    dockerfile_content: str = ""
    health_check_command: str = ""
    flag_value: str
    flag_location: str
    network_name: str
    services: list[str] = Field(default_factory=list)
    health_check_passed: bool = False
    patched_network_name: str = ""
    credentials: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    name_prefix: str = ""
    run_hash: str = ""


# ── Exploiter Output ──


class ExploitAttempt(BaseModel):
    """Record of a single exploit attempt."""

    attempt_number: int
    exploit_code: str
    stdout: str = ""
    stderr: str = ""
    target_logs: dict[str, str] = Field(default_factory=dict)
    flag_captured: bool = False
    captured_value: str | None = None
    error_analysis: str = ""
    model_tier_used: str = "smart"


class ExploitResult(BaseModel):
    """Final result from the Exploiter agent."""

    cve_id: str
    success: bool
    attempts: list[ExploitAttempt] = Field(default_factory=list)
    final_exploit_code: str = ""
    flag_captured: bool = False
    fails_on_patched: bool = False
    total_attempts: int = 0


# ── Judge Output ──


class HITLLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class JudgementReport(BaseModel):
    """Final audit report from the Judge agent."""

    cve_id: str
    exploitability_score: float = Field(ge=0.0, le=10.0)
    exploit_genuine: bool = False
    environment_realistic: bool = False
    no_external_pocs_used: bool = True
    hitl_level: HITLLevel = HITLLevel.NONE
    shortcut_detected: bool = False
    shortcut_details: str | None = None
    summary: str = ""
    full_analysis: str = ""
    judged_at: datetime = Field(default_factory=datetime.utcnow)


# ── Pipeline State ──


class PipelineState(BaseModel):
    """Full state passed through the LangGraph pipeline (for serialization/API use)."""

    cve_id: str
    cve_package: CVEPackage | None = None
    exploit_recipe: ExploitRecipe | None = None
    environment: EnvironmentSpec | None = None
    exploit_result: ExploitResult | None = None
    judgement: JudgementReport | None = None
    total_cost_usd: float = 0.0
    errors: list[str] = Field(default_factory=list)
    status: str = "pending"


class GraphState(TypedDict, total=False):
    """Typed state for the LangGraph StateGraph (covers all runtime keys)."""

    cve_id: str
    cve_package: CVEPackage | None
    exploit_recipe: ExploitRecipe | None
    environment: EnvironmentSpec | None
    exploit_result: ExploitResult | None
    judgement: JudgementReport | None
    total_cost_usd: float
    errors: list[str]
    status: str
    researcher_attempts: int
    researcher_escalated: bool
    researcher_needs_escalation: bool
    current_stage: str | None
    stages_completed: list[str]
