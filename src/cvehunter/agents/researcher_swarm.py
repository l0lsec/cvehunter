"""Multi-model Researcher sub-agent swarm.

Implements the four-role swarm architecture:
  1. Prioritizer  — ranks exploitation paths and assigns focus areas
  2. Lead Researcher — deep analysis of the top-priority path
  3. Contrarian   — challenges assumptions, finds alternative paths
  4. Verifier     — validates that the combined recipe is internally consistent

Models rotate across iterations: [Sonnet, Opus] (skipping any whose API key
is absent). Falls back to single-model researcher if only one model is
available.

Uses LangGraph's Send API for parallel fan-out of Lead + Contrarian.
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.constants import Send

from cvehunter.config import ModelTier, settings
from cvehunter.cost_tracker import check_cost_limits
from cvehunter.llm_router import extract_cost, get_rotation_models, structured_call
from cvehunter.schemas import CVEPackage, ExploitRecipe

logger = structlog.get_logger(__name__)


# ── Sub-agent prompts ──

PRIORITIZER_PROMPT = """\
You are a vulnerability triage specialist. Given CVE data, identify and rank \
the most promising exploitation paths. For each path, provide:
- A short label and one-sentence rationale
- Estimated feasibility (high/medium/low)

Return a ranked list of 2-4 exploitation paths with focus areas for deeper analysis.
Do NOT write exploit code.
"""

LEAD_RESEARCHER_PROMPT = """\
You are a lead vulnerability researcher. You have been assigned a specific \
exploitation path to analyze in depth. Your task:

1. Identify all exploitation primitives along this path
2. Build a dependency graph of these primitives
3. Find at least one complete exploitation chain
4. Produce detailed step-by-step exploitation instructions

Focus on technical precision. Use the patch diff to ground your analysis.
Do NOT generate actual exploit code — only the strategy and steps.
"""

CONTRARIAN_PROMPT = """\
You are a contrarian vulnerability analyst. Your job is to:

1. Challenge the primary exploitation path — identify weaknesses and assumptions
2. Propose at least one ALTERNATIVE exploitation path that the lead may have missed
3. Identify primitives that were overlooked or underestimated
4. Add any missing edges or prerequisites to the dependency graph

Be skeptical. Look for non-obvious attack surfaces in the patch diff.
Do NOT generate actual exploit code — only the strategy and steps.
"""

VERIFIER_PROMPT = """\
You are an exploitation chain verifier. You receive two independent analyses \
of the same vulnerability (lead and contrarian). Your task:

1. Merge the best primitives and chains from both analyses
2. Verify internal consistency — do all prerequisites actually exist?
3. Remove duplicates and contradictions
4. Produce a single, validated ExploitRecipe with a complete PrimitivesGraph

If neither analysis produced a viable complete chain, say so explicitly and \
set complete_chains to an empty list.
"""


def _build_cve_context(cve_package: CVEPackage) -> str:
    return f"""## CVE: {cve_package.cve_id}

**Description:** {cve_package.description}

**Affected Software:** {cve_package.affected_software}
**Language:** {cve_package.language}
**Framework:** {cve_package.framework or 'N/A'}
**CVSS Score:** {cve_package.cvss_score or 'N/A'}
**CWE:** {cve_package.cwe_id or 'N/A'}

## Patch Diff
```
{cve_package.patch_diff}
```

## Vulnerable Code
```
{cve_package.vulnerable_code or 'Not available'}
```

## Patched Code
```
{cve_package.patched_code or 'Not available'}
```
"""


# ── Sub-agent functions (used as LangGraph nodes) ──


async def _prioritizer(state: dict[str, Any]) -> dict[str, Any]:
    """Rank exploitation paths and produce focus areas."""
    model: BaseChatModel = state["_current_model"]
    tier: ModelTier = state["_current_tier"]
    cve_package: CVEPackage = state["cve_package"]

    messages = [
        SystemMessage(content=PRIORITIZER_PROMPT),
        HumanMessage(content=_build_cve_context(cve_package)),
    ]
    response = await model.ainvoke(messages)
    cost = extract_cost(response, tier)

    return {
        "_prioritized_context": response.content,
        "_accumulated_cost": state.get("_accumulated_cost", 0.0) + cost,
    }


async def _lead_researcher(state: dict[str, Any]) -> dict[str, Any]:
    """Deep analysis of the primary exploitation path."""
    model: BaseChatModel = state["_current_model"]
    tier: ModelTier = state["_current_tier"]
    cve_package: CVEPackage = state["cve_package"]
    priorities = state.get("_prioritized_context", "")

    context = _build_cve_context(cve_package) + f"\n\n## Prioritized Paths\n{priorities}"
    messages = [
        SystemMessage(content=LEAD_RESEARCHER_PROMPT),
        HumanMessage(content=context),
    ]

    recipe, cost = await structured_call(model, ExploitRecipe, messages, tier)

    return {
        "_lead_recipe": recipe,
        "_accumulated_cost": state.get("_accumulated_cost", 0.0) + cost,
    }


async def _contrarian(state: dict[str, Any]) -> dict[str, Any]:
    """Challenge and propose alternative exploitation paths."""
    model: BaseChatModel = state["_current_model"]
    tier: ModelTier = state["_current_tier"]
    cve_package: CVEPackage = state["cve_package"]
    priorities = state.get("_prioritized_context", "")

    context = _build_cve_context(cve_package) + f"\n\n## Prioritized Paths\n{priorities}"
    messages = [
        SystemMessage(content=CONTRARIAN_PROMPT),
        HumanMessage(content=context),
    ]

    recipe, cost = await structured_call(model, ExploitRecipe, messages, tier)

    return {
        "_contrarian_recipe": recipe,
        "_accumulated_cost": state.get("_accumulated_cost", 0.0) + cost,
    }


async def _verifier(state: dict[str, Any]) -> dict[str, Any]:
    """Merge and validate the lead + contrarian analyses."""
    model: BaseChatModel = state["_current_model"]
    tier: ModelTier = state["_current_tier"]
    cve_package: CVEPackage = state["cve_package"]

    lead: ExploitRecipe | None = state.get("_lead_recipe")
    contrarian: ExploitRecipe | None = state.get("_contrarian_recipe")

    lead_json = lead.model_dump_json(indent=2) if lead else "No lead analysis available."
    contrarian_json = (
        contrarian.model_dump_json(indent=2)
        if contrarian
        else "No contrarian analysis available."
    )

    context = f"""{_build_cve_context(cve_package)}

## Lead Researcher Analysis
```json
{lead_json}
```

## Contrarian Analysis
```json
{contrarian_json}
```
"""

    messages = [
        SystemMessage(content=VERIFIER_PROMPT),
        HumanMessage(content=context),
    ]

    recipe, cost = await structured_call(model, ExploitRecipe, messages, tier)

    return {
        "_verified_recipe": recipe,
        "_accumulated_cost": state.get("_accumulated_cost", 0.0) + cost,
    }


# ── Fan-out helper for parallel Lead + Contrarian ──


def _fan_out_researchers(state: dict[str, Any]) -> list[Send]:
    """Send the state to both Lead Researcher and Contrarian in parallel."""
    return [
        Send("lead_researcher", state),
        Send("contrarian", state),
    ]


# ── Main swarm entry point ──


async def run_researcher_swarm(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the multi-model researcher swarm.

    This is the top-level node wired into the main pipeline when
    ``settings.researcher_swarm_enabled`` is True.

    Each iteration rotates through available models. The swarm runs up to
    ``settings.researcher_escalation_threshold`` iterations before giving up.
    """
    cost_error = check_cost_limits(state.get("total_cost_usd", 0.0))
    if cost_error:
        return {
            "errors": state.get("errors", []) + [cost_error],
            "status": "cost_limit_exceeded",
            "total_cost_usd": state.get("total_cost_usd", 0.0),
        }

    cve_package: CVEPackage = state["cve_package"]
    researcher_attempts = state.get("researcher_attempts", 0) + 1
    run_cost = state.get("total_cost_usd", 0.0)

    rotation = get_rotation_models()
    idx = (researcher_attempts - 1) % len(rotation)
    tier, model = rotation[idx]

    logger.info(
        "researcher_swarm_iteration",
        cve_id=cve_package.cve_id,
        attempt=researcher_attempts,
        model_tier=tier.value,
    )

    swarm_state: dict[str, Any] = {
        "cve_package": cve_package,
        "_current_model": model,
        "_current_tier": tier,
        "_prioritized_context": "",
        "_lead_recipe": None,
        "_contrarian_recipe": None,
        "_verified_recipe": None,
        "_accumulated_cost": 0.0,
    }

    # Run sub-agents sequentially: Prioritizer → (Lead || Contrarian) → Verifier
    # Fan-out is conceptual here; we run lead + contrarian concurrently via asyncio
    import asyncio

    swarm_state = {**swarm_state, **(await _prioritizer(swarm_state))}

    lead_task = asyncio.create_task(_lead_researcher(swarm_state))
    contrarian_task = asyncio.create_task(_contrarian(swarm_state))
    lead_result, contrarian_result = await asyncio.gather(lead_task, contrarian_task)
    swarm_state = {**swarm_state, **lead_result, **contrarian_result}

    swarm_state = {**swarm_state, **(await _verifier(swarm_state))}

    recipe = swarm_state.get("_verified_recipe")
    run_cost += swarm_state.get("_accumulated_cost", 0.0)

    escalate = state.get("researcher_escalated", False)

    if recipe is None:
        # The verifier failed to produce a usable recipe; surface it so the
        # pipeline routes to the judge (or escalation) instead of KeyError-ing.
        return {
            "status": "research_failed",
            "errors": state.get("errors", [])
            + [f"Researcher swarm could not verify an ExploitRecipe for {cve_package.cve_id}"],
            "researcher_attempts": researcher_attempts,
            "researcher_escalated": escalate,
            "total_cost_usd": run_cost,
        }

    has_complete_chain = len(recipe.primitives_graph.complete_chains) > 0

    result: dict[str, Any] = {
        "exploit_recipe": recipe,
        "status": "researched",
        "researcher_attempts": researcher_attempts,
        # Persist the escalation flag (LangGraph drops state keys a node doesn't return).
        "researcher_escalated": escalate,
        "total_cost_usd": run_cost,
    }

    if not has_complete_chain and not escalate:
        if researcher_attempts >= settings.researcher_escalation_threshold:
            result["researcher_needs_escalation"] = True
        else:
            result["researcher_needs_escalation"] = False
    else:
        result["researcher_needs_escalation"] = False

    return result
