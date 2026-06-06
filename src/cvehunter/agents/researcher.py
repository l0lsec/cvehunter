"""Researcher Agent — analyzes vulnerabilities and builds exploit chains.

LLM Tier: SMART (Claude Sonnet 4.6), escalates to HEAVY (Opus 4.8) on failure
Input: CVEPackage
Output: ExploitRecipe with PrimitivesGraph
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from cvehunter.config import settings
from cvehunter.cost_tracker import check_cost_limits
from cvehunter.llm_router import get_model, get_tier_for_agent, structured_call
from cvehunter.schemas import CVEPackage, ExploitRecipe

logger = structlog.get_logger(__name__)

RESEARCHER_SYSTEM_PROMPT = """\
You are an expert vulnerability researcher. Given detailed CVE information including
the vulnerability description and patch diff, your task is to:

1. ANALYZE the vulnerability: identify the root cause, affected code paths, and
   exploitation primitives (e.g., buffer overflow, type confusion, use-after-free,
   SQL injection, path traversal, SSRF, etc.)

2. BUILD A PRIMITIVES GRAPH: identify all exploitation primitives and their
   dependencies. Each primitive should have:
   - A clear name and description
   - Confidence score (0.0-1.0) based on evidence
   - Prerequisites (other primitives needed first)

3. FIND COMPLETE CHAINS: identify one or more complete exploitation chains from
   the initial entry point to achieving code execution, data exfiltration, or
   other impact.

4. PRODUCE AN EXPLOIT RECIPE: step-by-step instructions for exploiting the
   vulnerability, including required conditions and estimated complexity.

Focus on the technical details from the patch diff. Identify what was vulnerable
in the old code and what the fix changed. Work backwards from the fix to
understand the exploitation path.

Do NOT generate actual exploit code — only the strategy and steps.
"""


async def run_researcher(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the Researcher agent node."""
    cost_error = check_cost_limits(state.get("total_cost_usd", 0.0))
    if cost_error:
        return {
            "errors": state.get("errors", []) + [cost_error],
            "status": "cost_limit_exceeded",
            "total_cost_usd": state.get("total_cost_usd", 0.0),
        }

    cve_package: CVEPackage = state["cve_package"]
    escalate = state.get("researcher_escalated", False)
    researcher_attempts = state.get("researcher_attempts", 0) + 1

    run_cost = state.get("total_cost_usd", 0.0)
    tier = get_tier_for_agent("researcher", escalate=escalate)
    llm = get_model("researcher", escalate=escalate)

    context = f"""## CVE: {cve_package.cve_id}

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

    messages = [
        SystemMessage(content=RESEARCHER_SYSTEM_PROMPT),
        HumanMessage(content=context),
    ]

    recipe, call_cost = await structured_call(llm, ExploitRecipe, messages, tier)
    run_cost += call_cost

    if recipe is None:
        return {
            "status": "research_failed",
            "errors": state.get("errors", [])
            + [f"Researcher could not produce an ExploitRecipe for {cve_package.cve_id}"],
            "researcher_attempts": researcher_attempts,
            "researcher_escalated": escalate,
            "total_cost_usd": run_cost,
        }

    has_complete_chain = len(recipe.primitives_graph.complete_chains) > 0

    result: dict[str, Any] = {
        "exploit_recipe": recipe,
        "status": "researched",
        "researcher_attempts": researcher_attempts,
        # Persist the escalation flag explicitly: LangGraph only keeps state keys
        # that a node returns, so without this the HEAVY-tier escalation set by
        # ``_run_researcher_escalated`` would be lost on the next pass.
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


def should_escalate_researcher(state: dict[str, Any]) -> str:
    """LangGraph conditional edge: retry, escalate to Opus, skip to judge, or continue.

    The builder requires an ``exploit_recipe``; a cost-limit abort or a hard
    research/verification failure leaves none, so those route straight to the
    judge (which emits a partial "could not assess" report) instead of crashing
    the builder with missing state.
    """
    if state.get("status") == "cost_limit_exceeded":
        return "skip_to_judge"
    if state.get("exploit_recipe") is None:
        return "skip_to_judge"
    if state.get("researcher_needs_escalation") and not state.get("researcher_escalated"):
        return "escalate"
    recipe = state["exploit_recipe"]
    if len(recipe.primitives_graph.complete_chains) == 0:
        return "retry"
    return "continue"
