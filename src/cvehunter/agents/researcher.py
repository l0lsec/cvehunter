"""Researcher Agent — analyzes vulnerabilities and builds exploit chains.

LLM Tier: SMART (Claude Sonnet 4), escalates to HEAVY (Opus 4.6) on failure
Input: CVEPackage
Output: ExploitRecipe with PrimitivesGraph
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from moak.config import settings
from moak.llm_router import get_model
from moak.schemas import CVEPackage, ExploitRecipe

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
    cve_package: CVEPackage = state["cve_package"]
    escalate = state.get("researcher_escalated", False)

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

    structured_llm = llm.with_structured_output(ExploitRecipe)
    recipe = await structured_llm.ainvoke(messages)

    has_complete_chain = len(recipe.primitives_graph.complete_chains) > 0

    result: dict[str, Any] = {
        "exploit_recipe": recipe,
        "status": "researched",
    }

    # If no complete chain found and we haven't escalated yet, flag for escalation
    if not has_complete_chain and not escalate:
        result["researcher_needs_escalation"] = True
    else:
        result["researcher_needs_escalation"] = False

    return result


def should_escalate_researcher(state: dict[str, Any]) -> str:
    """LangGraph conditional edge: decide whether to escalate the Researcher to Opus."""
    if state.get("researcher_needs_escalation") and not state.get("researcher_escalated"):
        return "escalate"
    return "continue"
