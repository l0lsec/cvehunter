"""Collector Agent — gathers CVE data, patch diffs, and metadata.

LLM Tier: CHEAP (DeepSeek V3.2)
Input: CVE ID string
Output: CVEPackage
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

logger = structlog.get_logger(__name__)

from cvehunter.config import ModelTier
from cvehunter.llm_router import extract_cost, get_model
from cvehunter.schemas import CVEPackage, PipelineState
from cvehunter.tools.advisory import scrape_advisory
from cvehunter.tools.git_ops import git_clone_and_diff
from cvehunter.tools.github import get_commit_diff, search_github_commits
from cvehunter.tools.nvd import fetch_cve
from cvehunter.tools.osv import fetch_osv
from cvehunter.tools.url_validation import ALLOWED_DOMAINS, validate_url

COLLECTOR_SYSTEM_PROMPT = """\
You are a vulnerability data collector. Given a CVE ID, gather all relevant information
about the vulnerability using the tools provided.

Your goal is to produce a structured CVEPackage with:
1. The CVE description and metadata (CVSS score, CWE, affected software)
2. The patch diff showing what code was changed to fix the vulnerability
3. The vulnerable and patched code snippets
4. Repository and commit information

IMPORTANT GUARDRAILS:
- Only use the provided tools to gather information
- Do NOT access exploit-db, packetstorm, or any PoC repositories
- Do NOT include any exploitation code or proof-of-concept details
- Focus only on the vulnerability description and the patch that fixed it

Steps:
1. Query NVD for the CVE details
2. Query OSV.dev for additional references and commit links
3. If NVD or OSV references link to a vendor advisory, use scrape_advisory to fetch
   additional details (patch links, affected versions, remediation info)
4. Search GitHub for the fix commit if no commit hash was found yet
5. Once you have a repo and commit SHA (from OSV, NVD references, or GitHub search),
   call get_commit_diff to fetch the actual patch diff — this is critical for
   downstream analysis. If get_commit_diff fails (e.g., non-GitHub repo), fall back
   to git_clone_and_diff.
6. Structure all findings into the output format
"""

collector_tools = [
    fetch_cve,
    fetch_osv,
    search_github_commits,
    get_commit_diff,
    scrape_advisory,
    git_clone_and_diff,
]


def _find_blocked_url(args: dict[str, Any]) -> str | None:
    """Return the first URL in tool args that fails the domain allowlist, or None."""
    for value in args.values():
        if isinstance(value, str) and value.startswith("http") and not validate_url(value):
            return value
    return None


async def run_collector(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the Collector agent node."""
    cve_id: str = state["cve_id"]
    run_cost = state.get("total_cost_usd", 0.0)
    tier = ModelTier.CHEAP
    llm = get_model("collector")
    llm_with_tools = llm.bind_tools(collector_tools)

    messages = [
        SystemMessage(content=COLLECTOR_SYSTEM_PROMPT),
        HumanMessage(content=f"Collect all vulnerability data for: {cve_id}"),
    ]

    # Agent loop: let the LLM call tools iteratively
    max_iterations = 10
    for _ in range(max_iterations):
        response = await llm_with_tools.ainvoke(messages)
        run_cost += extract_cost(response, tier)
        messages.append(response)

        if not response.tool_calls:
            break

        for tool_call in response.tool_calls:
            tool_fn = {t.name: t for t in collector_tools}.get(tool_call["name"])
            if tool_fn is None:
                continue

            blocked_url = _find_blocked_url(tool_call["args"])
            if blocked_url:
                messages.append(
                    ToolMessage(
                        content=f"URL blocked by domain allowlist: {blocked_url}",
                        tool_call_id=tool_call["id"],
                    )
                )
                continue

            result = await tool_fn.ainvoke(tool_call["args"])
            if isinstance(result, dict) and result.get("success") is False:
                logger.warning(
                    "tool_error",
                    tool=tool_call["name"],
                    cve_id=cve_id,
                    error=result.get("error", "unknown"),
                )
            messages.append(
                ToolMessage(content=str(result), tool_call_id=tool_call["id"])
            )

    # Build a clean extraction context from tool outputs instead of reusing the
    # tool-loop history. Passing a multi-turn history with prior tool_calls to a
    # structured-output call (bound to only CVEPackage) causes parsing failures:
    # DeepSeek may mirror prior tool names in its response, and LangChain's
    # PydanticToolsParser rejects any tool_call whose name != 'CVEPackage'.
    tool_outputs: list[str] = []
    for m in messages:
        if isinstance(m, ToolMessage):
            tool_outputs.append(f"[tool_result]\n{m.content}")
    collected_context = "\n\n---\n\n".join(tool_outputs) or "(no tool data collected)"

    extraction_messages = [
        SystemMessage(content=COLLECTOR_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"Based on the data collected below, extract a structured CVEPackage "
                f"for {cve_id}. Fill in every field you can, leaving optional fields "
                f"null only when the data is genuinely unavailable.\n\n"
                f"COLLECTED DATA:\n{collected_context}"
            )
        ),
    ]

    # DeepSeek's Chat Completions endpoint does not currently support the
    # default json_schema response_format, so we pin to function_calling.
    base_llm = get_model("collector")
    structured_llm = base_llm.with_structured_output(CVEPackage, method="function_calling")
    cve_package = await structured_llm.ainvoke(extraction_messages)
    run_cost += extract_cost(cve_package, tier) if hasattr(cve_package, "usage_metadata") else 0.0

    return {
        "cve_package": cve_package,
        "status": "collected",
        "total_cost_usd": run_cost,
    }
