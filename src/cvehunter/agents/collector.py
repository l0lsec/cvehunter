"""Collector Agent — gathers CVE data, patch diffs, and metadata.

LLM Tier: CHEAP (DeepSeek V3.2)
Input: CVE ID string
Output: CVEPackage
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool

from moak.llm_router import get_model
from moak.schemas import CVEPackage, PipelineState
from moak.tools.github import search_github_commits
from moak.tools.nvd import fetch_cve
from moak.tools.osv import fetch_osv

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
3. If a patch commit is found, extract the git diff
4. If no commit is found, search GitHub for the fix commit
5. Structure all findings into the output format
"""

ALLOWED_DOMAINS = {
    "nvd.nist.gov",
    "osv.dev",
    "github.com",
    "gitlab.com",
    "security-tracker.debian.org",
    "access.redhat.com",
    "ubuntu.com/security",
    "advisories.apache.org",
}


collector_tools = [fetch_cve, fetch_osv, search_github_commits]


async def run_collector(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the Collector agent node."""
    cve_id: str = state["cve_id"]
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
        messages.append(response)

        if not response.tool_calls:
            break

        for tool_call in response.tool_calls:
            tool_fn = {t.name: t for t in collector_tools}.get(tool_call["name"])
            if tool_fn is None:
                continue
            result = await tool_fn.ainvoke(tool_call["args"])
            from langchain_core.messages import ToolMessage

            messages.append(
                ToolMessage(content=str(result), tool_call_id=tool_call["id"])
            )

    # Parse the final response into a CVEPackage
    # The LLM should produce structured output; we parse it with Pydantic
    structured_llm = get_model("collector").with_structured_output(CVEPackage)
    cve_package = await structured_llm.ainvoke(messages)

    return {
        "cve_package": cve_package,
        "status": "collected",
    }
