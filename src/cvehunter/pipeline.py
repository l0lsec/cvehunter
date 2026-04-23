"""Main LangGraph pipeline — orchestrates the 5-agent workflow.

Flow:
    CVE ID → Collector → Researcher → (escalate?) → Builder → Exploiter → (retry?) → Judge
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from moak.agents.builder import run_builder
from moak.agents.collector import run_collector
from moak.agents.exploiter import run_exploiter, should_retry_exploit
from moak.agents.judge import run_judge
from moak.agents.researcher import run_researcher, should_escalate_researcher
from moak.schemas import PipelineState


def _state_to_dict(state: PipelineState) -> dict[str, Any]:
    return state.model_dump()


def build_pipeline() -> StateGraph:
    """Construct the LangGraph workflow for the MOAK-Lite pipeline."""

    workflow = StateGraph(dict)

    # Add nodes
    workflow.add_node("collector", run_collector)
    workflow.add_node("researcher", run_researcher)
    workflow.add_node("researcher_escalated", _run_researcher_escalated)
    workflow.add_node("builder", run_builder)
    workflow.add_node("exploiter", run_exploiter)
    workflow.add_node("judge", run_judge)

    # Entry point
    workflow.set_entry_point("collector")

    # Collector → Researcher
    workflow.add_edge("collector", "researcher")

    # Researcher → conditional: escalate or continue to Builder
    workflow.add_conditional_edges(
        "researcher",
        should_escalate_researcher,
        {
            "escalate": "researcher_escalated",
            "continue": "builder",
        },
    )

    # Escalated Researcher → Builder
    workflow.add_edge("researcher_escalated", "builder")

    # Builder → Exploiter
    workflow.add_edge("builder", "exploiter")

    # Exploiter → conditional: retry, validate (judge), or give up
    workflow.add_conditional_edges(
        "exploiter",
        should_retry_exploit,
        {
            "retry": "exploiter",
            "validate": "judge",
            "give_up": "judge",
        },
    )

    # Judge → END
    workflow.add_edge("judge", END)

    return workflow


async def _run_researcher_escalated(state: dict[str, Any]) -> dict[str, Any]:
    """Re-run the Researcher with the HEAVY tier model."""
    state["researcher_escalated"] = True
    return await run_researcher(state)


async def run_pipeline(cve_id: str) -> dict[str, Any]:
    """Execute the full pipeline for a given CVE ID.

    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2024-12345')

    Returns:
        Final pipeline state including all agent outputs and the judgement report.
    """
    workflow = build_pipeline()
    app = workflow.compile()

    initial_state = {
        "cve_id": cve_id,
        "cve_package": None,
        "exploit_recipe": None,
        "environment": None,
        "exploit_result": None,
        "judgement": None,
        "total_cost_usd": 0.0,
        "errors": [],
        "status": "started",
    }

    final_state = await app.ainvoke(initial_state)
    return final_state
