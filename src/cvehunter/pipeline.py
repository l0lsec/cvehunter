"""Main LangGraph pipeline — orchestrates the 5-agent workflow.

Flow:
    CVE ID → Collector → (ok?) → Researcher → (escalate?) → Builder → (ok?)
    → Exploiter → (retry?) → Judge → (HITL?) → Cleanup → END

    On failure at Collector or Builder, skips directly to Judge (which produces
    a partial "could not assess" report).

    Supports checkpointing for resume-on-failure and human-in-the-loop gates.
"""

from __future__ import annotations

from typing import Any

import structlog
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, StateGraph
from langgraph.types import interrupt

from cvehunter.agents.builder import run_builder
from cvehunter.agents.collector import run_collector
from cvehunter.agents.exploiter import run_exploiter, should_retry_exploit
from cvehunter.agents.judge import run_judge
from cvehunter.agents.researcher import run_researcher, should_escalate_researcher
from cvehunter.agents.researcher_swarm import run_researcher_swarm
from cvehunter.artifacts import save_artifacts
from cvehunter.config import settings
from cvehunter.cost_tracker import load_monthly_spend, save_monthly_spend
from cvehunter.schemas import GraphState, HITLLevel
from cvehunter.tools.docker_ops import cleanup_environment

logger = structlog.get_logger(__name__)


# ── Conditional edge functions ──


def _should_continue_after_collector(state: dict[str, Any]) -> str:
    if state.get("cve_package") is None or state.get("status") == "cost_limit_exceeded":
        return "skip_to_judge"
    return "continue"


def _should_continue_after_builder(state: dict[str, Any]) -> str:
    if state.get("status") in ("environment_failed", "cost_limit_exceeded"):
        return "skip_to_judge"
    return "continue"


# ── Helper nodes ──


def _get_researcher_fn():
    """Return the swarm runner if enabled, otherwise the simple researcher."""
    if settings.researcher_swarm_enabled:
        return run_researcher_swarm
    return run_researcher


async def _run_researcher_escalated(state: dict[str, Any]) -> dict[str, Any]:
    """Re-run the Researcher with the HEAVY tier model."""
    logger.info("researcher_escalated", cve_id=state.get("cve_id"))
    state["researcher_escalated"] = True
    return await run_researcher(state)


async def _hitl_gate_node(state: dict[str, Any]) -> dict[str, Any]:
    """Pause execution and wait for human approval when HITL level is medium/high."""
    judgement = state.get("judgement")
    hitl_level = judgement.hitl_level if judgement else "none"
    cve_id = state.get("cve_id", "UNKNOWN")

    logger.info("hitl_gate_paused", cve_id=cve_id, hitl_level=hitl_level)

    human_response = interrupt({
        "reason": "Human review required before finalizing",
        "cve_id": cve_id,
        "hitl_level": hitl_level,
        "exploitability_score": judgement.exploitability_score if judgement else None,
        "summary": judgement.summary if judgement else "",
    })

    action = human_response.get("action", "approve") if isinstance(human_response, dict) else "approve"
    notes = human_response.get("notes", "") if isinstance(human_response, dict) else ""

    if action == "reject":
        logger.info("hitl_rejected", cve_id=cve_id, notes=notes)
        return {
            "status": "rejected_by_human",
            "errors": state.get("errors", []) + [f"Rejected by human reviewer: {notes}"],
        }

    logger.info("hitl_approved", cve_id=cve_id, notes=notes)
    return {"status": "approved_by_human"}


def _should_pause_for_hitl(state: dict[str, Any]) -> str:
    """Route to HITL gate if the Judge flagged medium/high human intervention."""
    judgement = state.get("judgement")
    if judgement and judgement.hitl_level in (HITLLevel.MEDIUM, HITLLevel.HIGH):
        return "hitl_gate"
    return "cleanup"


async def _cleanup_node(state: dict[str, Any]) -> dict[str, Any]:
    """Tear down Docker environments created for this CVE run."""
    cve_id = state.get("cve_id", "")
    project = f"cvehunter-{cve_id.lower().replace('-', '_')}"
    await cleanup_environment(project)
    await cleanup_environment(f"{project}-patched")
    return state


# ── Graph construction ──


def build_pipeline() -> StateGraph:
    """Construct the LangGraph workflow for the CVEHunter pipeline."""

    workflow = StateGraph(GraphState)

    researcher_fn = _get_researcher_fn()

    workflow.add_node("collector", run_collector)
    workflow.add_node("researcher", researcher_fn)
    workflow.add_node("researcher_escalated", _run_researcher_escalated)
    workflow.add_node("builder", run_builder)
    workflow.add_node("exploiter", run_exploiter)
    workflow.add_node("judge", run_judge)
    workflow.add_node("hitl_gate", _hitl_gate_node)
    workflow.add_node("cleanup", _cleanup_node)

    workflow.set_entry_point("collector")

    # Collector → check if data was collected
    workflow.add_conditional_edges(
        "collector",
        _should_continue_after_collector,
        {
            "skip_to_judge": "judge",
            "continue": "researcher",
        },
    )

    # Researcher → conditional: retry, escalate, or continue to Builder
    workflow.add_conditional_edges(
        "researcher",
        should_escalate_researcher,
        {
            "retry": "researcher",
            "escalate": "researcher_escalated",
            "continue": "builder",
        },
    )

    workflow.add_edge("researcher_escalated", "builder")

    # Builder → check if environment is ready
    workflow.add_conditional_edges(
        "builder",
        _should_continue_after_builder,
        {
            "skip_to_judge": "judge",
            "continue": "exploiter",
        },
    )

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

    # Judge → HITL gate (if medium/high) or Cleanup
    workflow.add_conditional_edges(
        "judge",
        _should_pause_for_hitl,
        {
            "hitl_gate": "hitl_gate",
            "cleanup": "cleanup",
        },
    )

    workflow.add_edge("hitl_gate", "cleanup")
    workflow.add_edge("cleanup", END)

    return workflow


# ── Pipeline runner ──


def _checkpoint_db_path() -> str:
    settings.artifact_dir.mkdir(parents=True, exist_ok=True)
    return str(settings.artifact_dir / "checkpoints.db")


async def run_pipeline(cve_id: str) -> dict[str, Any]:
    """Execute the full pipeline for a given CVE ID.

    Uses SQLite-backed checkpointing so runs can be resumed after failure
    or paused at a human-in-the-loop gate.

    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2024-12345')

    Returns:
        Final pipeline state including all agent outputs and the judgement report.
    """
    workflow = build_pipeline()

    logger.info("pipeline_started", cve_id=cve_id)

    initial_state: dict[str, Any] = {
        "cve_id": cve_id,
        "cve_package": None,
        "exploit_recipe": None,
        "environment": None,
        "exploit_result": None,
        "judgement": None,
        "total_cost_usd": 0.0,
        "errors": [],
        "status": "started",
        "researcher_attempts": 0,
    }

    config = {"configurable": {"thread_id": cve_id}}
    final_state = initial_state

    async with AsyncSqliteSaver.from_conn_string(_checkpoint_db_path()) as checkpointer:
        app = workflow.compile(checkpointer=checkpointer)
        try:
            final_state = await app.ainvoke(initial_state, config=config)
            logger.info(
                "pipeline_completed",
                cve_id=cve_id,
                status=final_state.get("status"),
                cost_usd=final_state.get("total_cost_usd", 0.0),
            )
        except Exception:
            logger.exception("pipeline_failed", cve_id=cve_id)
            project = f"cvehunter-{cve_id.lower().replace('-', '_')}"
            await cleanup_environment(project)
            await cleanup_environment(f"{project}-patched")
            raise
        finally:
            save_artifacts(cve_id, final_state)
            run_cost = final_state.get("total_cost_usd", 0.0)
            if run_cost > 0:
                monthly = load_monthly_spend()
                save_monthly_spend(monthly + run_cost)

    return final_state


async def resume_pipeline(
    cve_id: str,
    *,
    human_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resume a previously paused or failed pipeline run from its last checkpoint.

    Args:
        cve_id: The CVE identifier whose run should be resumed.
        human_response: Optional dict passed as the interrupt response for HITL gates
                        (e.g., ``{"action": "approve", "notes": "Looks good"}``).

    Returns:
        Final pipeline state after resumption completes.
    """
    from langgraph.types import Command

    workflow = build_pipeline()
    config = {"configurable": {"thread_id": cve_id}}

    async with AsyncSqliteSaver.from_conn_string(_checkpoint_db_path()) as checkpointer:
        app = workflow.compile(checkpointer=checkpointer)

        snapshot = await app.aget_state(config)
        if snapshot is None or snapshot.values is None:
            raise ValueError(f"No checkpoint found for {cve_id}")

        logger.info(
            "pipeline_resuming",
            cve_id=cve_id,
            next_nodes=snapshot.next,
        )

        if human_response is not None:
            final_state = await app.ainvoke(
                Command(resume=human_response),
                config=config,
            )
        else:
            final_state = await app.ainvoke(None, config=config)

        logger.info(
            "pipeline_resumed_completed",
            cve_id=cve_id,
            status=final_state.get("status"),
        )

    save_artifacts(cve_id, final_state)
    return final_state
