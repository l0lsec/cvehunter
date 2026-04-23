"""Integration tests for the LangGraph pipeline."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cvehunter.pipeline import (
    _should_continue_after_builder,
    _should_continue_after_collector,
    build_pipeline,
    run_pipeline,
)
from cvehunter.schemas import (
    CVEPackage,
    ExploitRecipe,
    ExploitResult,
    JudgementReport,
    PrimitivesGraph,
)


def _mock_cve_package():
    return CVEPackage(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        affected_software="Apache Log4j",
        language="java",
    )


def _mock_recipe():
    return ExploitRecipe(
        cve_id="CVE-2021-44228",
        vulnerability_type="rce",
        attack_vector="network",
        primitives_graph=PrimitivesGraph(
            complete_chains=[["a", "b"]],
        ),
        exploitation_steps=["step1"],
    )


def _mock_exploit_result(success: bool = True):
    return ExploitResult(
        cve_id="CVE-2021-44228",
        success=success,
        flag_captured=success,
        total_attempts=1,
    )


def _mock_env():
    mock = MagicMock()
    mock.services = ["web"]
    mock.network_name = "test_default"
    mock.credentials = {}
    mock.health_check_passed = True
    mock.compose_yaml = "version: '3'"
    mock.flag_value = "CVEHUNTER{test}"
    mock.patched_network_name = ""
    return mock


def _collector_ok(state):
    return {
        "cve_package": _mock_cve_package(),
        "status": "collected",
        "total_cost_usd": 0.01,
    }


def _researcher_ok(state):
    return {
        "exploit_recipe": _mock_recipe(),
        "status": "researched",
        "researcher_attempts": 1,
        "researcher_needs_escalation": False,
        "total_cost_usd": state.get("total_cost_usd", 0.0) + 0.05,
    }


def _builder_ok(state):
    return {
        "environment": _mock_env(),
        "status": "environment_ready",
        "total_cost_usd": state.get("total_cost_usd", 0.0) + 0.02,
    }


def _exploiter_ok(state):
    return {
        "exploit_result": _mock_exploit_result(success=True),
        "status": "exploited",
        "total_cost_usd": state.get("total_cost_usd", 0.0) + 0.1,
    }


def _judge_ok(state):
    return {
        "judgement": JudgementReport(
            cve_id=state.get("cve_id", "CVE-TEST"),
            exploitability_score=8.0,
            summary="All good",
            full_analysis="Full analysis text",
        ),
        "status": "judged",
        "total_cost_usd": state.get("total_cost_usd", 0.0) + 0.005,
    }


class TestFullPipelineSuccess:
    async def test_end_to_end(self):
        with (
            patch("cvehunter.pipeline.run_collector", new_callable=AsyncMock, side_effect=_collector_ok),
            patch("cvehunter.pipeline.run_researcher", new_callable=AsyncMock, side_effect=_researcher_ok),
            patch("cvehunter.pipeline.run_builder", new_callable=AsyncMock, side_effect=_builder_ok),
            patch("cvehunter.pipeline.run_exploiter", new_callable=AsyncMock, side_effect=_exploiter_ok),
            patch("cvehunter.pipeline.run_judge", new_callable=AsyncMock, side_effect=_judge_ok),
            patch("cvehunter.pipeline.cleanup_environment", new_callable=AsyncMock),
            patch("cvehunter.pipeline.save_artifacts"),
            patch("cvehunter.pipeline.load_monthly_spend", return_value=0.0),
            patch("cvehunter.pipeline.save_monthly_spend"),
        ):
            result = await run_pipeline("CVE-2021-44228")

        assert result["status"] == "judged"
        assert result.get("judgement") is not None
        assert result["total_cost_usd"] > 0


class TestPipelineCollectorFailure:
    async def test_skips_to_judge(self):
        async def _collector_fail(state):
            return {"cve_package": None, "status": "collector_error", "total_cost_usd": 0.0}

        with (
            patch("cvehunter.pipeline.run_collector", new_callable=AsyncMock, side_effect=_collector_fail),
            patch("cvehunter.pipeline.run_judge", new_callable=AsyncMock, side_effect=_judge_ok),
            patch("cvehunter.pipeline.cleanup_environment", new_callable=AsyncMock),
            patch("cvehunter.pipeline.save_artifacts"),
            patch("cvehunter.pipeline.load_monthly_spend", return_value=0.0),
            patch("cvehunter.pipeline.save_monthly_spend"),
        ):
            result = await run_pipeline("CVE-2021-44228")

        assert result.get("judgement") is not None


class TestPipelineBuilderFailure:
    async def test_skips_to_judge(self):
        async def _builder_fail(state):
            return {
                "environment": None,
                "status": "environment_failed",
                "total_cost_usd": state.get("total_cost_usd", 0.0),
            }

        with (
            patch("cvehunter.pipeline.run_collector", new_callable=AsyncMock, side_effect=_collector_ok),
            patch("cvehunter.pipeline.run_researcher", new_callable=AsyncMock, side_effect=_researcher_ok),
            patch("cvehunter.pipeline.run_builder", new_callable=AsyncMock, side_effect=_builder_fail),
            patch("cvehunter.pipeline.run_judge", new_callable=AsyncMock, side_effect=_judge_ok),
            patch("cvehunter.pipeline.cleanup_environment", new_callable=AsyncMock),
            patch("cvehunter.pipeline.save_artifacts"),
            patch("cvehunter.pipeline.load_monthly_spend", return_value=0.0),
            patch("cvehunter.pipeline.save_monthly_spend"),
        ):
            result = await run_pipeline("CVE-2021-44228")

        assert result.get("judgement") is not None


class TestPipelineExploiterRetry:
    async def test_exploiter_retries_then_succeeds(self):
        call_count = 0

        async def _exploiter_retry(state):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "exploit_result": _mock_exploit_result(success=False),
                    "status": "exploit_attempt_failed",
                    "total_cost_usd": state.get("total_cost_usd", 0.0) + 0.05,
                }
            return _exploiter_ok(state)

        with (
            patch("cvehunter.pipeline.run_collector", new_callable=AsyncMock, side_effect=_collector_ok),
            patch("cvehunter.pipeline.run_researcher", new_callable=AsyncMock, side_effect=_researcher_ok),
            patch("cvehunter.pipeline.run_builder", new_callable=AsyncMock, side_effect=_builder_ok),
            patch("cvehunter.pipeline.run_exploiter", new_callable=AsyncMock, side_effect=_exploiter_retry),
            patch("cvehunter.pipeline.run_judge", new_callable=AsyncMock, side_effect=_judge_ok),
            patch("cvehunter.pipeline.cleanup_environment", new_callable=AsyncMock),
            patch("cvehunter.pipeline.save_artifacts"),
            patch("cvehunter.pipeline.load_monthly_spend", return_value=0.0),
            patch("cvehunter.pipeline.save_monthly_spend"),
        ):
            result = await run_pipeline("CVE-2021-44228")

        assert call_count >= 2
        assert result.get("judgement") is not None


class TestPipelineResearcherEscalation:
    async def test_escalation_path(self):
        call_count = 0

        async def _researcher_escalate(state):
            nonlocal call_count
            call_count += 1
            if not state.get("researcher_escalated"):
                return {
                    "exploit_recipe": _mock_recipe(),
                    "status": "researched",
                    "researcher_attempts": 3,
                    "researcher_needs_escalation": True,
                    "total_cost_usd": state.get("total_cost_usd", 0.0),
                }
            return _researcher_ok(state)

        with (
            patch("cvehunter.pipeline.run_collector", new_callable=AsyncMock, side_effect=_collector_ok),
            patch("cvehunter.pipeline.run_researcher", new_callable=AsyncMock, side_effect=_researcher_escalate),
            patch("cvehunter.pipeline.run_builder", new_callable=AsyncMock, side_effect=_builder_ok),
            patch("cvehunter.pipeline.run_exploiter", new_callable=AsyncMock, side_effect=_exploiter_ok),
            patch("cvehunter.pipeline.run_judge", new_callable=AsyncMock, side_effect=_judge_ok),
            patch("cvehunter.pipeline.cleanup_environment", new_callable=AsyncMock),
            patch("cvehunter.pipeline.save_artifacts"),
            patch("cvehunter.pipeline.load_monthly_spend", return_value=0.0),
            patch("cvehunter.pipeline.save_monthly_spend"),
        ):
            result = await run_pipeline("CVE-2021-44228")

        assert result.get("judgement") is not None


class TestPipelineExceptionCleanup:
    async def test_cleanup_on_exception(self):
        cleanup_mock = AsyncMock()

        async def _collector_raise(state):
            raise RuntimeError("NVD API exploded")

        with (
            patch("cvehunter.pipeline.run_collector", new_callable=AsyncMock, side_effect=_collector_raise),
            patch("cvehunter.pipeline.cleanup_environment", cleanup_mock),
            patch("cvehunter.pipeline.save_artifacts"),
            patch("cvehunter.pipeline.load_monthly_spend", return_value=0.0),
            patch("cvehunter.pipeline.save_monthly_spend"),
        ):
            with pytest.raises(RuntimeError, match="NVD API exploded"):
                await run_pipeline("CVE-2021-44228")

        assert cleanup_mock.await_count >= 1


class TestConditionalEdges:
    def test_collector_continue(self):
        assert _should_continue_after_collector({"cve_package": "pkg"}) == "continue"

    def test_collector_skip_none(self):
        assert _should_continue_after_collector({"cve_package": None}) == "skip_to_judge"

    def test_collector_skip_cost(self):
        assert _should_continue_after_collector(
            {"cve_package": "pkg", "status": "cost_limit_exceeded"}
        ) == "skip_to_judge"

    def test_builder_continue(self):
        assert _should_continue_after_builder({"status": "environment_ready"}) == "continue"

    def test_builder_skip_failed(self):
        assert _should_continue_after_builder({"status": "environment_failed"}) == "skip_to_judge"

    def test_builder_skip_cost(self):
        assert _should_continue_after_builder({"status": "cost_limit_exceeded"}) == "skip_to_judge"
