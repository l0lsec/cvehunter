"""Tests for the Judge agent."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from cvehunter.agents.judge import run_judge
from cvehunter.schemas import JudgementReport


class TestRunJudgeSuccess:
    async def test_all_artifacts_present(
        self,
        sample_cve_package,
        sample_exploit_recipe,
        sample_environment_spec,
        sample_exploit_result_success,
        sample_judgement_report,
    ):
        mock_llm = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=sample_judgement_report)
        mock_llm.with_structured_output = MagicMock(return_value=mock_structured)

        with patch("cvehunter.agents.judge.get_model", return_value=mock_llm):
            state = {
                "cve_id": "CVE-2021-44228",
                "cve_package": sample_cve_package,
                "exploit_recipe": sample_exploit_recipe,
                "environment": sample_environment_spec,
                "exploit_result": sample_exploit_result_success,
                "total_cost_usd": 1.0,
            }
            result = await run_judge(state)

        assert result["status"] == "judged"
        report = result["judgement"]
        assert isinstance(report, JudgementReport)
        assert report.cve_id == "CVE-2021-44228"
        assert report.exploitability_score >= 0


class TestRunJudgeMissingAllArtifacts:
    async def test_partial_report(self):
        state = {
            "cve_id": "CVE-2021-44228",
            "cve_package": None,
            "exploit_recipe": None,
            "environment": None,
            "exploit_result": None,
            "total_cost_usd": 0.0,
        }
        result = await run_judge(state)

        assert result["status"] == "judged_partial"
        report = result["judgement"]
        assert report.exploitability_score == 0.0
        for name in ("cve_package", "exploit_recipe", "environment", "exploit_result"):
            assert name in report.summary


class TestRunJudgeMissingSomeArtifacts:
    async def test_partial_with_some_data(self, sample_cve_package):
        state = {
            "cve_id": "CVE-2021-44228",
            "cve_package": sample_cve_package,
            "exploit_recipe": None,
            "environment": None,
            "exploit_result": None,
            "total_cost_usd": 0.5,
        }
        result = await run_judge(state)

        assert result["status"] == "judged_partial"
        report = result["judgement"]
        assert "exploit_recipe" in report.summary
        assert "cve_package" not in report.summary
