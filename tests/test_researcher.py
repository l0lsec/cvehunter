"""Tests for the Researcher agent."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cvehunter.agents.researcher import run_researcher, should_escalate_researcher
from cvehunter.schemas import CVEPackage, ExploitRecipe, PrimitivesGraph


@pytest.fixture
def sample_cve_package() -> CVEPackage:
    return CVEPackage(
        cve_id="CVE-2021-44228",
        description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        cvss_score=10.0,
        cwe_id="CWE-917",
        affected_software="Apache Log4j",
        affected_versions=["2.0-beta9", "2.14.1"],
        language="java",
        framework="Log4j",
        patch_diff="--- a/log4j-core/src/main/java/...\n+++ b/log4j-core/src/main/java/...",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )


def test_cve_package_schema(sample_cve_package: CVEPackage):
    """Test that CVEPackage validates correctly."""
    assert sample_cve_package.cve_id == "CVE-2021-44228"
    assert sample_cve_package.cvss_score == 10.0
    assert sample_cve_package.language == "java"


def _recipe_with_chains(chains: list[list[str]] | None = None) -> ExploitRecipe:
    return ExploitRecipe(
        cve_id="CVE-2021-44228",
        vulnerability_type="rce",
        attack_vector="network",
        primitives_graph=PrimitivesGraph(
            complete_chains=chains if chains is not None else [["a", "b"]],
        ),
        exploitation_steps=["step1"],
    )


class TestRunResearcherSuccess:
    async def test_produces_recipe_with_chain(self, sample_cve_package):
        recipe = _recipe_with_chains([["jndi", "ldap", "rce"]])

        mock_llm = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=recipe)
        mock_llm.with_structured_output = MagicMock(return_value=mock_structured)

        with (
            patch("cvehunter.agents.researcher.get_model", return_value=mock_llm),
            patch("cvehunter.agents.researcher.get_tier_for_agent", return_value="smart"),
            patch("cvehunter.agents.researcher.check_cost_limits", return_value=None),
            patch("cvehunter.agents.researcher.extract_cost", return_value=0.05),
        ):
            state = {"cve_package": sample_cve_package, "total_cost_usd": 0.0}
            result = await run_researcher(state)

        assert result["status"] == "researched"
        assert isinstance(result["exploit_recipe"], ExploitRecipe)
        assert len(result["exploit_recipe"].primitives_graph.complete_chains) > 0
        assert result["researcher_needs_escalation"] is False


class TestRunResearcherNoChainBelowThreshold:
    async def test_does_not_escalate(self, sample_cve_package):
        recipe = _recipe_with_chains([])

        mock_llm = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=recipe)
        mock_llm.with_structured_output = MagicMock(return_value=mock_structured)

        with (
            patch("cvehunter.agents.researcher.get_model", return_value=mock_llm),
            patch("cvehunter.agents.researcher.get_tier_for_agent", return_value="smart"),
            patch("cvehunter.agents.researcher.check_cost_limits", return_value=None),
            patch("cvehunter.agents.researcher.extract_cost", return_value=0.0),
        ):
            state = {
                "cve_package": sample_cve_package,
                "total_cost_usd": 0.0,
                "researcher_attempts": 0,
            }
            result = await run_researcher(state)

        assert result["researcher_needs_escalation"] is False
        assert result["researcher_attempts"] == 1


class TestRunResearcherEscalationTriggered:
    async def test_escalation_at_threshold(self, sample_cve_package):
        recipe = _recipe_with_chains([])

        mock_llm = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=recipe)
        mock_llm.with_structured_output = MagicMock(return_value=mock_structured)

        with (
            patch("cvehunter.agents.researcher.get_model", return_value=mock_llm),
            patch("cvehunter.agents.researcher.get_tier_for_agent", return_value="smart"),
            patch("cvehunter.agents.researcher.check_cost_limits", return_value=None),
            patch("cvehunter.agents.researcher.extract_cost", return_value=0.0),
            patch("cvehunter.agents.researcher.settings") as mock_settings,
        ):
            mock_settings.researcher_escalation_threshold = 3
            state = {
                "cve_package": sample_cve_package,
                "total_cost_usd": 0.0,
                "researcher_attempts": 2,  # will become 3 => threshold
            }
            result = await run_researcher(state)

        assert result["researcher_needs_escalation"] is True


class TestRunResearcherCostLimit:
    async def test_cost_limit_stops_early(self, sample_cve_package):
        with patch(
            "cvehunter.agents.researcher.check_cost_limits",
            return_value="Per-CVE cost limit exceeded",
        ):
            state = {"cve_package": sample_cve_package, "total_cost_usd": 100.0}
            result = await run_researcher(state)

        assert result["status"] == "cost_limit_exceeded"
        assert any("cost" in e.lower() for e in result["errors"])


class TestShouldEscalateResearcher:
    def test_returns_escalate(self):
        state = {
            "researcher_needs_escalation": True,
            "researcher_escalated": False,
            "exploit_recipe": _recipe_with_chains([]),
        }
        assert should_escalate_researcher(state) == "escalate"

    def test_returns_retry_no_chains(self):
        state = {
            "researcher_needs_escalation": False,
            "exploit_recipe": _recipe_with_chains([]),
        }
        assert should_escalate_researcher(state) == "retry"

    def test_returns_continue_with_chains(self):
        state = {
            "researcher_needs_escalation": False,
            "exploit_recipe": _recipe_with_chains([["a", "b"]]),
        }
        assert should_escalate_researcher(state) == "continue"

    def test_returns_continue_when_no_recipe(self):
        state = {"researcher_needs_escalation": False, "exploit_recipe": None}
        assert should_escalate_researcher(state) == "continue"
