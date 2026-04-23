"""Tests for the Collector agent and its tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cvehunter.agents.collector import _find_blocked_url, run_collector
from cvehunter.schemas import CVEPackage


@pytest.fixture
def _cve_package_for_structured() -> CVEPackage:
    return CVEPackage(
        cve_id="CVE-2021-44228",
        description="Log4Shell",
        affected_software="Apache Log4j",
        language="java",
        affected_versions=["2.14.1"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )


def _mock_tool(name: str, return_value: dict | None = None) -> MagicMock:
    """Return a mock tool with .name and async .ainvoke."""
    t = MagicMock()
    t.name = name
    t.ainvoke = AsyncMock(return_value=return_value or {"data": name})
    return t


class TestRunCollectorSuccess:
    async def test_produces_cve_package(
        self, _cve_package_for_structured, mock_ai_message
    ):
        no_tools_msg = mock_ai_message(content="done")
        no_tools_msg.tool_calls = []

        mock_llm = MagicMock()
        mock_llm_with_tools = MagicMock()
        mock_llm_with_tools.ainvoke = AsyncMock(return_value=no_tools_msg)
        mock_llm.bind_tools = MagicMock(return_value=mock_llm_with_tools)

        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=_cve_package_for_structured)

        call_count = 0
        def _get_model_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_llm
            return MagicMock(with_structured_output=MagicMock(return_value=mock_structured))

        with (
            patch("cvehunter.agents.collector.get_model", side_effect=_get_model_side_effect),
            patch("cvehunter.agents.collector.extract_cost", return_value=0.01),
        ):
            state = {"cve_id": "CVE-2021-44228"}
            result = await run_collector(state)

        assert result["status"] == "collected"
        assert isinstance(result["cve_package"], CVEPackage)
        assert result["cve_package"].cve_id == "CVE-2021-44228"
        assert result["total_cost_usd"] >= 0

    async def test_iterates_tool_calls(
        self, _cve_package_for_structured, mock_ai_message
    ):
        tool_msg = mock_ai_message(content="calling tools")
        tool_msg.tool_calls = [
            {"id": "tc1", "name": "fetch_cve", "args": {"cve_id": "CVE-2021-44228"}},
        ]
        no_tools_msg = mock_ai_message(content="done")
        no_tools_msg.tool_calls = []

        mock_llm = MagicMock()
        mock_llm_with_tools = MagicMock()
        mock_llm_with_tools.ainvoke = AsyncMock(side_effect=[tool_msg, no_tools_msg])
        mock_llm.bind_tools = MagicMock(return_value=mock_llm_with_tools)

        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=_cve_package_for_structured)

        mock_fetch_cve = _mock_tool("fetch_cve", {"cve_id": "CVE-2021-44228"})

        call_count = 0
        def _get_model_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_llm
            return MagicMock(with_structured_output=MagicMock(return_value=mock_structured))

        with (
            patch("cvehunter.agents.collector.get_model", side_effect=_get_model_side_effect),
            patch("cvehunter.agents.collector.extract_cost", return_value=0.01),
            patch(
                "cvehunter.agents.collector.collector_tools",
                [mock_fetch_cve],
            ),
        ):
            result = await run_collector({"cve_id": "CVE-2021-44228"})

        mock_fetch_cve.ainvoke.assert_awaited_once()
        assert result["status"] == "collected"


class TestRunCollectorBlockedUrl:
    async def test_blocked_url_produces_tool_message(
        self, _cve_package_for_structured, mock_ai_message
    ):
        tool_msg = mock_ai_message(content="scraping")
        tool_msg.tool_calls = [
            {
                "id": "tc1",
                "name": "scrape_advisory",
                "args": {"url": "https://exploit-db.com/exploits/1234"},
            },
        ]
        no_tools_msg = mock_ai_message(content="done")
        no_tools_msg.tool_calls = []

        mock_llm = MagicMock()
        mock_llm_with_tools = MagicMock()
        mock_llm_with_tools.ainvoke = AsyncMock(side_effect=[tool_msg, no_tools_msg])
        mock_llm.bind_tools = MagicMock(return_value=mock_llm_with_tools)

        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=_cve_package_for_structured)

        mock_scrape = _mock_tool("scrape_advisory")

        call_count = 0
        def _get_model_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_llm
            return MagicMock(with_structured_output=MagicMock(return_value=mock_structured))

        with (
            patch("cvehunter.agents.collector.get_model", side_effect=_get_model_side_effect),
            patch("cvehunter.agents.collector.extract_cost", return_value=0.0),
            patch("cvehunter.agents.collector.collector_tools", [mock_scrape]),
        ):
            result = await run_collector({"cve_id": "CVE-2021-44228"})

        mock_scrape.ainvoke.assert_not_awaited()
        assert result["status"] == "collected"


class TestRunCollectorToolError:
    async def test_tool_returning_error_continues(
        self, _cve_package_for_structured, mock_ai_message
    ):
        tool_msg = mock_ai_message(content="querying")
        tool_msg.tool_calls = [
            {"id": "tc1", "name": "fetch_cve", "args": {"cve_id": "CVE-2021-44228"}},
        ]
        no_tools_msg = mock_ai_message(content="done")
        no_tools_msg.tool_calls = []

        mock_llm = MagicMock()
        mock_llm_with_tools = MagicMock()
        mock_llm_with_tools.ainvoke = AsyncMock(side_effect=[tool_msg, no_tools_msg])
        mock_llm.bind_tools = MagicMock(return_value=mock_llm_with_tools)

        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=_cve_package_for_structured)

        mock_fetch = _mock_tool(
            "fetch_cve", {"success": False, "error": "NVD API down"}
        )

        call_count = 0
        def _get_model_side_effect(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_llm
            return MagicMock(with_structured_output=MagicMock(return_value=mock_structured))

        with (
            patch("cvehunter.agents.collector.get_model", side_effect=_get_model_side_effect),
            patch("cvehunter.agents.collector.extract_cost", return_value=0.0),
            patch("cvehunter.agents.collector.collector_tools", [mock_fetch]),
        ):
            result = await run_collector({"cve_id": "CVE-2021-44228"})

        assert result["status"] == "collected"


class TestFindBlockedUrl:
    def test_allowed_domain_returns_none(self):
        assert _find_blocked_url({"url": "https://github.com/apache/log4j2"}) is None

    def test_blocked_domain_returns_url(self):
        url = "https://exploit-db.com/exploits/1234"
        assert _find_blocked_url({"url": url}) == url

    def test_non_url_values_ignored(self):
        assert _find_blocked_url({"cve_id": "CVE-2021-44228", "count": 5}) is None

    def test_empty_args(self):
        assert _find_blocked_url({}) is None
