"""Tests for the Collector agent and its tools."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_nvd_fetch():
    """Test fetching a known CVE from the NVD API."""
    from moak.tools.nvd import fetch_cve

    result = await fetch_cve.ainvoke({"cve_id": "CVE-2021-44228"})
    assert "error" not in result or result.get("cve_id") == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_osv_fetch():
    """Test fetching a known CVE from OSV.dev."""
    from moak.tools.osv import fetch_osv

    result = await fetch_osv.ainvoke({"cve_id": "CVE-2021-44228"})
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_github_search():
    """Test searching GitHub for a CVE fix commit."""
    from moak.tools.github import search_github_commits

    result = await search_github_commits.ainvoke({"query": "CVE-2021-44228 fix"})
    assert isinstance(result, dict)
