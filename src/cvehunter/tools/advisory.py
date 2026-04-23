"""Advisory scraping tool — fetches vendor security advisory pages."""

from __future__ import annotations

import re

import httpx
from bs4 import BeautifulSoup
from langchain_core.tools import tool

from cvehunter.tools import tool_failure, tool_success
from cvehunter.tools.url_validation import validate_url

_PATCH_LINK_PATTERNS = re.compile(
    r"(commit|patch|diff|/compare/)", re.IGNORECASE
)
_USER_AGENT = (
    "Mozilla/5.0 (compatible; CVEHunter/0.1; +https://github.com/cvehunter)"
)
_MAX_BODY_LENGTH = 8000


@tool
async def scrape_advisory(url: str) -> dict:
    """Fetch a vendor security advisory page and extract relevant text.

    Args:
        url: The advisory URL to fetch. Must be on an allowed domain.
    """
    if not validate_url(url):
        return tool_failure(f"URL not in allowed domains: {url}")

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.HTTPError as e:
        return tool_failure(f"HTTP request failed: {e}")

    soup = BeautifulSoup(response.text, "html.parser")

    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    for tag in soup.find_all(["script", "style", "nav", "footer", "header"]):
        tag.decompose()

    body = soup.get_text(separator="\n", strip=True)
    if len(body) > _MAX_BODY_LENGTH:
        body = body[:_MAX_BODY_LENGTH] + "\n... [truncated]"

    patch_links = []
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"]
        if _PATCH_LINK_PATTERNS.search(href):
            patch_links.append(href)

    return tool_success({
        "title": title,
        "body": body,
        "patch_links": patch_links[:20],
        "url": url,
    })
