"""GitHub API client for finding patch commits and extracting diffs.

Uses the GitHub REST API. Free tier: 5,000 requests/hour with a token.
Docs: https://docs.github.com/en/rest
"""

from __future__ import annotations

import httpx
from langchain_core.tools import tool

from cvehunter.config import settings
from cvehunter.tools import tool_failure, tool_success

GITHUB_API_BASE = "https://api.github.com"


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


@tool
async def search_github_commits(query: str) -> dict:
    """Search GitHub for commits matching a query (e.g., CVE ID or fix description).

    Args:
        query: Search query string (e.g., 'CVE-2024-12345 fix')

    Returns:
        List of matching commits with repo, SHA, message, and diff URL.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            response = await client.get(
                f"{GITHUB_API_BASE}/search/commits",
                params={"q": query, "per_page": 5},
                headers=_github_headers(),
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                return tool_failure("Unexpected GitHub API response format")

            commits = []
            for item in data.get("items") or []:
                if not isinstance(item, dict):
                    continue
                commits.append({
                    "sha": item.get("sha", ""),
                    "message": item.get("commit", {}).get("message", "")[:500],
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "html_url": item.get("html_url", ""),
                    "date": item.get("commit", {}).get("author", {}).get("date", ""),
                })

            return tool_success({"commits": commits, "total_count": data.get("total_count", 0)})

        except httpx.HTTPStatusError as e:
            return tool_failure(f"GitHub API HTTP error: {e.response.status_code}")
        except Exception as e:
            return tool_failure(f"GitHub API error: {str(e)}")


@tool
async def get_commit_diff(repo: str, sha: str) -> dict:
    """Fetch the diff for a specific commit.

    Args:
        repo: Repository in 'owner/name' format (e.g., 'facebook/react')
        sha: The commit SHA hash

    Returns:
        The commit diff as a patch string, plus changed files list.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            response = await client.get(
                f"{GITHUB_API_BASE}/repos/{repo}/commits/{sha}",
                headers={
                    **_github_headers(),
                    "Accept": "application/vnd.github.v3.diff",
                },
            )
            response.raise_for_status()
            diff_text = response.text

            # Also get structured file info
            response_json = await client.get(
                f"{GITHUB_API_BASE}/repos/{repo}/commits/{sha}",
                headers=_github_headers(),
            )
            response_json.raise_for_status()
            commit_data = response_json.json()

            files = [
                {
                    "filename": f.get("filename", ""),
                    "status": f.get("status", ""),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                }
                for f in commit_data.get("files", [])
            ]

            return tool_success({
                "diff": diff_text[:10000],
                "files_changed": files,
                "commit_message": commit_data.get("commit", {}).get("message", ""),
            })

        except httpx.HTTPStatusError as e:
            return tool_failure(f"GitHub API HTTP error: {e.response.status_code}")
        except Exception as e:
            return tool_failure(f"GitHub API error: {str(e)}")
