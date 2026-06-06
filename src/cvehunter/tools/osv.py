"""OSV.dev API client.

Google's open-source vulnerability database. Complements NVD with better
Git commit references and ecosystem-specific metadata.
Docs: https://osv.dev/docs/
"""

from __future__ import annotations

import httpx
from langchain_core.tools import tool

from cvehunter.tools import tool_failure, tool_success

OSV_API_BASE = "https://api.osv.dev/v1"


@tool
async def fetch_osv(cve_id: str) -> dict:
    """Fetch vulnerability data from OSV.dev by CVE alias.

    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2024-12345')

    Returns:
        Dictionary with affected packages, versions, Git ranges, and fix commits.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            response = await client.get(f"{OSV_API_BASE}/vulns/{cve_id}")
            if response.status_code == 404:
                return tool_failure(f"No OSV record for {cve_id}")
            response.raise_for_status()
            vuln = response.json()

            if not vuln or not vuln.get("id"):
                return tool_failure(f"No OSV record for {cve_id}")

            affected_packages = []
            fix_commits = []
            for affected in vuln.get("affected", []):
                pkg = affected.get("package", {})
                affected_packages.append({
                    "ecosystem": pkg.get("ecosystem", ""),
                    "name": pkg.get("name", ""),
                })

                for rng in affected.get("ranges", []):
                    if rng.get("type") == "GIT":
                        repo = rng.get("repo", "")
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fix_commits.append({
                                    "repo": repo,
                                    "commit": event["fixed"],
                                })

            details = vuln.get("details", "") or ""
            if len(details) > 2000:
                details = details[:2000] + "\n... [truncated]"

            return tool_success({
                "osv_id": vuln.get("id", ""),
                "summary": vuln.get("summary", ""),
                "details": details,
                "affected_packages": affected_packages,
                "fix_commits": fix_commits,
                "references": [
                    {"type": ref.get("type", ""), "url": ref.get("url", "")}
                    for ref in vuln.get("references", [])
                ],
            })

        except httpx.HTTPStatusError as e:
            return tool_failure(f"OSV API HTTP error: {e.response.status_code}")
        except Exception as e:
            return tool_failure(f"OSV API error: {str(e)}")
