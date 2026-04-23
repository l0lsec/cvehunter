"""NVD (National Vulnerability Database) API client.

Uses the NVD API 2.0 via the nvdlib Python wrapper.
Free API with key — 0.6s rate limit with key, 6s without.
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

from langchain_core.tools import tool

from moak.config import settings


@tool
async def fetch_cve(cve_id: str) -> dict:
    """Fetch CVE details from the NVD API.

    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2024-12345')

    Returns:
        Dictionary with CVE description, CVSS scores, CWE, references, and affected products.
    """
    import nvdlib

    try:
        results = nvdlib.searchCVE(cveId=cve_id, key=settings.nvd_api_key or None)
        if not results:
            return {"error": f"No results found for {cve_id}"}

        cve = results[0]

        descriptions = []
        if hasattr(cve, "descriptions"):
            descriptions = [
                d.value for d in cve.descriptions if d.lang == "en"
            ]

        references = []
        if hasattr(cve, "references"):
            references = [ref.url for ref in cve.references]

        cvss_v3 = None
        if hasattr(cve, "v31score"):
            cvss_v3 = cve.v31score
        elif hasattr(cve, "v30score"):
            cvss_v3 = cve.v30score

        cwe_ids = []
        if hasattr(cve, "cwe"):
            cwe_ids = [cve.cwe]

        return {
            "cve_id": cve_id,
            "description": descriptions[0] if descriptions else "",
            "cvss_v3_score": cvss_v3,
            "cwe_ids": cwe_ids,
            "references": references,
            "published": str(cve.published) if hasattr(cve, "published") else None,
            "last_modified": str(cve.lastModified) if hasattr(cve, "lastModified") else None,
        }

    except Exception as e:
        return {"error": f"NVD API error: {str(e)}"}
