"""Tests for the Researcher agent."""

from __future__ import annotations

import pytest

from moak.schemas import CVEPackage


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
