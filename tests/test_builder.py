"""Tests for the Environment Builder agent."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import yaml

from cvehunter.agents.builder import (
    _extract_yaml,
    _get_flag_location,
    load_template,
    run_builder,
)
from cvehunter.config import settings
from cvehunter.schemas import EnvironmentSpec


def _env_spec_from_llm() -> EnvironmentSpec:
    """Minimal EnvironmentSpec as the structured LLM would return."""
    return EnvironmentSpec(
        cve_id="",
        vulnerable_image="vuln-img:1.0",
        patched_image="patched-img:1.1",
        compose_yaml="version: '3'\nservices:\n  web:\n    image: vuln-img:1.0\n",
        flag_value="",
        flag_location="",
        network_name="",
        services=["web"],
    )


class TestRunBuilderSuccess:
    async def test_environment_ready(
        self, sample_cve_package, sample_exploit_recipe, mock_structured_llm
    ):
        env_spec = _env_spec_from_llm()
        mock_llm = mock_structured_llm(env_spec)

        compose_result = {
            "project_name": "cvehunter-cve_2021_44228",
            "status": "running",
            "containers": [{"name": "cvehunter-cve_2021_44228-web-1"}],
            "network_name": "cvehunter-cve_2021_44228_default",
        }
        flag_result = {"status": "inserted", "location": "/root/flag.txt"}
        hc_result = {"healthy": True, "exit_code": 0}
        patched_compose_result = {
            "project_name": "cvehunter-cve_2021_44228-patched",
            "network_name": "cvehunter-cve_2021_44228-patched_default",
        }

        isolation_ok = {"network": "test", "internal": True, "probe_passed": True, "status": "isolated"}

        with (
            patch("cvehunter.agents.builder.get_model", return_value=mock_llm),
            patch("cvehunter.agents.builder.check_cost_limits", return_value=None),
            patch(
                "cvehunter.agents.builder.compose_up",
                MagicMock(ainvoke=AsyncMock(side_effect=[compose_result, patched_compose_result])),
            ),
            patch(
                "cvehunter.agents.builder.insert_flag",
                MagicMock(ainvoke=AsyncMock(return_value=flag_result)),
            ),
            patch(
                "cvehunter.agents.builder.health_check",
                MagicMock(ainvoke=AsyncMock(return_value=hc_result)),
            ),
            patch("cvehunter.agents.builder.verify_network_isolation", new_callable=AsyncMock, return_value=isolation_ok),
        ):
            state = {
                "cve_package": sample_cve_package,
                "exploit_recipe": sample_exploit_recipe,
                "total_cost_usd": 0.0,
            }
            result = await run_builder(state)

        assert result["status"] == "environment_ready"
        env = result["environment"]
        assert isinstance(env, EnvironmentSpec)
        assert env.flag_value.startswith("CVEHUNTER{")
        assert env.network_name == "cvehunter-cve_2021_44228_default"
        assert env.health_check_passed is True
        # The persisted compose artifact reflects the isolated form: the LLM's
        # bare compose (no networks section) gains an internal default network.
        persisted = yaml.safe_load(env.compose_yaml)
        assert persisted["networks"]["default"]["internal"] is True


class TestRunBuilderComposeRetry:
    async def test_retry_succeeds_on_second_attempt(
        self, sample_cve_package, sample_exploit_recipe, mock_structured_llm
    ):
        env_spec = _env_spec_from_llm()
        mock_llm = mock_structured_llm(env_spec)

        fail_result = {"error": "port already allocated"}
        ok_result = {
            "project_name": "cvehunter-cve_2021_44228",
            "status": "running",
            "containers": [{"name": "cvehunter-cve_2021_44228-web-1"}],
            "network_name": "cvehunter-cve_2021_44228_default",
        }
        flag_result = {"status": "inserted"}
        hc_result = {"healthy": True}

        isolation_ok = {"network": "test", "internal": True, "probe_passed": True, "status": "isolated"}

        with (
            patch("cvehunter.agents.builder.get_model", return_value=mock_llm),
            patch("cvehunter.agents.builder.check_cost_limits", return_value=None),
            patch(
                "cvehunter.agents.builder.compose_up",
                MagicMock(ainvoke=AsyncMock(side_effect=[fail_result, ok_result, ok_result])),
            ),
            patch(
                "cvehunter.agents.builder.insert_flag",
                MagicMock(ainvoke=AsyncMock(return_value=flag_result)),
            ),
            patch(
                "cvehunter.agents.builder.health_check",
                MagicMock(ainvoke=AsyncMock(return_value=hc_result)),
            ),
            patch("cvehunter.agents.builder._retry_compose", new_callable=AsyncMock, return_value=ok_result),
            patch("cvehunter.agents.builder.verify_network_isolation", new_callable=AsyncMock, return_value=isolation_ok),
        ):
            state = {
                "cve_package": sample_cve_package,
                "exploit_recipe": sample_exploit_recipe,
                "total_cost_usd": 0.0,
            }
            result = await run_builder(state)

        assert result["status"] == "environment_ready"


class TestRunBuilderComposeExhausted:
    async def test_all_retries_fail(
        self, sample_cve_package, sample_exploit_recipe, mock_structured_llm
    ):
        env_spec = _env_spec_from_llm()
        mock_llm = mock_structured_llm(env_spec)

        fail_result = {"error": "build failed"}

        with (
            patch("cvehunter.agents.builder.get_model", return_value=mock_llm),
            patch("cvehunter.agents.builder.check_cost_limits", return_value=None),
            patch(
                "cvehunter.agents.builder.compose_up",
                MagicMock(ainvoke=AsyncMock(return_value=fail_result)),
            ),
            patch("cvehunter.agents.builder._retry_compose", new_callable=AsyncMock, return_value=fail_result),
        ):
            state = {
                "cve_package": sample_cve_package,
                "exploit_recipe": sample_exploit_recipe,
                "total_cost_usd": 0.0,
            }
            result = await run_builder(state)

        assert result["status"] == "environment_failed"
        assert any("compose_up" in e for e in result.get("errors", []))


class TestRunBuilderHealthCheckFailure:
    async def test_unhealthy_env(
        self, sample_cve_package, sample_exploit_recipe, mock_structured_llm
    ):
        env_spec = _env_spec_from_llm()
        mock_llm = mock_structured_llm(env_spec)

        compose_result = {
            "project_name": "cvehunter-cve_2021_44228",
            "status": "running",
            "containers": [{"name": "cvehunter-cve_2021_44228-web-1"}],
            "network_name": "test_default",
        }

        isolation_ok = {"network": "test", "internal": True, "probe_passed": True, "status": "isolated"}

        with (
            patch("cvehunter.agents.builder.get_model", return_value=mock_llm),
            patch("cvehunter.agents.builder.check_cost_limits", return_value=None),
            patch(
                "cvehunter.agents.builder.compose_up",
                MagicMock(ainvoke=AsyncMock(return_value=compose_result)),
            ),
            patch(
                "cvehunter.agents.builder.insert_flag",
                MagicMock(ainvoke=AsyncMock(return_value={"status": "inserted"})),
            ),
            patch(
                "cvehunter.agents.builder.health_check",
                MagicMock(ainvoke=AsyncMock(return_value={"healthy": False, "exit_code": 1})),
            ),
            patch("cvehunter.agents.builder.verify_network_isolation", new_callable=AsyncMock, return_value=isolation_ok),
        ):
            state = {
                "cve_package": sample_cve_package,
                "exploit_recipe": sample_exploit_recipe,
                "total_cost_usd": 0.0,
            }
            result = await run_builder(state)

        assert result["status"] == "environment_failed"


class TestRunBuilderNetworkIsolation:
    async def test_isolation_failure_is_fatal_when_enforced(
        self, sample_cve_package, sample_exploit_recipe, mock_structured_llm
    ):
        env_spec = _env_spec_from_llm()
        mock_llm = mock_structured_llm(env_spec)

        compose_result = {
            "project_name": "cvehunter-cve_2021_44228",
            "status": "running",
            "containers": [{"name": "cvehunter-cve_2021_44228-web-1"}],
            "network_name": "cvehunter-cve_2021_44228_default",
        }
        isolation_fail = {
            "error": "Network 'cvehunter-cve_2021_44228_default' is not marked as internal",
            "internal": False,
        }

        with (
            patch("cvehunter.agents.builder.get_model", return_value=mock_llm),
            patch("cvehunter.agents.builder.check_cost_limits", return_value=None),
            patch(
                "cvehunter.agents.builder.compose_up",
                MagicMock(ainvoke=AsyncMock(return_value=compose_result)),
            ),
            patch(
                "cvehunter.agents.builder.verify_network_isolation",
                new_callable=AsyncMock,
                return_value=isolation_fail,
            ),
            patch.object(settings, "network_isolation_enforced", True),
        ):
            state = {
                "cve_package": sample_cve_package,
                "exploit_recipe": sample_exploit_recipe,
                "total_cost_usd": 0.0,
            }
            result = await run_builder(state)

        assert result["status"] == "environment_failed"
        assert any("isolation failed" in e.lower() for e in result.get("errors", []))

    async def test_isolation_failure_is_warning_when_not_enforced(
        self, sample_cve_package, sample_exploit_recipe, mock_structured_llm
    ):
        env_spec = _env_spec_from_llm()
        mock_llm = mock_structured_llm(env_spec)

        compose_result = {
            "project_name": "cvehunter-cve_2021_44228",
            "status": "running",
            "containers": [{"name": "cvehunter-cve_2021_44228-web-1"}],
            "network_name": "cvehunter-cve_2021_44228_default",
        }
        patched_compose_result = {
            "project_name": "cvehunter-cve_2021_44228-patched",
            "network_name": "cvehunter-cve_2021_44228-patched_default",
        }
        isolation_fail = {
            "error": "Network 'cvehunter-cve_2021_44228_default' is not marked as internal",
            "internal": False,
        }

        with (
            patch("cvehunter.agents.builder.get_model", return_value=mock_llm),
            patch("cvehunter.agents.builder.check_cost_limits", return_value=None),
            patch(
                "cvehunter.agents.builder.compose_up",
                MagicMock(ainvoke=AsyncMock(side_effect=[compose_result, patched_compose_result])),
            ),
            patch(
                "cvehunter.agents.builder.insert_flag",
                MagicMock(ainvoke=AsyncMock(return_value={"status": "inserted"})),
            ),
            patch(
                "cvehunter.agents.builder.health_check",
                MagicMock(ainvoke=AsyncMock(return_value={"healthy": True})),
            ),
            patch(
                "cvehunter.agents.builder.verify_network_isolation",
                new_callable=AsyncMock,
                return_value=isolation_fail,
            ),
            patch.object(settings, "network_isolation_enforced", False),
        ):
            state = {
                "cve_package": sample_cve_package,
                "exploit_recipe": sample_exploit_recipe,
                "total_cost_usd": 0.0,
            }
            result = await run_builder(state)

        assert result["status"] == "environment_ready"
        env = result["environment"]
        assert any("isolation warning" in e.lower() for e in env.errors)


class TestLoadTemplate:
    def test_known_language(self):
        result = load_template("python", "flask")
        assert isinstance(result, dict)

    def test_unknown_language(self):
        result = load_template("brainfuck", None)
        assert isinstance(result, dict)

    def test_with_db(self):
        result = load_template("python", "flask", needs_db=True)
        assert isinstance(result, dict)


class TestGetFlagLocation:
    def test_path_traversal(self):
        assert _get_flag_location("path_traversal") == "/etc/secret_flag.txt"

    def test_sqli(self):
        assert _get_flag_location("sqli") == "database_record"

    def test_rce(self):
        assert _get_flag_location("rce") == "/root/flag.txt"

    def test_unknown_defaults(self):
        assert _get_flag_location("zero_day_quantum") == "/root/flag.txt"


class TestExtractYaml:
    def test_yaml_block(self):
        content = "Here is the fix:\n```yaml\nversion: '3'\nservices:\n  web: {}\n```\nDone."
        assert _extract_yaml(content) == "version: '3'\nservices:\n  web: {}"

    def test_yml_block(self):
        content = "```yml\nfoo: bar\n```"
        assert _extract_yaml(content) == "foo: bar"

    def test_no_yaml(self):
        assert _extract_yaml("no yaml here") is None
