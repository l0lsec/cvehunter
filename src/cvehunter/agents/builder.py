"""Environment Builder Agent — provisions Docker labs for exploit testing.

LLM Tier: CHEAP (DeepSeek V3.2)
Input: CVEPackage + ExploitRecipe
Output: EnvironmentSpec
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from cvehunter.config import ModelTier
from cvehunter.cost_tracker import check_cost_limits
from cvehunter.llm_router import extract_cost, get_model
from cvehunter.schemas import CVEPackage, EnvironmentSpec, ExploitRecipe
from cvehunter.tools.docker_ops import (
    build_image,
    compose_up,
    health_check,
    insert_flag,
    verify_network_isolation,
)

logger = structlog.get_logger(__name__)

MAX_BUILDER_RETRIES = 3

builder_tools = [build_image, compose_up, health_check]

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

TEMPLATE_MAP = {
    ("python", "flask"): "python-flask",
    ("javascript", "express"): "node-express",
    ("java", "spring"): "java-spring",
    ("php", None): "php-apache",
    ("c", None): "c-native",
}


def load_template(
    language: str, framework: str | None, needs_db: bool = False
) -> dict[str, str]:
    """Load matching Dockerfile and compose templates based on language/framework."""
    result: dict[str, str] = {}

    key = (language.lower(), (framework or "").lower() or None)
    template_name = TEMPLATE_MAP.get(key) or TEMPLATE_MAP.get((key[0], None))

    if template_name:
        df_path = TEMPLATES_DIR / "dockerfiles" / f"{template_name}.Dockerfile"
        if df_path.exists():
            result["dockerfile"] = df_path.read_text()

    compose_name = "web-with-db" if needs_db else "standalone-web"
    cf_path = TEMPLATES_DIR / "compose" / f"{compose_name}.yml"
    if cf_path.exists():
        result["compose"] = cf_path.read_text()

    return result

BUILDER_SYSTEM_PROMPT = """\
You are an expert DevOps engineer specializing in security lab environments.
Given a CVE's details and an exploitation recipe, build a Docker environment
that realistically hosts the vulnerable application.

Requirements:
1. Generate a Dockerfile that installs the EXACT vulnerable version of the software
2. Generate a docker-compose.yml with all necessary services (web server, database, etc.)
3. The environment must be REALISTIC — no unnecessary privileges or backdoors
4. Include only the minimum services needed for the vulnerability to be exploitable
5. Do NOT include:
   - Root/admin access that isn't part of the normal application
   - Debug modes or development configurations
   - Exposed management ports
   - Default credentials beyond what the application normally ships with

The flag will be inserted separately — just indicate where it should go based
on the vulnerability type.

Output a complete docker-compose.yml and any Dockerfiles needed.
"""

FLAG_PLACEMENT = {
    "path_traversal": "/etc/secret_flag.txt",
    "lfi": "/var/secret/flag.txt",
    "rce": "/root/flag.txt",
    "command_injection": "/root/flag.txt",
    "sqli": "database_record",
    "sql_injection": "database_record",
    "ssrf": "http://internal-flag-service/flag",
    "xxe": "/etc/flag.txt",
    "file_upload": "/root/flag.txt",
    "deserialization": "/root/flag.txt",
    "default": "/root/flag.txt",
}


def _get_flag_location(vuln_type: str) -> str:
    """Determine flag placement based on vulnerability type."""
    vuln_lower = vuln_type.lower().replace(" ", "_")
    for key, location in FLAG_PLACEMENT.items():
        if key in vuln_lower:
            return location
    return FLAG_PLACEMENT["default"]


async def _retry_compose(
    llm: Any,
    env_spec: EnvironmentSpec,
    last_error: dict,
    project_name: str,
) -> dict:
    """Feed compose_up errors back to the LLM for iterative correction."""
    llm_with_tools = llm.bind_tools(builder_tools)

    retry_messages = [
        SystemMessage(content=BUILDER_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"The Docker build failed with this error:\n{last_error['error']}\n\n"
                f"Original compose YAML:\n```yaml\n{env_spec.compose_yaml}\n```\n\n"
                "Fix the issue and provide a corrected docker-compose.yml. "
                "You can use the compose_up tool to test it."
            )
        ),
    ]

    for retry_num in range(MAX_BUILDER_RETRIES):
        response = await llm_with_tools.ainvoke(retry_messages)
        retry_messages.append(response)

        if response.tool_calls:
            for tool_call in response.tool_calls:
                tool_fn = {t.name: t for t in builder_tools}.get(tool_call["name"])
                if tool_fn is None:
                    continue
                result = await tool_fn.ainvoke(tool_call["args"])
                retry_messages.append(
                    ToolMessage(content=str(result), tool_call_id=tool_call["id"])
                )
                if tool_call["name"] == "compose_up" and "error" not in result:
                    yaml_arg = tool_call["args"].get("compose_yaml")
                    if yaml_arg:
                        env_spec.compose_yaml = yaml_arg
                    return result

        corrected_yaml = _extract_yaml(response.content)
        if corrected_yaml:
            env_spec.compose_yaml = corrected_yaml
            result = await compose_up.ainvoke({
                "compose_yaml": corrected_yaml,
                "project_name": project_name,
            })
            if "error" not in result:
                return result
            last_error = result
            retry_messages.append(
                HumanMessage(content=f"Still failing: {result['error']}\nTry again.")
            )

        logger.warning(
            "builder_retry_failed",
            retry=retry_num + 1,
            max_retries=MAX_BUILDER_RETRIES,
        )

    return last_error


def _extract_yaml(content: str) -> str | None:
    """Extract a YAML code block from LLM response text."""
    for marker in ("```yaml", "```yml"):
        if marker in content:
            parts = content.split(marker, 1)
            if len(parts) > 1:
                return parts[1].split("```")[0].strip()
    return None


async def run_builder(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the Environment Builder agent node."""
    cost_error = check_cost_limits(state.get("total_cost_usd", 0.0))
    if cost_error:
        return {
            "errors": state.get("errors", []) + [cost_error],
            "status": "cost_limit_exceeded",
            "total_cost_usd": state.get("total_cost_usd", 0.0),
        }

    cve_package: CVEPackage = state["cve_package"]
    recipe: ExploitRecipe = state["exploit_recipe"]
    run_cost = state.get("total_cost_usd", 0.0)
    tier = ModelTier.CHEAP

    flag_value = f"CVEHUNTER{{{secrets.token_hex(16)}}}"
    flag_location = _get_flag_location(recipe.vulnerability_type)

    llm = get_model("builder")

    context = f"""## Build Environment for: {cve_package.cve_id}

**Software:** {cve_package.affected_software}
**Vulnerable Versions:** {', '.join(cve_package.affected_versions)}
**Language:** {cve_package.language}
**Framework:** {cve_package.framework or 'N/A'}
**Vulnerability Type:** {recipe.vulnerability_type}
**Attack Vector:** {recipe.attack_vector}

## Required Conditions from Research
{chr(10).join(f'- {c}' for c in recipe.required_conditions)}

## Exploitation Steps (for environment planning only)
{chr(10).join(f'{i+1}. {s}' for i, s in enumerate(recipe.exploitation_steps))}

Generate a docker-compose.yml and Dockerfile(s) for this environment.
The flag location will be: {flag_location}
"""

    needs_db = any(k in recipe.vulnerability_type.lower() for k in ("sql", "database"))
    templates = load_template(cve_package.language, cve_package.framework, needs_db)
    if templates.get("dockerfile"):
        context += (
            f"\n## Reference Dockerfile Template\n"
            f"```dockerfile\n{templates['dockerfile']}\n```\n"
        )
    if templates.get("compose"):
        context += (
            f"\n## Reference Compose Template\n"
            f"```yaml\n{templates['compose']}\n```\n"
        )

    messages = [
        SystemMessage(content=BUILDER_SYSTEM_PROMPT),
        HumanMessage(content=context),
    ]

    structured_llm = llm.with_structured_output(EnvironmentSpec, method="function_calling")
    env_spec = await structured_llm.ainvoke(messages)
    run_cost += extract_cost(env_spec, tier) if hasattr(env_spec, "usage_metadata") else 0.0

    env_spec.cve_id = cve_package.cve_id
    env_spec.flag_value = flag_value
    env_spec.flag_location = flag_location

    project_name = f"cvehunter-{cve_package.cve_id.lower().replace('-', '_')}"

    compose_result = await compose_up.ainvoke({
        "compose_yaml": env_spec.compose_yaml,
        "project_name": project_name,
    })

    if "error" in compose_result:
        compose_result = await _retry_compose(
            llm, env_spec, compose_result, project_name
        )

    if "error" in compose_result:
        return {
            "environment": env_spec,
            "status": "environment_failed",
            "errors": [f"compose_up failed after retries: {compose_result['error']}"],
            "total_cost_usd": run_cost,
        }

    env_spec.network_name = compose_result.get(
        "network_name", f"{project_name}_default"
    )

    isolation_result = await verify_network_isolation(env_spec.network_name)
    if "error" in isolation_result:
        logger.warning(
            "network_isolation_failed",
            cve_id=cve_package.cve_id,
            error=isolation_result.get("error"),
        )
        env_spec.errors = env_spec.errors or []
        env_spec.errors.append(f"Network isolation warning: {isolation_result.get('error')}")

    compose_containers = compose_result.get("containers", [])
    if compose_containers:
        container_name = compose_containers[0]["name"]
    elif env_spec.services:
        container_name = f"{project_name}-{env_spec.services[0]}-1"
    else:
        container_name = project_name

    flag_result = await insert_flag.ainvoke({
        "container_name": container_name,
        "flag_location": flag_location,
        "flag_value": flag_value,
        "project_name": project_name,
    })
    if flag_result.get("status") == "failed" or "error" in flag_result:
        logger.warning(
            "flag_insertion_issue",
            cve_id=cve_package.cve_id,
            result=flag_result,
        )
        env_spec.errors = env_spec.errors or []
        env_spec.errors.append(f"Flag insertion problem: {flag_result}")

    hc_result = await health_check.ainvoke({
        "container_name": container_name,
    })
    env_spec.health_check_passed = hc_result.get("healthy", False)

    if not env_spec.health_check_passed:
        return {
            "environment": env_spec,
            "status": "environment_failed",
            "errors": [f"Health check failed: {hc_result}"],
            "total_cost_usd": run_cost,
        }

    if env_spec.patched_image:
        patched_project = f"{project_name}-patched"
        patched_compose = env_spec.compose_yaml.replace(
            env_spec.vulnerable_image, env_spec.patched_image
        )
        patched_result = await compose_up.ainvoke({
            "compose_yaml": patched_compose,
            "project_name": patched_project,
        })
        if "error" not in patched_result:
            env_spec.patched_network_name = patched_result.get(
                "network_name", f"{patched_project}_default"
            )
        else:
            logger.warning(
                "patched_env_failed",
                cve_id=cve_package.cve_id,
                error=patched_result["error"],
            )
    else:
        logger.warning(
            "patched_image_missing",
            cve_id=cve_package.cve_id,
        )

    return {
        "environment": env_spec,
        "status": "environment_ready",
        "total_cost_usd": run_cost,
    }
