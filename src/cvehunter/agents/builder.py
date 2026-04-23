"""Environment Builder Agent — provisions Docker labs for exploit testing.

LLM Tier: CHEAP (DeepSeek V3.2)
Input: CVEPackage + ExploitRecipe
Output: EnvironmentSpec
"""

from __future__ import annotations

import secrets
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from moak.llm_router import get_model
from moak.schemas import CVEPackage, EnvironmentSpec, ExploitRecipe
from moak.tools.docker_ops import (
    build_image,
    compose_up,
    health_check,
    insert_flag,
)

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


async def run_builder(state: dict[str, Any]) -> dict[str, Any]:
    """Execute the Environment Builder agent node."""
    cve_package: CVEPackage = state["cve_package"]
    recipe: ExploitRecipe = state["exploit_recipe"]

    flag_value = f"MOAK{{{secrets.token_hex(16)}}}"
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

    messages = [
        SystemMessage(content=BUILDER_SYSTEM_PROMPT),
        HumanMessage(content=context),
    ]

    structured_llm = llm.with_structured_output(EnvironmentSpec)
    env_spec = await structured_llm.ainvoke(messages)

    env_spec.cve_id = cve_package.cve_id
    env_spec.flag_value = flag_value
    env_spec.flag_location = flag_location

    # TODO: Actually build and verify the Docker environment
    # await compose_up(env_spec.compose_yaml)
    # await insert_flag(container_id, flag_location, flag_value)
    # env_spec.health_check_passed = await health_check(container_id)

    return {
        "environment": env_spec,
        "status": "environment_ready",
    }
