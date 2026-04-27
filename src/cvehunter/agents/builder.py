"""Environment Builder Agent — provisions Docker labs for exploit testing.

LLM Tier: CHEAP (DeepSeek V4 Flash)
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

MAX_BUILDER_RETRIES = 5

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

Output:
- ``compose_yaml``: a complete docker-compose.yml.
- ``dockerfile_content``: the full Dockerfile content when the compose file
  uses a ``build:`` section referencing ``Dockerfile``. If every service in
  compose uses only pre-built ``image:`` references, ``dockerfile_content``
  may be an empty string.
- ``health_check_command``: a shell command run **inside** the primary
  container that returns exit code 0 when the vulnerable service is ready
  to receive exploit traffic. Examples: ``curl -sf http://localhost:8080/``,
  ``nc -z localhost 1099``, ``test -f /tmp/ready``. Pick a port that
  matches what your service actually listens on.

The Dockerfile must be self-contained: inline any source files with
``RUN echo ... > /path/file`` or ``RUN cat <<'EOF' > /path/file`` heredocs —
there is no build context with extra files, only the Dockerfile itself.

Prefer multi-arch base images (``eclipse-temurin:*``, ``python:*-slim``,
``node:*-slim``, ``debian:*-slim``) so the build works on both linux/amd64
and linux/arm64. Avoid older ``openjdk:8*`` tags which lack arm64 manifests.

Java-specific rules:
- If the Dockerfile calls ``javac`` or ``mvn``/``gradle``, the base image
  MUST be a JDK variant (e.g. ``eclipse-temurin:8-jdk`` or
  ``eclipse-temurin:11-jdk``). JRE images (``*-jre-*``) do NOT ship javac
  and will fail compilation with ``exit code 127``. Use a multi-stage build
  (JDK builder → JRE runtime) only if you really need to shrink the runtime.
- Prefer pre-built images that already contain the build/runtime tooling
  instead of downloading tarballs inside the Dockerfile:
    * Maven builds → ``FROM maven:3.9-eclipse-temurin-8`` (or ``-11``/``-17``)
      as the builder stage. Do NOT ``curl`` Maven tarballs manually.
    * Gradle builds → ``FROM gradle:8-jdk8`` (or matching JDK).
    * Servlet containers → ``FROM tomcat:9-jdk8-temurin`` (etc.) instead of
      downloading Tomcat tarballs.
  If you extract a tarball anyway, reference the resulting directory
  literally (for example ``/opt/apache-tomcat-9.0.56``) rather than with
  shell variables that may drift.
- NEVER download Apache project archives from ``https://dlcdn.apache.org``.
  That CDN only hosts CURRENT releases; older versions are pruned and your
  ``curl -fsSL`` will fail with exit code 22 (HTTP 404). For pinned/older
  versions use ``https://archive.apache.org/dist/...`` instead, OR (better)
  use a pre-built image as listed above so you don't need to download the
  tool at all.
- Ensure every directory referenced by ``-d``, ``--output``, ``-o``, or
  similar flags is created with ``mkdir -p`` in the same ``RUN`` before the
  tool runs.
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


def _build_retry_hint(error_text: str) -> str:
    """Pattern-match common Docker build failures and produce targeted hints."""
    hints: list[str] = []
    err = error_text or ""
    low = err.lower()

    if "dlcdn.apache.org" in low:
        hints.append(
            "DETECTED: dlcdn.apache.org URL. That CDN drops older releases — "
            "use a pre-built image instead (e.g. `FROM maven:3.9-eclipse-temurin-8` "
            "for Maven builds, `FROM tomcat:9-jdk8-temurin` for Tomcat). If you "
            "absolutely need a tarball, use `https://archive.apache.org/dist/...`."
        )
    if "exit code: 22" in low and "curl" in low:
        hints.append(
            "DETECTED: `curl --fail` exited 22 (HTTP 4xx/5xx). The URL is "
            "unreachable or the version was pruned. Switch to an official "
            "pre-built image (e.g. maven:*, tomcat:*, gradle:*) so no download "
            "is needed."
        )
    if "mvn" in low and ("exit code: 127" in low or "mvn: command not found" in low or "mvn: not found" in low):
        hints.append(
            "DETECTED: `mvn` not on PATH. The base image (e.g. eclipse-temurin) "
            "does NOT include Maven. Switch the builder stage to a Maven image: "
            "`FROM maven:3.9-eclipse-temurin-8` (or `-11`/`-17`) — it ships both "
            "the JDK and the Maven CLI. Do NOT install Maven manually with curl."
        )
    elif "gradle" in low and ("exit code: 127" in low or "gradle: command not found" in low or "gradle: not found" in low):
        hints.append(
            "DETECTED: `gradle` not on PATH. Use `FROM gradle:8-jdk8` (or matching "
            "JDK) for the builder stage instead of installing Gradle manually."
        )
    elif "javac: command not found" in low or "exit code: 127" in low:
        hints.append(
            "DETECTED: javac missing. Use a JDK base image "
            "(`eclipse-temurin:8-jdk` / `:11-jdk` / `:17-jdk`), NOT a JRE."
        )
    if "no match for platform in manifest" in low:
        hints.append(
            "DETECTED: base image lacks an arm64 manifest. Use a multi-arch "
            "image such as `eclipse-temurin:*-jdk` or `maven:*-eclipse-temurin-*`."
        )
    if "directory not found" in low and "javac" in low:
        hints.append(
            "DETECTED: javac output directory missing. `mkdir -p` it in the "
            "same RUN before invoking javac."
        )
    return "\n".join(hints)


async def _retry_compose(
    llm: Any,
    env_spec: EnvironmentSpec,
    last_error: dict,
    project_name: str,
    name_prefix: str = "",
) -> dict:
    """Feed compose_up errors back to the LLM for iterative correction."""
    # Only bind compose_up during retries. Binding build_image causes the LLM
    # to fork its experimentation across two tools, and build_image returns a
    # stripped error ("non-zero code: 1") that hides the real Maven/javac
    # stderr — so retries via that path are uninformative for both the LLM
    # and our hint matcher. Forcing all retries through compose_up keeps the
    # full BuildKit error stream in the loop.
    llm_with_tools = llm.bind_tools([compose_up])

    initial_hint = _build_retry_hint(last_error.get("error", ""))
    hint_block = f"\n\nTARGETED HINT:\n{initial_hint}\n" if initial_hint else ""

    retry_messages = [
        SystemMessage(content=BUILDER_SYSTEM_PROMPT),
        HumanMessage(
            content=(
                f"The Docker build failed with this error:\n{last_error['error']}\n"
                f"{hint_block}\n"
                f"Original compose YAML:\n```yaml\n{env_spec.compose_yaml}\n```\n\n"
                f"Original Dockerfile:\n```dockerfile\n{env_spec.dockerfile_content or '(none provided)'}\n```\n\n"
                "Fix the issue and call the `compose_up` tool ONCE with the "
                "corrected `compose_yaml` AND `dockerfile_content` arguments. "
                "Do not call `build_image` or any other tool — only `compose_up`. "
                "Inline any source files inside the Dockerfile via RUN heredocs — "
                "there is no extra build context."
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
                if tool_call["name"] == "compose_up":
                    df_arg = tool_call["args"].get("dockerfile_content") or ""
                    if "error" in result:
                        last_error = result
                    else:
                        yaml_arg = tool_call["args"].get("compose_yaml")
                        if yaml_arg:
                            env_spec.compose_yaml = yaml_arg
                        if df_arg:
                            env_spec.dockerfile_content = df_arg
                        return result

        corrected_yaml = _extract_yaml(response.content)
        corrected_dockerfile = _extract_dockerfile(response.content)
        if corrected_yaml or corrected_dockerfile:
            if corrected_yaml:
                env_spec.compose_yaml = corrected_yaml
            if corrected_dockerfile:
                env_spec.dockerfile_content = corrected_dockerfile
            result = await compose_up.ainvoke({
                "compose_yaml": env_spec.compose_yaml,
                "project_name": project_name,
                "dockerfile_content": env_spec.dockerfile_content,
                "name_prefix": name_prefix,
            })
            if "error" not in result:
                return result
            last_error = result
            hint = _build_retry_hint(result.get("error", ""))
            hint_text = f"\n\nTARGETED HINT:\n{hint}" if hint else ""
            retry_messages.append(
                HumanMessage(
                    content=f"Still failing: {result['error']}{hint_text}\nTry again."
                )
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


def _extract_dockerfile(content: str) -> str | None:
    """Extract a Dockerfile code block from LLM response text."""
    for marker in ("```dockerfile", "```Dockerfile"):
        if marker in content:
            parts = content.split(marker, 1)
            if len(parts) > 1:
                return parts[1].split("```")[0].strip()
    return None


def _strip_host_ports(compose_yaml: str) -> str:
    """Remove ``ports:`` blocks from a compose YAML.

    The patched env runs alongside the vulnerable env on the same host. Both
    publishing the same host port (e.g. ``0.0.0.0:8080``) collides at the
    Docker daemon level. The patched env is only ever reached internally
    (judge probes via container name on the bridge network), so dropping
    host-side publishing eliminates the collision without breaking
    functionality. Service-level ``expose:`` is left intact.
    """
    try:
        import yaml  # local import keeps top of module clean
    except Exception:
        return compose_yaml

    try:
        doc = yaml.safe_load(compose_yaml)
    except Exception:
        return compose_yaml

    if not isinstance(doc, dict):
        return compose_yaml
    services = doc.get("services")
    if not isinstance(services, dict):
        return compose_yaml
    for svc in services.values():
        if isinstance(svc, dict) and "ports" in svc:
            svc.pop("ports", None)
    return yaml.safe_dump(doc, sort_keys=False)


def _derive_health_check_command(compose_yaml: str) -> str:
    """Derive a TCP-level health probe from the first published port in compose.

    Uses ``curl`` exit codes: 0 (success) and 22 (HTTP error) both mean the
    TCP socket is accepting connections, so the service is up even if it
    returns 4xx/5xx on ``/``. Exit 7 (couldn't connect) keeps it unhealthy.
    """
    try:
        import yaml as _yaml
        spec = _yaml.safe_load(compose_yaml) or {}
        services = spec.get("services") or {}
        for svc in services.values():
            for port in svc.get("ports", []) or []:
                port_str = str(port)
                container_port = port_str.split(":")[-1].split("/")[0].strip()
                if container_port.isdigit():
                    return (
                        f"sh -c 'curl -s -o /dev/null --max-time 5 "
                        f"http://localhost:{container_port}/; "
                        f"code=$?; [ $code -eq 0 ] || [ $code -eq 22 ]'"
                    )
    except Exception:
        pass
    return ""


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

    run_hash = secrets.token_hex(2)
    cve_slug = cve_package.cve_id.lower()
    name_prefix = f"{cve_slug}-{run_hash}"
    project_name = f"cvehunter-{cve_slug}-{run_hash}"
    env_spec.run_hash = run_hash
    env_spec.name_prefix = name_prefix

    compose_result = await compose_up.ainvoke({
        "compose_yaml": env_spec.compose_yaml,
        "project_name": project_name,
        "dockerfile_content": env_spec.dockerfile_content,
        "name_prefix": name_prefix,
    })

    if "error" in compose_result:
        compose_result = await _retry_compose(
            llm, env_spec, compose_result, project_name, name_prefix
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
        env_spec.services = [c["name"] for c in compose_containers if c.get("name")]
    elif env_spec.services:
        container_name = f"{name_prefix}-{env_spec.services[0]}"
    else:
        container_name = name_prefix

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

    derived = _derive_health_check_command(env_spec.compose_yaml)
    hc_command = derived or env_spec.health_check_command
    hc_kwargs = {"container_name": container_name}
    if hc_command:
        hc_kwargs["check_command"] = hc_command
    hc_result = await health_check.ainvoke(hc_kwargs)
    env_spec.health_check_passed = hc_result.get("healthy", False)

    if not env_spec.health_check_passed:
        return {
            "environment": env_spec,
            "status": "environment_failed",
            "errors": [f"Health check failed: {hc_result}"],
            "total_cost_usd": run_cost,
        }

    if env_spec.patched_image:
        patched_project = f"cvehunter-{cve_slug}-patched-{run_hash}"
        patched_prefix = f"{cve_slug}-patched-{run_hash}"
        patched_compose = env_spec.compose_yaml.replace(
            env_spec.vulnerable_image, env_spec.patched_image
        )
        patched_compose = _strip_host_ports(patched_compose)
        patched_result = await compose_up.ainvoke({
            "compose_yaml": patched_compose,
            "project_name": patched_project,
            "dockerfile_content": env_spec.dockerfile_content,
            "name_prefix": patched_prefix,
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
