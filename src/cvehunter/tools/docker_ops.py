"""Docker operations for building and managing exploit test environments.

Uses the Docker SDK for Python to manage containers, images, and networks.
All exploit environments run in isolated Docker networks with no internet access.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import docker
from langchain_core.tools import tool

from moak.config import settings


def _get_client() -> docker.DockerClient:
    return docker.DockerClient(base_url=settings.docker_host)


@tool
async def build_image(dockerfile_content: str, tag: str) -> dict:
    """Build a Docker image from a Dockerfile string.

    Args:
        dockerfile_content: The full Dockerfile content
        tag: Image tag (e.g., 'moak-vuln-cve-2024-12345')

    Returns:
        Build result with image ID and any warnings.
    """
    client = _get_client()
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = Path(tmpdir) / "Dockerfile"
            dockerfile_path.write_text(dockerfile_content)

            image, build_logs = client.images.build(
                path=tmpdir,
                tag=tag,
                rm=True,
            )
            logs = [log.get("stream", "") for log in build_logs if "stream" in log]
            return {
                "image_id": image.id,
                "tag": tag,
                "logs": "".join(logs)[-2000:],
            }
    except docker.errors.BuildError as e:
        return {"error": f"Docker build failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Docker error: {str(e)}"}


@tool
async def compose_up(compose_yaml: str, project_name: str) -> dict:
    """Start services from a docker-compose.yml string.

    Args:
        compose_yaml: The full docker-compose.yml content
        project_name: Unique project name for this CVE run

    Returns:
        Running container IDs and network info.
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            compose_path = Path(tmpdir) / "docker-compose.yml"
            compose_path.write_text(compose_yaml)

            import subprocess

            result = subprocess.run(
                ["docker", "compose", "-f", str(compose_path), "-p", project_name, "up", "-d"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                return {"error": f"Compose up failed: {result.stderr}"}

            return {
                "project_name": project_name,
                "stdout": result.stdout,
                "status": "running",
            }
    except Exception as e:
        return {"error": f"Compose error: {str(e)}"}


@tool
async def health_check(container_name: str, check_command: str = "curl -sf http://localhost/") -> dict:
    """Run a health check command inside a container.

    Args:
        container_name: Name or ID of the container
        check_command: Command to verify the service is running

    Returns:
        Health check result with pass/fail status.
    """
    client = _get_client()
    try:
        container = client.containers.get(container_name)
        exit_code, output = container.exec_run(check_command)
        return {
            "healthy": exit_code == 0,
            "exit_code": exit_code,
            "output": output.decode("utf-8", errors="replace")[:1000],
        }
    except Exception as e:
        return {"error": f"Health check error: {str(e)}"}


@tool
async def insert_flag(container_name: str, flag_location: str, flag_value: str) -> dict:
    """Insert a secret flag into the target container.

    Args:
        container_name: Name or ID of the container
        flag_location: File path or instruction for where to place the flag
        flag_value: The flag string to insert

    Returns:
        Confirmation of flag insertion.
    """
    client = _get_client()
    try:
        container = client.containers.get(container_name)

        if flag_location.startswith("http"):
            # SSRF-type: flag goes in an internal service (handled by compose)
            return {"status": "flag_in_service", "location": flag_location}

        if "database" in flag_location.lower() or "INSERT" in flag_location:
            # SQL-type: flag goes in a database record
            # This requires DB-specific insertion handled by the compose setup
            return {"status": "flag_in_database", "instruction": flag_location}

        # Default: write flag to a file in the container
        exit_code, _ = container.exec_run(
            f"sh -c 'mkdir -p $(dirname {flag_location}) && echo {flag_value} > {flag_location}'"
        )
        return {
            "status": "inserted" if exit_code == 0 else "failed",
            "location": flag_location,
            "exit_code": exit_code,
        }
    except Exception as e:
        return {"error": f"Flag insertion error: {str(e)}"}


async def cleanup_environment(project_name: str) -> dict[str, Any]:
    """Tear down all containers and networks for a CVE run."""
    try:
        import subprocess

        result = subprocess.run(
            ["docker", "compose", "-p", project_name, "down", "-v", "--remove-orphans"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "status": "cleaned" if result.returncode == 0 else "error",
            "output": result.stdout + result.stderr,
        }
    except Exception as e:
        return {"error": f"Cleanup error: {str(e)}"}
