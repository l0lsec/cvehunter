"""Docker operations for building and managing exploit test environments.

Uses the Docker SDK for Python to manage containers, images, and networks.
All exploit environments run in isolated Docker networks with no internet access.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import docker
from langchain_core.tools import tool

from cvehunter.config import settings
from cvehunter.tools import tool_failure, tool_success


def _get_client() -> docker.DockerClient:
    return docker.DockerClient(base_url=settings.docker_host)


@tool
async def build_image(dockerfile_content: str, tag: str) -> dict:
    """Build a Docker image from a Dockerfile string.

    Args:
        dockerfile_content: The full Dockerfile content
        tag: Image tag (e.g., 'cvehunter-vuln-cve-2024-12345')

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
            return tool_success({
                "image_id": image.id,
                "tag": tag,
                "logs": "".join(logs)[-2000:],
            })
    except docker.errors.BuildError as e:
        return tool_failure(f"Docker build failed: {str(e)}")
    except Exception as e:
        return tool_failure(f"Docker error: {str(e)}")


def _query_compose_containers(project_name: str) -> list[dict[str, str]]:
    """Get container names, IDs, and status for a compose project."""
    try:
        result = subprocess.run(
            ["docker", "compose", "-p", project_name, "ps", "--format", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return []
        containers = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            try:
                entry = json.loads(line)
                containers.append({
                    "name": entry.get("Name", ""),
                    "id": entry.get("ID", ""),
                    "status": entry.get("State", entry.get("Status", "")),
                    "service": entry.get("Service", ""),
                })
            except json.JSONDecodeError:
                continue
        return containers
    except Exception:
        return []


def _query_compose_network(project_name: str) -> str:
    """Get the primary Docker network name for a compose project."""
    try:
        result = subprocess.run(
            [
                "docker", "network", "ls",
                "--filter", f"name={project_name}",
                "--format", "{{.Name}}",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return f"{project_name}_default"


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

            result = subprocess.run(
                ["docker", "compose", "-f", str(compose_path), "-p", project_name, "up", "-d"],
                capture_output=True,
                text=True,
                timeout=settings.compose_up_timeout_seconds,
            )

            if result.returncode != 0:
                return tool_failure(f"Compose up failed: {result.stderr}")

            containers = _query_compose_containers(project_name)
            network_name = _query_compose_network(project_name)

            return tool_success({
                "project_name": project_name,
                "stdout": result.stdout,
                "status": "running",
                "containers": containers,
                "network_name": network_name,
            })
    except Exception as e:
        return tool_failure(f"Compose error: {str(e)}")


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
        return tool_success({
            "healthy": exit_code == 0,
            "exit_code": exit_code,
            "output": output.decode("utf-8", errors="replace")[:1000],
        })
    except Exception as e:
        return tool_failure(f"Health check error: {str(e)}")


def _write_file_to_container(
    container: Any, path: str, content: str,
) -> dict[str, Any]:
    """Write a file into a container via put_archive (no shell injection risk)."""
    dirname = os.path.dirname(path) or "/"
    basename = os.path.basename(path)

    container.exec_run(["mkdir", "-p", dirname])

    tar_stream = io.BytesIO()
    data = content.encode("utf-8")
    info = tarfile.TarInfo(name=basename)
    info.size = len(data)
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        tar.addfile(info, io.BytesIO(data))
    tar_stream.seek(0)

    ok = container.put_archive(dirname, tar_stream)
    if ok:
        return tool_success({"status": "inserted", "location": path})
    return tool_failure("put_archive returned False", status="failed", location=path)


def _detect_db_type(container: Any) -> str | None:
    """Infer DB engine from a container's image tags."""
    tags = container.image.tags if container.image.tags else []
    image_name = tags[0].lower() if tags else ""
    for db in ("postgres", "mysql", "mariadb", "mongo"):
        if db in image_name:
            return db
    return None


_DB_INSERT_COMMANDS: dict[str, str] = {
    "postgres": (
        "psql -U postgres -c "
        "\"CREATE TABLE IF NOT EXISTS flags(val TEXT); "
        "INSERT INTO flags VALUES('{flag}');\""
    ),
    "mysql": (
        "mysql -u root -e "
        "\"CREATE DATABASE IF NOT EXISTS test; "
        "CREATE TABLE IF NOT EXISTS test.flags(val TEXT); "
        "INSERT INTO test.flags VALUES('{flag}');\""
    ),
    "mariadb": (
        "mysql -u root -e "
        "\"CREATE DATABASE IF NOT EXISTS test; "
        "CREATE TABLE IF NOT EXISTS test.flags(val TEXT); "
        "INSERT INTO test.flags VALUES('{flag}');\""
    ),
    "mongo": "mongosh --eval \"db.flags.insertOne({{val: '{flag}'}})\"",
}


def _insert_flag_into_db(
    client: docker.DockerClient,
    project_name: str,
    flag_value: str,
) -> dict[str, Any]:
    """Detect DB containers in the project and insert the flag via SQL/command."""
    safe_flag = flag_value.replace("'", "''")

    for container in client.containers.list(
        filters={"label": f"com.docker.compose.project={project_name}"}
    ):
        db_type = _detect_db_type(container)
        if db_type is None:
            continue

        cmd_template = _DB_INSERT_COMMANDS[db_type]
        cmd = cmd_template.replace("{flag}", safe_flag)

        exit_code, output = container.exec_run(["sh", "-c", cmd])
        info = {
            "status": "inserted" if exit_code == 0 else "failed",
            "db_type": db_type,
            "container": container.name,
            "exit_code": exit_code,
            "output": output.decode("utf-8", errors="replace")[:500],
        }
        if exit_code == 0:
            return tool_success(info)
        return tool_failure(f"DB insert failed (exit {exit_code})", **info)

    return tool_failure("No recognised database container found", status="failed")


@tool
async def insert_flag(
    container_name: str,
    flag_location: str,
    flag_value: str,
    project_name: str = "",
) -> dict:
    """Insert a secret flag into the target container.

    Args:
        container_name: Name or ID of the container
        flag_location: File path or instruction for where to place the flag
        flag_value: The flag string to insert
        project_name: Compose project name (needed for database flag insertion)

    Returns:
        Confirmation of flag insertion.
    """
    client = _get_client()
    try:
        container = client.containers.get(container_name)

        if flag_location.startswith("http"):
            return tool_success({"status": "flag_in_service", "location": flag_location})

        if "database" in flag_location.lower() or "INSERT" in flag_location:
            return _insert_flag_into_db(client, project_name, flag_value)

        return _write_file_to_container(container, flag_location, flag_value)

    except Exception as e:
        return tool_failure(f"Flag insertion error: {str(e)}")


async def verify_network_isolation(network_name: str) -> dict[str, Any]:
    """Verify that a Docker network blocks outbound internet access.

    Checks the network's Internal flag and optionally probes for connectivity
    using a lightweight container.
    """
    client = _get_client()
    try:
        network = client.networks.get(network_name)
        is_internal = network.attrs.get("Internal", False)

        if not is_internal:
            return tool_failure(
                f"Network '{network_name}' is not marked as internal — "
                "exploit containers may have internet access",
                network=network_name,
                internal=False,
                probe_passed=None,
            )

        probe_passed = True
        try:
            container = client.containers.run(
                "alpine:3.20",
                command="wget -q --spider --timeout=3 http://1.1.1.1",
                network=network_name,
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
            )
            probe_passed = False
        except docker.errors.ContainerError:
            probe_passed = True
        except Exception:
            probe_passed = True

        if not probe_passed:
            return tool_failure(
                f"Network '{network_name}' is internal but outbound probe succeeded — "
                "isolation may be compromised",
                network=network_name,
                internal=True,
                probe_passed=False,
            )

        return tool_success({
            "network": network_name,
            "internal": True,
            "probe_passed": True,
            "status": "isolated",
        })

    except docker.errors.NotFound:
        return tool_failure(
            f"Network '{network_name}' not found", network=network_name
        )
    except Exception as e:
        return tool_failure(f"Network isolation check error: {e}")


async def cleanup_environment(project_name: str) -> dict[str, Any]:
    """Tear down all containers and networks for a CVE run."""
    try:
        result = subprocess.run(
            ["docker", "compose", "-p", project_name, "down", "-v", "--remove-orphans"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout + result.stderr
        if result.returncode == 0:
            return tool_success({"status": "cleaned", "output": output})
        return tool_failure(f"Cleanup failed (exit {result.returncode})", output=output)
    except Exception as e:
        return tool_failure(f"Cleanup error: {str(e)}")
