"""Sandboxed exploit execution environment.

Runs exploit scripts in isolated containers with no host access.
The exploit container can only reach the target Docker network.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import docker

from cvehunter.config import settings


def _get_client() -> docker.DockerClient:
    return docker.DockerClient(base_url=settings.docker_host)


async def run_exploit(
    exploit_code: str,
    target_network: str,
    timeout_seconds: int = 60,
    container_name: str = "",
) -> dict[str, Any]:
    """Execute exploit code in a sandboxed container.

    The exploit runs in a minimal Python container connected only to the
    target's Docker network. It has no internet access and no host mounts.

    Args:
        exploit_code: Python script content to execute
        target_network: Docker network name to connect the exploit container to
        timeout_seconds: Maximum execution time before killing the container
        container_name: Optional CVE-based name for the sandbox container
            (e.g. ``cve-2021-44228-exploit-a3f2``). If empty, Docker assigns
            a random name.

    Returns:
        stdout, stderr, and exit code from the exploit execution.
    """
    client = _get_client()

    with tempfile.TemporaryDirectory() as tmpdir:
        exploit_path = Path(tmpdir) / "exploit.py"
        exploit_path.write_text(exploit_code)

        try:
            container = client.containers.run(
                image="python:3.12-slim",
                command=["python", "/exploit/exploit.py"],
                volumes={tmpdir: {"bind": "/exploit", "mode": "ro"}},
                network=target_network,
                detach=True,
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,  # 50% of one CPU
                read_only=True,
                tmpfs={"/tmp": "size=100m"},
                security_opt=["no-new-privileges"],
                name=container_name or None,
            )

            try:
                result = container.wait(timeout=timeout_seconds)
                stdout = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
                stderr = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )

                return {
                    "exit_code": result.get("StatusCode", -1),
                    "stdout": stdout[:5000],
                    "stderr": stderr[:5000],
                }
            except Exception:
                container.kill()
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Exploit timed out after {timeout_seconds}s",
                }
            finally:
                container.remove(force=True)

        except docker.errors.ImageNotFound:
            client.images.pull("python:3.12-slim")
            return await run_exploit(
                exploit_code, target_network, timeout_seconds, container_name
            )
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Sandbox error: {str(e)}",
            }


async def run_against_patched(
    exploit_code: str,
    patched_network: str,
    timeout_seconds: int = 60,
    container_name: str = "",
) -> dict[str, Any]:
    """Run the exploit against the patched environment (should fail).

    Same as run_exploit but against the patched version. A successful
    exploitation here means the exploit is not targeting the actual vulnerability.
    """
    return await run_exploit(
        exploit_code, patched_network, timeout_seconds, container_name
    )
