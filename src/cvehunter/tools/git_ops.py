"""Git operations tool — clone repos and extract diffs when the API route fails."""

from __future__ import annotations

import asyncio
import shutil
import tempfile

from langchain_core.tools import tool

from cvehunter.tools import tool_failure, tool_success
from cvehunter.tools.url_validation import validate_url

_CLONE_TIMEOUT = 60
_MAX_DIFF_LENGTH = 10000


@tool
async def git_clone_and_diff(repo_url: str, commit_sha: str) -> dict:
    """Clone a git repository and extract the diff for a specific commit.

    Use this as a fallback when get_commit_diff fails (e.g., non-GitHub repos,
    GitLab repos, or when the GitHub API diff endpoint is unavailable).

    Args:
        repo_url: The git clone URL (https://...).
        commit_sha: The commit hash to extract the diff for.
    """
    if not validate_url(repo_url):
        return tool_failure(f"URL not in allowed domains: {repo_url}")

    tmpdir = tempfile.mkdtemp(prefix="cvehunter-git-")
    try:
        clone_proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "50", "--single-branch", repo_url, tmpdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, clone_stderr = await asyncio.wait_for(
            clone_proc.communicate(), timeout=_CLONE_TIMEOUT
        )
        if clone_proc.returncode != 0:
            return tool_failure(f"git clone failed: {clone_stderr.decode()[:2000]}")

        diff_proc = await asyncio.create_subprocess_exec(
            "git", "-C", tmpdir, "diff", f"{commit_sha}~1..{commit_sha}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        diff_stdout, diff_stderr = await asyncio.wait_for(
            diff_proc.communicate(), timeout=30
        )
        if diff_proc.returncode != 0:
            return tool_failure(f"git diff failed: {diff_stderr.decode()[:2000]}")

        log_proc = await asyncio.create_subprocess_exec(
            "git", "-C", tmpdir, "log", "-1", "--format=%s", commit_sha,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        log_stdout, _ = await asyncio.wait_for(log_proc.communicate(), timeout=10)

        diff_text = diff_stdout.decode(errors="replace")
        if len(diff_text) > _MAX_DIFF_LENGTH:
            diff_text = diff_text[:_MAX_DIFF_LENGTH] + "\n... [truncated]"

        return tool_success({
            "diff": diff_text,
            "commit_message": log_stdout.decode(errors="replace").strip(),
            "repo_url": repo_url,
            "commit_sha": commit_sha,
        })

    except asyncio.TimeoutError:
        return tool_failure("git operation timed out")
    except Exception as e:
        return tool_failure(f"git operation failed: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
