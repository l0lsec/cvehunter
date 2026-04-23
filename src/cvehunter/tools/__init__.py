"""Tool implementations for CVEHunter agents."""

from __future__ import annotations

from typing import Any


class ToolError(Exception):
    """Raised when a tool encounters a recoverable error."""

    def __init__(
        self,
        message: str,
        tool_name: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.details = details or {}


def tool_success(data: dict[str, Any]) -> dict[str, Any]:
    """Wrap a successful tool result with ``success=True``."""
    return {"success": True, **data}


def tool_failure(error: str, **extra: Any) -> dict[str, Any]:
    """Wrap a failed tool result with ``success=False``."""
    return {"success": False, "error": error, **extra}
