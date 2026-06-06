"""API key authentication for the CVEHunter API."""

from __future__ import annotations

from fastapi import Security
from fastapi.security import APIKeyHeader

from cvehunter.api.errors import HTTP_STATUS_MAP, ErrorCode, ErrorResponse
from cvehunter.config import settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    key: str | None = Security(_api_key_header),
) -> None:
    """Dependency that enforces API key auth when ``CVEHUNTER_API_KEY`` is configured."""
    if not settings.api_key:
        return
    if not key or key != settings.api_key:
        from fastapi import HTTPException

        err = ErrorResponse.from_code(ErrorCode.API_KEY_MISSING, "Invalid or missing API key")
        raise HTTPException(
            status_code=HTTP_STATUS_MAP[ErrorCode.API_KEY_MISSING],
            detail=err.model_dump(mode="json"),
        )
