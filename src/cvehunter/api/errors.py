"""Structured error codes and responses for the CVEHunter API."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ErrorCode(StrEnum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    CVE_ALREADY_RUNNING = "CVE_ALREADY_RUNNING"
    RUN_NOT_RUNNING = "RUN_NOT_RUNNING"
    RUN_NOT_RETRYABLE = "RUN_NOT_RETRYABLE"
    API_KEY_MISSING = "API_KEY_MISSING"
    PIPELINE_FAILED = "PIPELINE_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


HTTP_STATUS_MAP: dict[ErrorCode, int] = {
    ErrorCode.VALIDATION_ERROR: 422,
    ErrorCode.RUN_NOT_FOUND: 404,
    ErrorCode.CVE_ALREADY_RUNNING: 409,
    ErrorCode.RUN_NOT_RUNNING: 409,
    ErrorCode.RUN_NOT_RETRYABLE: 409,
    ErrorCode.API_KEY_MISSING: 401,
    ErrorCode.PIPELINE_FAILED: 500,
    ErrorCode.INTERNAL_ERROR: 500,
}


class ErrorResponse(BaseModel):
    error_code: str
    detail: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_code(cls, code: ErrorCode, detail: str) -> ErrorResponse:
        return cls(error_code=code.value, detail=detail)
