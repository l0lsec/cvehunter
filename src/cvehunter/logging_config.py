"""Structured logging configuration for the CVEHunter pipeline.

Uses structlog for JSON-formatted (production) or pretty console (development)
output. Log files are written per-CVE to the artifact directory.
"""

from __future__ import annotations

import logging
import os
import sys

import structlog

from cvehunter.config import settings

_configured = False


def setup_logging(cve_id: str | None = None) -> None:
    """Initialise structured logging for the application.

    Args:
        cve_id: When provided, also writes logs to
                ``{artifact_dir}/{cve_id}/pipeline.log``.
    """
    global _configured  # noqa: PLW0603

    log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    console_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    json_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    root = logging.getLogger()
    if _configured:
        root.handlers.clear()

    root.setLevel(log_level)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(console_formatter)
    root.addHandler(console_handler)

    if cve_id:
        log_dir = settings.artifact_dir / cve_id
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "pipeline.log", mode="a")
        file_handler.setFormatter(json_formatter)
        root.addHandler(file_handler)

    _httpx_logger = logging.getLogger("httpx")
    _httpx_logger.setLevel(logging.WARNING)
    _httpcore_logger = logging.getLogger("httpcore")
    _httpcore_logger.setLevel(logging.WARNING)

    _configured = True
