import logging
import sys
from pathlib import Path
from typing import Any, Optional

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars


def configure_logging(
    level: int = logging.INFO, log_file: Optional[str] = None
) -> None:
    """Configures JSON structured logging for console and optional file output."""
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        log_path = Path(log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=handlers,
        force=True,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Returns a shared structured logger."""
    return structlog.get_logger(name)


def bind_scan_context(
    scan_id: str,
    aws_account_id: str,
    **extra: Any,
) -> None:
    """Binds scan-scoped fields that propagate across asyncio tasks."""
    bind_contextvars(
        scan_id=scan_id,
        aws_account_id=aws_account_id,
        **extra,
    )


def clear_logging_context() -> None:
    """Clears scan-scoped logging context."""
    clear_contextvars()
