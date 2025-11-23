"""Logging configuration for lematt using loguru.

This module provides centralized logging setup with loguru's enhanced
formatting, structured output, and better defaults.
"""

import sys

from loguru import logger

# Remove default handler - we'll configure our own
logger.remove()

# Export the configured logger
__all__ = ["logger", "setup_logging"]


def setup_logging(
    *,
    verbose: bool = False,
    cron: bool = False,
    test_mode: bool = False,
) -> None:
    """Configure loguru logging for lematt.

    Args:
        verbose: Enable debug-level logging.
        cron: Minimize output (only warnings and errors).
        test_mode: Add [TEST] prefix to all messages.
    """
    # Remove any existing handlers
    logger.remove()

    # Determine log level
    if cron:
        level = "WARNING"
    elif verbose:
        level = "DEBUG"
    else:
        level = "INFO"

    # Build format string
    if cron:
        # Simpler format for cron logs
        fmt = "{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {message}"
    else:
        # Interactive format with colors
        if test_mode:
            fmt = "<yellow>[TEST]</yellow> <level>{message}</level>"
        else:
            fmt = "<level>{message}</level>"

    # Add console handler
    logger.add(
        sys.stderr,
        format=fmt,
        level=level,
        colorize=not cron,
        backtrace=verbose,
        diagnose=verbose,
    )


def log_certificate_status(
    domain: str,
    key_type: str,
    status: str,
    *,
    days_remaining: int | None = None,
    error: str | None = None,
) -> None:
    """Log certificate status with structured data.

    Args:
        domain: Domain name.
        key_type: Key type (RSA/EC).
        status: Status string.
        days_remaining: Days until expiration.
        error: Error message if any.
    """
    extra = {
        "domain": domain,
        "key_type": key_type,
        "status": status,
    }
    if days_remaining is not None:
        extra["days_remaining"] = days_remaining
    if error:
        extra["error"] = error

    with logger.contextualize(**extra):
        if error:
            logger.error(f"[{key_type}] {domain}: {status} - {error}")
        elif days_remaining is not None and days_remaining < 7:
            logger.warning(f"[{key_type}] {domain}: {status} ({days_remaining} days)")
        else:
            logger.info(f"[{key_type}] {domain}: {status}")


def log_progress(
    completed: int,
    total: int,
    succeeded: int,
    failed: int,
) -> None:
    """Log batch processing progress.

    Args:
        completed: Number of completed tasks.
        total: Total number of tasks.
        succeeded: Number of successful tasks.
        failed: Number of failed tasks.
    """
    percent = (completed / total * 100) if total > 0 else 100
    logger.info(
        f"Progress: {completed}/{total} ({percent:.1f}%) - "
        f"Success: {succeeded}, Failed: {failed}"
    )
