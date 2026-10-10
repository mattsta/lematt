"""Shared rich console and status styling for lematt's terminal output.

Reports and the help system render through ``console`` and style statuses
with ``StatusStyle`` so they look the same everywhere.
"""

from typing import ClassVar

from rich.console import Console
from rich.style import Style

# Shared console instance
console = Console()


# Status styles
class StatusStyle:
    """Consistent styling for status indicators."""

    HEALTHY = Style(color="green", bold=True)
    WARNING = Style(color="yellow", bold=True)
    CRITICAL = Style(color="red", bold=True)
    UNKNOWN = Style(color="bright_black")
    INFO = Style(color="cyan")
    MUTED = Style(color="bright_black")

    ICONS: ClassVar[dict[str, str]] = {
        "healthy": "✓",
        "warning": "⚠",
        "critical": "✗",
        "unknown": "?",
    }

    @classmethod
    def get_style(cls, status: str) -> Style:
        """Get style for a status string."""
        status_lower = status.lower()
        if status_lower in ("healthy", "ok", "success", "valid"):
            return cls.HEALTHY
        elif status_lower in ("warning", "warn", "expiring"):
            return cls.WARNING
        elif status_lower in ("critical", "error", "failure", "expired", "missing"):
            return cls.CRITICAL
        return cls.UNKNOWN

    @classmethod
    def get_icon(cls, status: str) -> str:
        """Get icon for a status string."""
        status_lower = status.lower()
        if status_lower in ("healthy", "ok", "success", "valid"):
            return cls.ICONS["healthy"]
        elif status_lower in ("warning", "warn", "expiring"):
            return cls.ICONS["warning"]
        elif status_lower in ("critical", "error", "failure", "expired", "missing"):
            return cls.ICONS["critical"]
        return cls.ICONS["unknown"]
