"""Interactive dashboard for certificate monitoring.

This module provides the Textual-based interactive dashboard for real-time
certificate health monitoring. It replaces the legacy Rich-based implementation
with a fully interactive TUI supporting keyboard/mouse input, filtering, search,
and drill-down views.

For backwards compatibility, this module re-exports the main dashboard components
and provides simple implementations of legacy utility functions.
"""

from datetime import datetime
from enum import Enum, auto

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel

# Re-export Textual dashboard components
from lematt.tui.app import DashboardConfig, LemattDashboardApp

# For backwards compatibility
Dashboard = LemattDashboardApp


class DashboardView(Enum):
    """Dashboard view types (for backwards compatibility)."""

    OVERVIEW = auto()
    CERTIFICATES = auto()
    HEALTH = auto()
    LOGS = auto()


class DashboardState:
    """Dashboard state (legacy compatibility class).

    This class is maintained for backwards compatibility but is no longer
    used by the Textual dashboard. The new dashboard uses Textual's reactive
    state management system instead.
    """

    def __init__(self) -> None:
        """Initialize empty dashboard state."""
        self.current_view = DashboardView.OVERVIEW
        self.certificates: list[dict] = []
        self.health_data = None
        self.log_lines: list[str] = []
        self.is_paused = False
        self.error_message: str | None = None
        self.last_update: datetime | None = None


console = Console()


def create_simple_dashboard(
    certificates: list[dict],
    health_data: dict | None = None,
) -> Layout:
    """Create a simple dashboard layout without interactivity.

    This is a simplified implementation that creates a basic Rich layout
    for one-time display in CLI commands.

    Args:
        certificates: List of certificate status dicts.
        health_data: Optional health summary dict.

    Returns:
        Rich Layout object for display.
    """
    from lematt.display import create_certificate_table, create_health_summary
    from lematt.health import CertificateHealth, HealthStatus, SystemHealth

    layout = Layout()
    layout.split_row(
        Layout(name="main", ratio=3),
        Layout(name="sidebar", ratio=1),
    )

    # Convert certificates to table
    if certificates:
        # Convert dicts to CertificateHealth objects
        cert_healths = []
        for cert in certificates:
            cert_healths.append(
                CertificateHealth(
                    domain=cert.get("domain", "unknown"),
                    key_type=cert.get("key_type", "unknown"),
                    status=HealthStatus[cert.get("status", "UNKNOWN").upper()],
                    message=cert.get("message", ""),
                    days_until_expiry=cert.get("days_until_expiry"),
                )
            )

        table = create_certificate_table(cert_healths)
        layout["main"].update(Panel(table, title="Certificates"))
    else:
        layout["main"].update(Panel("No certificates", title="Certificates"))

    # Show health summary in sidebar
    if health_data:
        cert_healths = []
        for cert_dict in health_data.get("certificates", []):
            cert_healths.append(
                CertificateHealth(
                    domain=cert_dict.get("domain", "unknown"),
                    key_type=cert_dict.get("key_type", "unknown"),
                    status=HealthStatus[cert_dict.get("status", "UNKNOWN").upper()],
                    message=cert_dict.get("message", ""),
                    days_until_expiry=cert_dict.get("days_until_expiry"),
                )
            )

        health = SystemHealth(
            status=HealthStatus[health_data.get("status", "UNKNOWN").upper()],
            certificates=cert_healths,
            summary=health_data.get("summary", ""),
        )
        layout["sidebar"].update(create_health_summary(health))
    else:
        layout["sidebar"].update(Panel("No health data", title="Status"))

    return layout


def print_dashboard_snapshot(
    certificates: list[dict],
    health_data: dict | None = None,
) -> None:
    """Print a static dashboard snapshot to the console.

    Args:
        certificates: List of certificate status dicts.
        health_data: Optional health summary dict.
    """
    layout = create_simple_dashboard(certificates, health_data)
    console.print(layout)


__all__ = [
    "Dashboard",
    "DashboardConfig",
    "DashboardState",
    "DashboardView",
    "LemattDashboardApp",
    "create_simple_dashboard",
    "print_dashboard_snapshot",
]
