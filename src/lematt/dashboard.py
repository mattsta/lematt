"""Interactive dashboard for real-time certificate monitoring.

This module provides a live-updating terminal dashboard that displays
certificate status, health metrics, and system information with auto-refresh.
"""

import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .display import (
    DisplayConfig,
    StatusStyle,
    console,
    create_certificate_table,
    create_health_summary,
)
from .health import HealthChecker, HealthStatus, SystemHealth


class DashboardView(Enum):
    """Available dashboard views."""

    OVERVIEW = auto()
    CERTIFICATES = auto()
    HEALTH = auto()
    LOGS = auto()


@dataclass
class DashboardConfig:
    """Configuration for the interactive dashboard."""

    refresh_interval: float = 5.0  # Seconds between updates
    show_header: bool = True
    show_footer: bool = True
    show_sidebar: bool = True
    max_log_lines: int = 20
    compact_mode: bool = False
    auto_refresh: bool = True


@dataclass
class DashboardState:
    """Mutable state for the dashboard."""

    current_view: DashboardView = DashboardView.OVERVIEW
    last_update: datetime | None = None
    health_data: SystemHealth | None = None
    certificates: list[dict] = field(default_factory=list)
    log_lines: list[str] = field(default_factory=list)
    is_paused: bool = False
    error_message: str | None = None

    def add_log(self, message: str) -> None:
        """Add a log line with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_lines.append(f"[dim]{timestamp}[/dim] {message}")
        # Keep only recent logs
        if len(self.log_lines) > 100:
            self.log_lines = self.log_lines[-100:]


class DashboardRenderer:
    """Renders dashboard components."""

    def __init__(self, config: DashboardConfig):
        self.config = config
        self.display_config = DisplayConfig(compact=config.compact_mode)

    def render_header(self, state: DashboardState) -> Panel:
        """Render the dashboard header."""
        title = Text()
        title.append("lematt", style="bold cyan")
        title.append(" Dashboard", style="bold")

        status = Text()
        if state.is_paused:
            status.append(" PAUSED ", style="bold yellow on dark_yellow")
        elif state.error_message:
            status.append(" ERROR ", style="bold white on red")
        else:
            status.append(" LIVE ", style="bold white on green")

        if state.last_update:
            status.append(
                f"  Last update: {state.last_update.strftime('%H:%M:%S')}", style="dim"
            )

        header_content = Group(title, status)
        return Panel(header_content, style="cyan", height=4)

    def render_footer(self, state: DashboardState) -> Panel:
        """Render the dashboard footer with keybindings."""
        keys = Text()
        keys.append(" [q] ", style="bold cyan")
        keys.append("Quit")
        keys.append("  [r] ", style="bold cyan")
        keys.append("Refresh")
        keys.append("  [p] ", style="bold cyan")
        keys.append("Pause" if not state.is_paused else "Resume")
        keys.append("  [1-4] ", style="bold cyan")
        keys.append("Switch View")
        keys.append("  [c] ", style="bold cyan")
        keys.append("Compact")

        view_indicator = Text()
        view_indicator.append("View: ", style="dim")
        for view in DashboardView:
            if view == state.current_view:
                view_indicator.append(f" {view.name} ", style="bold white on blue")
            else:
                view_indicator.append(f" {view.name} ", style="dim")

        footer_content = Group(keys, view_indicator)
        return Panel(footer_content, style="bright_black", height=4)

    def render_sidebar(self, state: DashboardState) -> Panel:
        """Render the status sidebar."""
        content = Text()

        # System status
        content.append("System Status\n", style="bold underline")
        if state.health_data:
            icon = StatusStyle.get_icon(str(state.health_data.status))
            style = StatusStyle.get_style(str(state.health_data.status))
            content.append(f"{icon} {state.health_data.status.name}\n", style=style)
        else:
            content.append("? Unknown\n", style=StatusStyle.UNKNOWN)

        content.append("\n")

        # Certificate counts
        content.append("Certificates\n", style="bold underline")
        if state.health_data:
            h = state.health_data
            content.append(f"  {StatusStyle.ICONS['healthy']} Healthy: ", style="dim")
            content.append(f"{h.healthy_count}\n", style=StatusStyle.HEALTHY)
            content.append(f"  {StatusStyle.ICONS['warning']} Warning: ", style="dim")
            content.append(f"{h.warning_count}\n", style=StatusStyle.WARNING)
            content.append(f"  {StatusStyle.ICONS['critical']} Critical: ", style="dim")
            content.append(f"{h.critical_count}\n", style=StatusStyle.CRITICAL)
            content.append(f"  {StatusStyle.ICONS['unknown']} Unknown: ", style="dim")
            content.append(f"{h.unknown_count}\n", style=StatusStyle.MUTED)
        else:
            content.append("  No data\n", style="dim")

        content.append("\n")

        # Refresh info
        content.append("Auto-refresh\n", style="bold underline")
        if state.is_paused:
            content.append("  Paused\n", style="yellow")
        else:
            content.append(f"  Every {self.config.refresh_interval}s\n", style="dim")

        return Panel(content, title="[bold]Status[/bold]", border_style="bright_black")

    def render_overview(self, state: DashboardState) -> Panel:
        """Render the overview panel."""
        if not state.health_data:
            return Panel(
                "[dim]Loading health data...[/dim]",
                title="[bold]Overview[/bold]",
            )

        # Create health summary
        health_dict = state.health_data.to_dict()
        summary_panel = create_health_summary(health_dict, self.display_config)

        # Create quick stats table
        stats = Table(show_header=False, box=None, padding=(0, 2))
        stats.add_column("Metric", style="dim")
        stats.add_column("Value", style="bold")

        total = len(state.health_data.certificates)
        stats.add_row("Total Certificates", str(total))

        # Find soonest expiry
        soonest = None
        soonest_domain = None
        for cert in state.health_data.certificates:
            if cert.days_until_expiry is not None:
                if soonest is None or cert.days_until_expiry < soonest:
                    soonest = cert.days_until_expiry
                    soonest_domain = cert.domain

        if soonest is not None:
            style = StatusStyle.get_style(
                "critical" if soonest < 7 else "warning" if soonest < 14 else "healthy"
            )
            stats.add_row(
                "Soonest Expiry",
                Text(f"{soonest} days ({soonest_domain})", style=style),
            )

        content = Group(summary_panel, Text(), stats)
        return Panel(content, title="[bold]Overview[/bold]", border_style="cyan")

    def render_certificates(self, state: DashboardState) -> Panel:
        """Render the certificates panel."""
        if not state.certificates:
            return Panel(
                "[dim]No certificate data available[/dim]",
                title="[bold]Certificates[/bold]",
            )

        table = create_certificate_table(
            state.certificates,
            title="",
            config=self.display_config,
        )

        return Panel(table, title="[bold]Certificates[/bold]", border_style="cyan")

    def render_health(self, state: DashboardState) -> Panel:
        """Render the health details panel."""
        if not state.health_data:
            return Panel(
                "[dim]Loading health data...[/dim]",
                title="[bold]Health Details[/bold]",
            )

        # Detailed health table
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="bright_black",
            expand=True,
        )
        table.add_column("Domain", style="bold")
        table.add_column("Type", justify="center", width=6)
        table.add_column("Status", justify="center", width=10)
        table.add_column("Days", justify="right", width=6)
        table.add_column("Message", overflow="fold")
        table.add_column("Issuer", style="dim", overflow="ellipsis")

        for cert in state.health_data.certificates:
            icon = StatusStyle.get_icon(str(cert.status))
            style = StatusStyle.get_style(str(cert.status))

            days_text = Text()
            if cert.days_until_expiry is not None:
                days_style = (
                    StatusStyle.CRITICAL
                    if cert.days_until_expiry < 7
                    else StatusStyle.WARNING
                    if cert.days_until_expiry < 14
                    else StatusStyle.HEALTHY
                )
                days_text = Text(str(cert.days_until_expiry), style=days_style)
            else:
                days_text = Text("-", style=StatusStyle.MUTED)

            table.add_row(
                cert.domain,
                cert.key_type,
                Text(f"{icon} {cert.status.name}", style=style),
                days_text,
                cert.message,
                cert.issuer or "-",
            )

        return Panel(table, title="[bold]Health Details[/bold]", border_style="cyan")

    def render_logs(self, state: DashboardState) -> Panel:
        """Render the log panel."""
        if not state.log_lines:
            return Panel(
                "[dim]No log entries yet[/dim]",
                title="[bold]Activity Log[/bold]",
            )

        # Show most recent logs
        visible_logs = state.log_lines[-self.config.max_log_lines :]
        log_content = Text("\n".join(visible_logs))

        return Panel(
            log_content,
            title="[bold]Activity Log[/bold]",
            border_style="cyan",
        )

    def render_error(self, state: DashboardState) -> Panel:
        """Render error message panel."""
        if not state.error_message:
            return Panel("")

        return Panel(
            Text(state.error_message, style="bold red"),
            title="[bold red]Error[/bold red]",
            border_style="red",
        )

    def create_layout(self, state: DashboardState) -> Layout:
        """Create the full dashboard layout."""
        layout = Layout()

        # Main structure
        if self.config.show_header and self.config.show_footer:
            layout.split_column(
                Layout(name="header", size=4),
                Layout(name="body"),
                Layout(name="footer", size=4),
            )
        elif self.config.show_header:
            layout.split_column(
                Layout(name="header", size=4),
                Layout(name="body"),
            )
        elif self.config.show_footer:
            layout.split_column(
                Layout(name="body"),
                Layout(name="footer", size=4),
            )
        else:
            layout.split_column(Layout(name="body"))

        # Header
        if self.config.show_header:
            layout["header"].update(self.render_header(state))

        # Footer
        if self.config.show_footer:
            layout["footer"].update(self.render_footer(state))

        # Body with optional sidebar
        if self.config.show_sidebar:
            layout["body"].split_row(
                Layout(name="sidebar", size=25),
                Layout(name="main"),
            )
            layout["sidebar"].update(self.render_sidebar(state))
        else:
            layout["body"].split_row(Layout(name="main"))

        # Main content based on current view
        main_content: Panel
        if state.error_message:
            main_content = self.render_error(state)
        elif state.current_view == DashboardView.OVERVIEW:
            main_content = self.render_overview(state)
        elif state.current_view == DashboardView.CERTIFICATES:
            main_content = self.render_certificates(state)
        elif state.current_view == DashboardView.HEALTH:
            main_content = self.render_health(state)
        elif state.current_view == DashboardView.LOGS:
            main_content = self.render_logs(state)
        else:
            main_content = self.render_overview(state)

        layout["main"].update(main_content)

        return layout


@dataclass
class Dashboard:
    """Interactive dashboard controller.

    Manages the dashboard lifecycle, input handling, and data updates.
    """

    config: DashboardConfig = field(default_factory=DashboardConfig)
    health_checker: HealthChecker | None = None
    data_provider: Callable[[], dict] | None = None

    _state: DashboardState = field(default_factory=DashboardState, init=False)
    _renderer: DashboardRenderer | None = field(default=None, init=False)
    _running: bool = field(default=False, init=False)
    _live: Live | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self._renderer = DashboardRenderer(self.config)

    def _refresh_data(self) -> None:
        """Refresh dashboard data from sources."""
        self._state.add_log("Refreshing data...")

        try:
            if self.health_checker:
                # Get health data
                domains = self.health_checker.config.domains
                key_types = [str(kt) for kt in self.health_checker.config.key_types]
                self._state.health_data = self.health_checker.check_all_certificates(
                    domains, key_types
                )

                # Convert to certificate dicts for display
                self._state.certificates = [
                    cert.to_dict() for cert in self._state.health_data.certificates
                ]

                self._state.add_log(
                    f"Health check complete: {self._state.health_data.summary}"
                )
                self._state.error_message = None

            elif self.data_provider:
                data = self.data_provider()
                if "health" in data:
                    self._state.health_data = data["health"]
                if "certificates" in data:
                    self._state.certificates = data["certificates"]
                self._state.add_log("Data refreshed from provider")
                self._state.error_message = None

            self._state.last_update = datetime.now()

        except Exception as e:
            self._state.error_message = f"Error refreshing data: {e}"
            self._state.add_log(f"[red]Error: {e}[/red]")

    def _handle_input(self, key: str) -> bool:
        """Handle keyboard input. Returns False to quit."""
        if key.lower() == "q":
            return False
        elif key.lower() == "r":
            self._state.is_paused = False
            self._refresh_data()
        elif key.lower() == "p":
            self._state.is_paused = not self._state.is_paused
            status = "paused" if self._state.is_paused else "resumed"
            self._state.add_log(f"Auto-refresh {status}")
        elif key.lower() == "c":
            self.config.compact_mode = not self.config.compact_mode
            self._renderer = DashboardRenderer(self.config)
            self._state.add_log(f"Compact mode: {self.config.compact_mode}")
        elif key == "1":
            self._state.current_view = DashboardView.OVERVIEW
        elif key == "2":
            self._state.current_view = DashboardView.CERTIFICATES
        elif key == "3":
            self._state.current_view = DashboardView.HEALTH
        elif key == "4":
            self._state.current_view = DashboardView.LOGS

        return True

    def run(self) -> None:
        """Run the interactive dashboard."""
        self._running = True
        self._state.add_log("Dashboard started")

        # Initial data load
        self._refresh_data()

        # Set up signal handlers
        original_sigint = signal.getsignal(signal.SIGINT)

        def handle_sigint(signum: int, frame: object) -> None:
            self._running = False

        signal.signal(signal.SIGINT, handle_sigint)

        try:
            with Live(
                self._renderer.create_layout(self._state),
                console=console,
                refresh_per_second=4,
                screen=True,
            ) as live:
                self._live = live
                last_refresh = time.time()

                while self._running:
                    # Check for auto-refresh
                    now = time.time()
                    if (
                        self.config.auto_refresh
                        and not self._state.is_paused
                        and now - last_refresh >= self.config.refresh_interval
                    ):
                        self._refresh_data()
                        last_refresh = now

                    # Update display
                    live.update(self._renderer.create_layout(self._state))

                    # Small sleep to prevent CPU spinning
                    time.sleep(0.1)

        finally:
            signal.signal(signal.SIGINT, original_sigint)
            self._running = False
            self._state.add_log("Dashboard stopped")

    def run_once(self) -> None:
        """Run the dashboard for a single refresh (non-interactive)."""
        self._refresh_data()
        console.print(self._renderer.create_layout(self._state))


def create_simple_dashboard(
    certificates: list[dict],
    health_data: dict | None = None,
) -> Layout:
    """Create a simple dashboard layout without interactivity.

    Useful for one-off display in CLI commands.

    Args:
        certificates: List of certificate status dicts
        health_data: Optional health summary dict

    Returns:
        Rich Layout object for display
    """
    config = DashboardConfig(
        show_header=False,
        show_footer=False,
        show_sidebar=True,
    )
    renderer = DashboardRenderer(config)

    state = DashboardState()
    state.certificates = certificates
    state.last_update = datetime.now()

    # Convert health_data dict to SystemHealth if provided
    if health_data:
        from .health import CertificateHealth, SystemHealth

        cert_healths = []
        for cert_dict in health_data.get("certificates", []):
            cert_healths.append(
                CertificateHealth(
                    domain=cert_dict.get("domain", "unknown"),
                    key_type=cert_dict.get("key_type", "unknown"),
                    status=HealthStatus[cert_dict.get("status", "unknown").upper()],
                    message=cert_dict.get("message", ""),
                    days_until_expiry=cert_dict.get("days_until_expiry"),
                )
            )

        state.health_data = SystemHealth(
            status=HealthStatus[health_data.get("status", "unknown").upper()],
            certificates=cert_healths,
            summary=health_data.get("summary", ""),
        )

    return renderer.create_layout(state)


def print_dashboard_snapshot(
    certificates: list[dict],
    health_data: dict | None = None,
) -> None:
    """Print a static dashboard snapshot to the console.

    Args:
        certificates: List of certificate status dicts
        health_data: Optional health summary dict
    """
    layout = create_simple_dashboard(certificates, health_data)
    console.print(layout)
