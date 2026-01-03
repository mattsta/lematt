"""Main Textual application for the interactive dashboard."""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from textual.app import App
from textual.binding import Binding
from textual.reactive import reactive

from lematt.config import DomainConfig
from lematt.health import HealthChecker, SystemHealth
from lematt.log import logger
from lematt.tui.screens import (
    CertificateDetailScreen,
    DashboardScreen,
)
from lematt.tui.widgets import CertificateTable, HealthTable, LogViewer, OverviewPanel


@dataclass
class DashboardConfig:
    """Configuration for the dashboard application.

    Attributes:
        refresh_interval: Seconds between auto-refreshes (default: 5.0).
        auto_refresh: Whether to enable auto-refresh (default: True).
        compact_mode: Whether to hide certificate paths (default: False).
        warning_days: Days before expiry to show warning (default: 14).
        critical_days: Days before expiry to show critical (default: 7).
    """

    refresh_interval: float = 5.0
    auto_refresh: bool = True
    compact_mode: bool = False
    warning_days: int = 14
    critical_days: int = 7


class LemattDashboardApp(App[None]):
    """Interactive Textual dashboard for certificate monitoring.

    Provides a fully interactive TUI with:
    - Real-time certificate health monitoring
    - Multiple views (Overview, Certificates, Health, Logs)
    - Interactive filtering and search
    - Certificate detail drill-down
    - Auto-refresh with pause/resume
    - Keyboard and mouse navigation

    Keybindings:
        q: Quit application
        r: Force refresh now
        p: Pause/resume auto-refresh
        c: Toggle compact mode
        1-4: Switch views
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True, priority=True),
        Binding("r", "refresh_now", "Refresh", show=True),
        Binding("p", "toggle_pause", "Pause", show=True),
    ]

    SCREENS = {"dashboard": DashboardScreen}

    CSS_PATH = Path(__file__).parent / "dashboard.css"

    # Reactive state - automatically triggers UI updates when changed
    health_data: reactive[SystemHealth | None] = reactive(None)
    is_paused: reactive[bool] = reactive(False)
    error_message: reactive[str | None] = reactive(None)
    last_update: reactive[datetime | None] = reactive(None)

    def __init__(
        self,
        health_checker: HealthChecker,
        domains: list[DomainConfig],
        config: DashboardConfig | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize the dashboard application.

        Args:
            health_checker: Health checker instance for certificate monitoring.
            domains: List of domain configurations to monitor.
            config: Dashboard configuration (uses defaults if None).
            **kwargs: Additional arguments passed to App.
        """
        super().__init__(**kwargs)
        self.health_checker = health_checker
        self.domains = domains
        self.config = config or DashboardConfig()

        self._refresh_timer = None

    def on_mount(self) -> None:
        """Set up the dashboard when the app starts."""
        # Push the main dashboard screen (defined in SCREENS)
        self.push_screen("dashboard")

        # Add log entry immediately
        self._add_log("Dashboard initialized")
        self._add_log(f"Monitoring {len(self.domains)} domains")
        self._add_log("Loading certificate data...")

        # Start auto-refresh timer
        if self.config.auto_refresh:
            self._refresh_timer = self.set_interval(
                self.config.refresh_interval,
                self._refresh_data_callback,
            )

        # Initial data load (non-blocking worker)
        self.run_worker(self._refresh_data(), exclusive=False)

    def watch_health_data(self, health: SystemHealth | None) -> None:
        """Update UI components when health data changes.

        This watcher is automatically called when the health_data reactive
        variable changes. It propagates the data to all relevant widgets.

        Args:
            health: The new health data.
        """
        if not health or not self.is_mounted:
            return

        # Check if we're on the dashboard screen
        if not isinstance(self.screen, DashboardScreen):
            return

        try:
            # Update header
            header = self.screen.query_one("#header")
            header.last_update = self.last_update
            header.error_message = self.error_message
            header.is_test = self.health_checker.config.is_test

            # Update sidebar
            sidebar = self.screen.query_one("#sidebar")
            sidebar.health_data = health
            sidebar.refresh_interval = self.config.refresh_interval

            # Update overview panel
            overview = self.screen.query_one(OverviewPanel)
            overview.health_data = health

            # Update certificate table
            cert_table = self.screen.query_one(CertificateTable)
            cert_table.certificates = health.certificates

            # Update health table
            health_table = self.screen.query_one(HealthTable)
            health_table.certificates = health.certificates

        except Exception as e:
            logger.error(f"Error updating widgets: {e}", exc_info=True)

    def watch_is_paused(self, paused: bool) -> None:
        """Update UI when pause state changes.

        Args:
            paused: Whether the dashboard is paused.
        """
        if not self.is_mounted:
            return

        # Check if we're on the dashboard screen
        if not isinstance(self.screen, DashboardScreen):
            return

        try:
            header = self.screen.query_one("#header")
            header.is_paused = paused

            # Add log entry
            status = "paused" if paused else "resumed"
            self._add_log(f"Auto-refresh {status}")
        except Exception:
            pass

    async def _refresh_data(self) -> None:
        """Refresh certificate health data asynchronously.

        Runs the health checker in a thread pool to avoid blocking the UI.
        Updates the reactive health_data variable which triggers UI updates.
        """
        if self.is_paused:
            return

        try:
            self._add_log("Refreshing certificate data...")

            # Run blocking health check in executor with timeout
            loop = asyncio.get_running_loop()

            try:
                health = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        self._run_health_check,
                    ),
                    timeout=30.0,  # 30 second timeout
                )
            except TimeoutError:
                self._add_log("[red]Health check timed out after 30 seconds[/red]")
                logger.error("Health check timed out")
                return

            # Update reactive state
            self.health_data = health
            self.last_update = datetime.now()
            self.error_message = None

            # Log summary
            if health:
                summary = (
                    f"Refresh complete: {health.healthy_count} healthy, "
                    f"{health.warning_count} warning, {health.critical_count} critical"
                )
                self._add_log(summary)

        except Exception as e:
            logger.error(f"Dashboard refresh error: {e}", exc_info=True)
            self.error_message = str(e)
            self._add_log(f"[red]Error refreshing data: {e}[/red]")

    def _run_health_check(self) -> SystemHealth:
        """Run the health check synchronously.

        This method is called from a thread pool executor.

        Returns:
            SystemHealth object with check results.
        """
        try:
            logger.debug(f"Starting health check for {len(self.domains)} domains")

            key_types = []

            # Determine which key types to check based on domains
            if self.domains:
                # Check both RSA and EC by default
                key_types = ["rsa", "ec"]

            logger.debug(f"Checking key types: {key_types}")
            result = self.health_checker.check_all_certificates(self.domains, key_types)
            logger.debug(
                f"Health check completed: {len(result.certificates)} certificates"
            )
            return result

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            # Return empty health data on error
            from lematt.health import HealthStatus, SystemHealth

            return SystemHealth(
                status=HealthStatus.UNKNOWN,
                certificates=[],
                summary=f"Error: {e}",
            )

    def _refresh_data_callback(self) -> None:
        """Callback for the refresh timer.

        Spawns an async worker to refresh data without blocking.
        """
        if not self.is_paused:
            self.run_worker(self._refresh_data())

    def action_quit(self) -> None:
        """Quit the application."""
        self._add_log("Shutting down dashboard...")
        self.exit()

    def action_refresh_now(self) -> None:
        """Force immediate refresh of certificate data."""
        self.is_paused = False
        self.run_worker(self._refresh_data())

    def action_toggle_pause(self) -> None:
        """Toggle pause state for auto-refresh."""
        self.is_paused = not self.is_paused

    def on_certificate_table_certificate_selected(
        self, message: CertificateTable.CertificateSelected
    ) -> None:
        """Handle certificate selection from certificate table.

        Opens the detail screen for the selected certificate.

        Args:
            message: Message containing the selected certificate.
        """
        self.push_screen(CertificateDetailScreen(message.certificate))

    def on_health_table_certificate_selected(
        self, message: HealthTable.CertificateSelected
    ) -> None:
        """Handle certificate selection from health table.

        Opens the detail screen for the selected certificate.

        Args:
            message: Message containing the selected certificate.
        """
        self.push_screen(CertificateDetailScreen(message.certificate))

    def _add_log(self, message: str) -> None:
        """Add a log entry to the log viewer.

        Args:
            message: The log message to add.
        """
        try:
            if isinstance(self.screen, DashboardScreen):
                log_viewer = self.screen.query_one(LogViewer)
                log_viewer.add_log(message)
        except Exception:
            # Log viewer not mounted yet
            pass
