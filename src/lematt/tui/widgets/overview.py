"""Dashboard overview panel displaying health summary and quick stats."""

from rich.console import RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.containers import Container, Vertical
from textual.reactive import reactive
from textual.widgets import Static

from lematt.health import SystemHealth


class OverviewPanel(Container):
    """Overview panel showing health summary and certificate statistics.

    Displays:
    - Health summary panel with overall status
    - Quick stats table (total certificates, soonest expiry)
    - Certificate count breakdown by status
    """

    health_data: reactive[SystemHealth | None] = reactive(None)

    def compose(self):
        """Compose the overview panel layout."""
        yield Vertical(
            HealthSummaryWidget(id="health-summary"),
            QuickStatsWidget(id="quick-stats"),
        )

    def watch_health_data(self, health: SystemHealth | None) -> None:
        """Update child widgets when health data changes.

        Args:
            health: The new health data.
        """
        try:
            summary_widget = self.query_one("#health-summary", HealthSummaryWidget)
            summary_widget.health_data = health

            stats_widget = self.query_one("#quick-stats", QuickStatsWidget)
            stats_widget.health_data = health
        except Exception:
            # Widgets not mounted yet
            pass


class HealthSummaryWidget(Static):
    """Widget displaying the health summary panel."""

    health_data: reactive[SystemHealth | None] = reactive(None)

    def render(self) -> RenderableType:
        """Render the health summary.

        Returns:
            Rich renderable with health summary.
        """
        if not self.health_data:
            return Panel(Text("Loading...", style="dim"), title="Health Summary")

        # Build health summary panel
        status_icons = {"healthy": "✓", "warning": "⚠", "critical": "✗", "unknown": "?"}
        status_styles = {
            "healthy": "bold green",
            "warning": "bold yellow",
            "critical": "bold red",
            "unknown": "dim",
        }

        status = self.health_data.status.name.lower()
        icon = status_icons.get(status, "?")
        style = status_styles.get(status, "dim")

        # Build summary text
        summary = Text()
        summary.append(f"{icon} ", style=style)
        summary.append("Overall: ", style="bold")
        summary.append(self.health_data.status.name.upper(), style=style)
        summary.append(f"\n\n{self.health_data.summary}")

        return Panel(summary, title="Health Summary", border_style=style)

    def watch_health_data(self, health: SystemHealth | None) -> None:
        """Refresh display when health data changes."""
        self.refresh()


class QuickStatsWidget(Static):
    """Widget displaying quick statistics table."""

    health_data: reactive[SystemHealth | None] = reactive(None)

    def render(self) -> RenderableType:
        """Render the quick stats table.

        Returns:
            Rich renderable with statistics.
        """
        if not self.health_data:
            return Panel(Text("Loading...", style="dim"), title="Statistics")

        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold cyan")
        table.add_column(style="")

        # Total certificates
        total_certs = len(self.health_data.certificates)
        table.add_row("Total Certificates:", str(total_certs))

        # Soonest expiry
        soonest = self._get_soonest_expiry()
        if soonest:
            domain, days = soonest
            if days < 7:
                style = "bold red"
            elif days < 14:
                style = "bold yellow"
            else:
                style = "bold green"

            expiry_text = Text()
            expiry_text.append(domain, style="")
            expiry_text.append(f" ({days} days)", style=style)
            table.add_row("Soonest Expiry:", expiry_text)
        else:
            table.add_row("Soonest Expiry:", Text("N/A", style="dim"))

        # Status breakdown
        table.add_row("", "")  # Spacer
        table.add_row("Status Breakdown:", "")
        table.add_row(
            "  Healthy:",
            Text(str(self.health_data.healthy_count), style="green"),
        )
        table.add_row(
            "  Warning:",
            Text(str(self.health_data.warning_count), style="yellow"),
        )
        table.add_row(
            "  Critical:",
            Text(str(self.health_data.critical_count), style="red"),
        )
        table.add_row(
            "  Unknown:",
            Text(str(self.health_data.unknown_count), style="dim"),
        )

        return Panel(table, title="Quick Stats", border_style="cyan")

    def watch_health_data(self, health: SystemHealth | None) -> None:
        """Refresh display when health data changes."""
        self.refresh()

    def _get_soonest_expiry(self) -> tuple[str, int] | None:
        """Get the certificate with the soonest expiry.

        Returns:
            Tuple of (domain, days_until_expiry) or None.
        """
        if not self.health_data or not self.health_data.certificates:
            return None

        soonest = None
        min_days = float("inf")

        for cert in self.health_data.certificates:
            if cert.days_until_expiry is not None and cert.days_until_expiry < min_days:
                min_days = cert.days_until_expiry
                soonest = (cert.domain, cert.days_until_expiry)

        return soonest
