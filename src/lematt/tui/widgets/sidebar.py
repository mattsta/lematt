"""Dashboard sidebar widget displaying health summary and statistics."""

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static

from lematt.health import SystemHealth


class StatusSidebar(Static):
    """Sidebar widget showing health status and certificate counts.

    Displays:
    - Overall health status with icon
    - Certificate counts (total, healthy, warning, critical, unknown)
    - Next certificate expiry
    - Refresh interval and status
    """

    health_data: reactive[SystemHealth | None] = reactive(None)
    refresh_interval: reactive[float] = reactive(5.0)

    def render(self) -> RenderableType:
        """Render the sidebar with health summary and stats."""
        if not self.health_data:
            return Panel(
                Text("Loading...", style="dim"),
                title="Status",
                border_style="dim",
            )

        # Health status with icon
        status_icons = {
            "healthy": "✓",
            "warning": "⚠",
            "critical": "✗",
            "unknown": "?",
        }

        status_styles = {
            "healthy": "bold green",
            "warning": "bold yellow",
            "critical": "bold red",
            "unknown": "dim",
        }

        status = self.health_data.status.name.lower()
        icon = status_icons.get(status, "?")
        style = status_styles.get(status, "dim")

        content = Text()
        content.append(f"{icon} ", style=style)
        content.append(self.health_data.status.name.upper(), style=style)
        content.append("\n\n")

        # Certificate counts table
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold")
        table.add_column(style="dim")

        table.add_row("Total:", str(len(self.health_data.certificates)))
        table.add_row(
            "Healthy:",
            f"[green]{self.health_data.healthy_count}[/green]",
        )
        table.add_row(
            "Warning:",
            f"[yellow]{self.health_data.warning_count}[/yellow]",
        )
        table.add_row(
            "Critical:",
            f"[red]{self.health_data.critical_count}[/red]",
        )
        table.add_row(
            "Unknown:",
            f"[dim]{self.health_data.unknown_count}[/dim]",
        )

        # Next expiry
        soonest = self._get_soonest_expiry()
        if soonest:
            domain, days = soonest
            if days < 7:
                style_str = "red"
            elif days < 14:
                style_str = "yellow"
            else:
                style_str = "green"

            table.add_row("", "")  # Spacer
            table.add_row("Next Expiry:", "")
            table.add_row(f"  {domain}", f"[{style_str}]{days}d[/{style_str}]")

        # Refresh info
        table.add_row("", "")  # Spacer
        table.add_row("Refresh:", f"{self.refresh_interval:.1f}s")

        return Panel(
            Group(content, table),
            title="Status",
            border_style=style,
        )

    def watch_health_data(self, health: SystemHealth | None) -> None:
        """Automatically update display when health data changes."""
        self.refresh()

    def watch_refresh_interval(self, interval: float) -> None:
        """Automatically update display when refresh interval changes."""
        self.refresh()

    def _get_soonest_expiry(self) -> tuple[str, int] | None:
        """Get the certificate with the soonest expiry.

        Returns:
            Tuple of (domain, days_until_expiry) or None if no certificates.
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
