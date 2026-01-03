"""Screen definitions for the Textual dashboard application."""

import json

from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, RadioButton, RadioSet, Static

from lematt.health import CertificateHealth
from lematt.tui.widgets import (
    CertificateTable,
    DashboardHeader,
    HealthTable,
    KeybindingsFooter,
    LogViewer,
    OverviewPanel,
    StatusSidebar,
)


class DashboardScreen(Screen):
    """Main dashboard screen with all views and navigation.

    Layout:
    - Header (title, status, last update)
    - Body (horizontal):
      - Sidebar (status summary)
      - Content area (switchable views)
    - Footer (keybindings)
    """

    BINDINGS = [
        Binding("1", "switch_view('overview')", "Overview", show=False),
        Binding("2", "switch_view('certificates')", "Certificates", show=False),
        Binding("3", "switch_view('health')", "Health", show=False),
        Binding("4", "switch_view('logs')", "Logs", show=False),
    ]

    DEFAULT_CSS = """
    DashboardScreen {
        layout: vertical;
    }

    #body {
        layout: horizontal;
        height: 1fr;
    }

    #sidebar {
        width: 30;
        border-right: solid $accent;
    }

    #content {
        width: 1fr;
    }

    .view-container {
        display: none;
    }

    .view-container.current {
        display: block;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        """Initialize the dashboard screen.

        Args:
            **kwargs: Additional arguments passed to Screen.
        """
        super().__init__(**kwargs)
        self.current_view = "overview"

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        yield DashboardHeader(id="header")

        with Horizontal(id="body"):
            yield StatusSidebar(id="sidebar")

            with Container(id="content"):
                with Container(id="overview", classes="view-container current"):
                    yield OverviewPanel()

                with Container(id="certificates", classes="view-container"):
                    yield CertificateTable()

                with Container(id="health", classes="view-container"):
                    yield HealthTable()

                with Container(id="logs", classes="view-container"):
                    yield LogViewer(max_lines=100)

        yield KeybindingsFooter(id="footer")

    def action_switch_view(self, view: str) -> None:
        """Switch to a different view.

        Args:
            view: The view to switch to (overview, certificates, health, logs).
        """
        # Hide all views
        for view_id in ["overview", "certificates", "health", "logs"]:
            try:
                container = self.query_one(f"#{view_id}")
                container.remove_class("current")
            except Exception:
                pass

        # Show selected view
        try:
            container = self.query_one(f"#{view}")
            container.add_class("current")
            self.current_view = view

            # Focus the appropriate widget in the new view
            if view == "certificates":
                # Focus the certificate table
                cert_table = self.query_one(CertificateTable)
                table_widget = cert_table.query_one("#cert-table")
                table_widget.focus()
            elif view == "health":
                # Focus the health table
                health_table = self.query_one(HealthTable)
                health_table.focus()
            elif view == "logs":
                # Focus the log viewer
                log_viewer = self.query_one(LogViewer)
                log_viewer.focus()
            # Overview doesn't need focus (static content)

        except Exception:
            pass


class CertificateDetailScreen(Screen):
    """Modal screen showing detailed certificate information.

    Displays:
    - Domain and status
    - Key type and expiry details
    - Issuer information
    - Serial number
    - SAN domains
    - File paths
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=True),
        Binding("e", "export_json", "Export JSON", show=True),
    ]

    DEFAULT_CSS = """
    CertificateDetailScreen {
        layout: vertical;
    }

    #detail-header {
        height: 3;
        background: $primary;
        content-align: center middle;
        text-style: bold;
    }

    #detail-container {
        width: 100%;
        height: 1fr;
        padding: 2 4;
    }

    #detail-content {
        height: auto;
    }

    #footer-text {
        height: 1;
        content-align: center middle;
        color: #ffffff;
        text-style: bold;
    }
    """

    def __init__(self, certificate: CertificateHealth, **kwargs: object) -> None:
        """Initialize the detail screen.

        Args:
            certificate: The certificate to display.
            **kwargs: Additional arguments passed to Screen.
        """
        super().__init__(**kwargs)
        self.certificate = certificate

    def compose(self) -> ComposeResult:
        """Compose the detail screen layout."""
        yield Static(
            f"Certificate Details: {self.certificate.domain}", id="detail-header"
        )
        with Container(id="detail-container"):
            yield Static(self._create_detail_panel(), id="detail-content")
        yield Static(
            "Press [[Escape]] to close  |  Press [[e]] to export JSON", id="footer-text"
        )

    def _create_detail_panel(self) -> Table:
        """Create the certificate detail panel.

        Returns:
            Rich Table with certificate details.
        """
        table = Table.grid(padding=(0, 4))
        table.add_column(style="bold cyan", width=25)
        table.add_column()

        # Basic info
        table.add_row("Domain:", self.certificate.domain)

        # Status with color and icon
        status_icons = {"HEALTHY": "✓", "WARNING": "⚠", "CRITICAL": "✗", "UNKNOWN": "?"}
        status_styles = {
            "HEALTHY": "bold green",
            "WARNING": "bold yellow",
            "CRITICAL": "bold red",
            "UNKNOWN": "dim",
        }
        status_name = self.certificate.status.name
        icon = status_icons.get(status_name, "?")
        style = status_styles.get(status_name, "")
        status_text = Text(f"{icon} {status_name}", style=style)
        table.add_row("Status:", status_text)

        table.add_row("Key Type:", self.certificate.key_type)

        # Expiry info
        if self.certificate.not_after:
            expiry_str = self.certificate.not_after.strftime("%Y-%m-%d %H:%M:%S")
            table.add_row("Expires:", expiry_str)

        if self.certificate.days_until_expiry is not None:
            days = self.certificate.days_until_expiry
            if days < 7:
                style = "bold red"
            elif days < 14:
                style = "bold yellow"
            else:
                style = "bold green"
            table.add_row("Days Until Expiry:", Text(str(days), style=style))

        # Issuer
        if self.certificate.issuer:
            table.add_row("Issuer:", self.certificate.issuer)

        # Message
        if self.certificate.message:
            table.add_row("Message:", self.certificate.message)

        # File paths
        if self.certificate.cert_path:
            table.add_row("Certificate Path:", self.certificate.cert_path)

        # Additional details from dict
        if self.certificate.details:
            table.add_row("", "")
            table.add_row("[bold]Additional Information[/bold]", "")
            for key, value in self.certificate.details.items():
                label = key.replace("_", " ").title() + ":"
                table.add_row(label, str(value))

        return table

    def action_dismiss(self) -> None:
        """Close the detail screen."""
        self.dismiss()

    def action_export_json(self) -> None:
        """Export certificate details as JSON."""
        data = {
            "domain": self.certificate.domain,
            "status": self.certificate.status.name,
            "key_type": self.certificate.key_type,
            "days_until_expiry": self.certificate.days_until_expiry,
            "message": self.certificate.message,
            "issuer": self.certificate.issuer,
            "cert_path": self.certificate.cert_path,
        }

        if self.certificate.not_after:
            data["expires"] = self.certificate.not_after.isoformat()

        # Add all details from the details dict
        if self.certificate.details:
            data["details"] = self.certificate.details

        # Write to file
        filename = f"{self.certificate.domain}-{self.certificate.key_type}.json"
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            # Would show notification here in a real app
        except Exception:
            # Would show error notification here
            pass


class FilterDialogScreen(Screen):
    """Modal dialog for configuring certificate filters.

    Allows filtering by:
    - Status (all/healthy/warning/critical)
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    FilterDialogScreen {
        align: center middle;
    }

    #filter-container {
        width: 60;
        height: auto;
        background: $panel;
        border: thick $primary;
        padding: 1 2;
    }

    #filter-content {
        height: auto;
    }

    #button-row {
        layout: horizontal;
        height: auto;
        align: center middle;
        padding-top: 1;
    }

    Button {
        margin: 0 1;
    }

    RadioSet {
        padding: 1 0;
    }
    """

    def __init__(self, current_filter: str = "all", **kwargs: object) -> None:
        """Initialize the filter dialog.

        Args:
            current_filter: The current filter setting.
            **kwargs: Additional arguments passed to Screen.
        """
        super().__init__(**kwargs)
        self.current_filter = current_filter
        self.selected_filter = current_filter

    def compose(self) -> ComposeResult:
        """Compose the filter dialog layout."""
        with Container(id="filter-container"):
            with Vertical(id="filter-content"):
                yield Static("Filter Certificates By Status:", style="bold")
                with RadioSet(id="filter-radio"):
                    yield RadioButton(
                        "All Certificates", value=(self.current_filter == "all")
                    )
                    yield RadioButton(
                        "Healthy Only", value=(self.current_filter == "healthy")
                    )
                    yield RadioButton(
                        "Warning Only", value=(self.current_filter == "warning")
                    )
                    yield RadioButton(
                        "Critical Only", value=(self.current_filter == "critical")
                    )

            with Horizontal(id="button-row"):
                yield Button("Apply", id="apply-btn", variant="primary")
                yield Button("Cancel", id="cancel-btn")

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Handle radio button selection.

        Args:
            event: The radio set changed event.
        """
        # Map radio index to filter value
        filters = ["all", "healthy", "warning", "critical"]
        if event.pressed and event.pressed.parent:
            try:
                index = list(event.pressed.parent.children).index(event.pressed)
                self.selected_filter = filters[index]
            except (ValueError, IndexError):
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses.

        Args:
            event: The button pressed event.
        """
        if event.button.id == "apply-btn":
            self.dismiss(self.selected_filter)
        elif event.button.id == "cancel-btn":
            self.dismiss()

    def action_dismiss(self) -> None:
        """Cancel and close the dialog."""
        self.dismiss()
