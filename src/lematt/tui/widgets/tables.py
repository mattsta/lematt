"""Interactive table widgets for displaying certificates and health data."""

from textual.containers import Container
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import DataTable

from lematt.health import CertificateHealth


class CertificateTable(Container):
    """Interactive certificate table with selection and drill-down.

    Features:
    - Row selection with arrow keys
    - Color-coded rows by expiry status
    - Press Enter to view certificate details

    Keybindings:
        Arrow keys: Navigate rows
        Enter: View details for selected certificate
    """

    BINDINGS = []

    certificates: reactive[list[CertificateHealth]] = reactive(list, init=False)
    filter_status: reactive[str] = reactive("all")
    compact_mode: reactive[bool] = reactive(False)

    class CertificateSelected(Message):
        """Message sent when a certificate is selected."""

        def __init__(self, certificate: CertificateHealth) -> None:
            """Initialize the message.

            Args:
                certificate: The selected certificate.
            """
            super().__init__()
            self.certificate = certificate

    def __init__(self, compact_mode: bool = False, **kwargs: object) -> None:
        """Initialize the certificate table.

        Args:
            compact_mode: Whether to hide file paths.
            **kwargs: Additional arguments passed to Container.
        """
        super().__init__(**kwargs)
        self.certificates = []
        self.compact_mode = compact_mode

    def compose(self) -> None:
        """Compose the table layout with data table."""
        yield DataTable(id="cert-table", cursor_type="row")

    def on_mount(self) -> None:
        """Set up the table when mounted."""
        table = self.query_one("#cert-table", DataTable)

        # Enable focus for keyboard navigation
        table.can_focus = True

        # Add columns
        if self.compact_mode:
            table.add_columns("Status", "Domain", "Key Type", "Expiry", "Days")
        else:
            table.add_columns(
                "Status",
                "Domain",
                "Key Type",
                "Expiry",
                "Days",
                "Path",
            )

        # Build initial table
        self._rebuild_table()

    def watch_certificates(self, certs: list[CertificateHealth]) -> None:
        """Rebuild table when certificates change.

        Args:
            certs: The new list of certificates.
        """
        self._rebuild_table()

    def watch_filter_status(self, status: str) -> None:
        """Rebuild table when filter changes.

        Args:
            status: The new filter status.
        """
        self._rebuild_table()

    def watch_compact_mode(self, compact: bool) -> None:
        """Update table columns when compact mode changes.

        Args:
            compact: Whether compact mode is enabled.
        """
        if not self.is_mounted:
            return

        try:
            table = self.query_one("#cert-table", DataTable)
            table.clear(columns=True)

            if compact:
                table.add_columns("Status", "Domain", "Key Type", "Expiry", "Days")
            else:
                table.add_columns(
                    "Status",
                    "Domain",
                    "Key Type",
                    "Expiry",
                    "Days",
                    "Path",
                )

            self._rebuild_table()
        except Exception:
            # Widget not fully mounted yet
            pass

    def _rebuild_table(self) -> None:
        """Rebuild the table with current certificates and filters."""
        try:
            table = self.query_one("#cert-table", DataTable)
        except Exception:
            # Table not mounted yet
            return

        table.clear()

        # Apply filters
        filtered_certs = self._apply_filters(self.certificates)

        # Add rows
        for cert in filtered_certs:
            # Status icon and text
            status_icons = {
                "HEALTHY": "✓",
                "WARNING": "⚠",
                "CRITICAL": "✗",
                "UNKNOWN": "?",
            }
            icon = status_icons.get(cert.status, "?")
            status_text = f"{icon} {cert.status}"

            # Days styling
            if cert.days_until_expiry is None:
                days_text = "N/A"
                days_style = "dim"
            elif cert.days_until_expiry < 7:
                days_text = str(cert.days_until_expiry)
                days_style = "bold red"
            elif cert.days_until_expiry < 14:
                days_text = str(cert.days_until_expiry)
                days_style = "bold yellow"
            else:
                days_text = str(cert.days_until_expiry)
                days_style = "bold green"

            # Expiry date
            expiry_str = (
                cert.not_after.strftime("%Y-%m-%d") if cert.not_after else "Unknown"
            )

            # Build row
            if self.compact_mode:
                row = (
                    status_text,
                    cert.domain,
                    cert.key_type,
                    expiry_str,
                    days_text,
                )
            else:
                row = (
                    status_text,
                    cert.domain,
                    cert.key_type,
                    expiry_str,
                    days_text,
                    cert.cert_path or "",
                )

            table.add_row(*row)

    def _apply_filters(self, certs: list[CertificateHealth]) -> list[CertificateHealth]:
        """Apply current filters to certificates.

        Args:
            certs: The certificates to filter.

        Returns:
            Filtered list of certificates.
        """
        filtered = certs

        # Filter by status
        if self.filter_status != "all":
            filtered = [
                c for c in filtered if c.status.name.lower() == self.filter_status
            ]

        return filtered

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection when Enter is pressed.

        Args:
            event: The row selected event.
        """
        # Get the certificate for the selected row
        if event.cursor_row < len(self._apply_filters(self.certificates)):
            cert = self._apply_filters(self.certificates)[event.cursor_row]
            self.post_message(self.CertificateSelected(cert))


class HealthTable(DataTable):
    """Health details table showing extended certificate information.

    Displays all health check details including issuer, messages, and status.

    Keybindings:
        Enter: View details for selected certificate
    """

    certificates: reactive[list[CertificateHealth]] = reactive(list, init=False)

    class CertificateSelected(Message):
        """Message sent when a certificate is selected."""

        def __init__(self, certificate: CertificateHealth) -> None:
            """Initialize the message.

            Args:
                certificate: The selected certificate.
            """
            super().__init__()
            self.certificate = certificate

    def __init__(self, **kwargs: object) -> None:
        """Initialize the health table.

        Args:
            **kwargs: Additional arguments passed to DataTable.
        """
        super().__init__(**kwargs)
        self.certificates = []

    def on_mount(self) -> None:
        """Set up the table when mounted."""
        self.cursor_type = "row"

        # Enable focus for keyboard navigation
        self.can_focus = True

        # Add columns
        self.add_columns(
            "Domain",
            "Key Type",
            "Status",
            "Days",
            "Message",
            "Issuer",
        )

        self._rebuild_table()

    def watch_certificates(self, certs: list[CertificateHealth]) -> None:
        """Rebuild table when certificates change.

        Args:
            certs: The new list of certificates.
        """
        self._rebuild_table()

    def _rebuild_table(self) -> None:
        """Rebuild the table with current certificates."""
        self.clear()

        for cert in self.certificates:
            # Status with icon
            status_icons = {
                "HEALTHY": "✓",
                "WARNING": "⚠",
                "CRITICAL": "✗",
                "UNKNOWN": "?",
            }
            icon = status_icons.get(cert.status, "?")
            status_text = f"{icon} {cert.status}"

            # Days
            days_text = (
                str(cert.days_until_expiry)
                if cert.days_until_expiry is not None
                else "N/A"
            )

            # Message
            message = cert.message or "No message"

            # Issuer
            issuer = cert.issuer or "Unknown"

            self.add_row(
                cert.domain,
                cert.key_type,
                status_text,
                days_text,
                message,
                issuer,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection when Enter is pressed.

        Args:
            event: The row selected event.
        """
        # Get the certificate for the selected row
        if event.cursor_row < len(self.certificates):
            cert = self.certificates[event.cursor_row]
            self.post_message(self.CertificateSelected(cert))
