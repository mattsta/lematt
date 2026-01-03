"""Widget components for the Textual dashboard."""

from lematt.tui.widgets.footer import KeybindingsFooter
from lematt.tui.widgets.header import DashboardHeader
from lematt.tui.widgets.logs import LogViewer
from lematt.tui.widgets.overview import OverviewPanel
from lematt.tui.widgets.sidebar import StatusSidebar
from lematt.tui.widgets.tables import CertificateTable, HealthTable

__all__ = [
    "DashboardHeader",
    "KeybindingsFooter",
    "StatusSidebar",
    "CertificateTable",
    "HealthTable",
    "OverviewPanel",
    "LogViewer",
]
