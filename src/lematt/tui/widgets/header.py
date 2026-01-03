"""Dashboard header widget displaying title, status, and last update time."""

from datetime import datetime

from rich.text import Text
from textual.reactive import reactive
from textual.widgets import Static


class DashboardHeader(Static):
    """Header widget with title, status badge, and last update timestamp.

    Displays:
    - Application title
    - TEST MODE warning (if applicable)
    - Status badge (LIVE/PAUSED/ERROR)
    - Last update timestamp
    """

    is_paused: reactive[bool] = reactive(False)
    error_message: reactive[str | None] = reactive(None)
    last_update: reactive[datetime | None] = reactive(None)
    is_test: reactive[bool] = reactive(False)

    def render(self) -> Text:
        """Render the header with status badge and timestamp."""
        # Add TEST MODE warning if applicable
        if self.is_test:
            title = Text("⚠ TEST MODE ⚠ ", style="bold red")
            title.append("Lematt Certificate Dashboard", style="bold cyan")
        else:
            title = Text("Lematt Certificate Dashboard", style="bold cyan")

        # Status badge
        if self.error_message:
            status = Text(" ERROR ", style="bold white on red")
        elif self.is_paused:
            status = Text(" PAUSED ", style="bold black on yellow")
        else:
            status = Text(" LIVE ", style="bold white on green")

        # Last update timestamp
        if self.last_update:
            time_str = self.last_update.strftime("%H:%M:%S")
            update_text = Text(f" Last update: {time_str}", style="dim")
        else:
            update_text = Text(" Initializing...", style="dim")

        # Combine all parts
        result = Text()
        result.append(title)
        result.append("  ")
        result.append(status)
        result.append(update_text)

        return result

    def watch_is_paused(self, paused: bool) -> None:
        """Automatically update display when pause state changes."""
        self.refresh()

    def watch_error_message(self, error: str | None) -> None:
        """Automatically update display when error state changes."""
        self.refresh()

    def watch_last_update(self, timestamp: datetime | None) -> None:
        """Automatically update display when last update time changes."""
        self.refresh()
