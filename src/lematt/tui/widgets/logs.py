"""Dashboard log viewer widget for activity logs."""

from datetime import datetime

from textual.binding import Binding
from textual.reactive import reactive
from textual.widgets import RichLog


class LogViewer(RichLog):
    """Scrollable log viewer with auto-scroll and timestamp support.

    Extends Textual's RichLog widget to display timestamped activity logs
    with automatic scrolling to the bottom when new entries are added.

    Keybindings:
        Home: Scroll to top of logs
        End: Scroll to bottom of logs
    """

    BINDINGS = [
        Binding("home", "scroll_top", "Top", show=False),
        Binding("end", "scroll_bottom", "Bottom", show=False),
    ]

    log_lines: reactive[list[str]] = reactive(list, init=False)
    max_lines: reactive[int] = reactive(100)
    auto_scroll: reactive[bool] = reactive(True)

    def __init__(
        self,
        max_lines: int = 100,
        auto_scroll: bool = True,
        **kwargs: object,
    ) -> None:
        """Initialize the log viewer.

        Args:
            max_lines: Maximum number of log lines to retain.
            auto_scroll: Whether to automatically scroll to bottom on new entries.
            **kwargs: Additional arguments passed to RichLog.
        """
        super().__init__(markup=True, **kwargs)
        self.log_lines = []
        self.max_lines = max_lines
        self.auto_scroll = auto_scroll

    def add_log(self, message: str) -> None:
        """Add a timestamped log message.

        Args:
            message: The log message to add.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[dim]{timestamp}[/dim] {message}"

        # Add to internal list
        self.log_lines.append(log_entry)

        # Trim to max_lines
        if len(self.log_lines) > self.max_lines:
            self.log_lines = self.log_lines[-self.max_lines :]

        # Write to display
        self.write(log_entry)

        # Auto-scroll to bottom
        if self.auto_scroll:
            self.scroll_end(animate=False)

    def watch_log_lines(self, lines: list[str]) -> None:
        """Update display when log lines change.

        Args:
            lines: The new list of log lines.
        """
        self.clear()
        for line in lines[-self.max_lines :]:
            self.write(line)

        if self.auto_scroll:
            self.scroll_end(animate=False)

    def action_scroll_top(self) -> None:
        """Scroll to the top of the logs."""
        self.scroll_home(animate=True)

    def action_scroll_bottom(self) -> None:
        """Scroll to the bottom of the logs."""
        self.scroll_end(animate=True)

    def clear_logs(self) -> None:
        """Clear all log entries."""
        self.log_lines = []
        self.clear()
