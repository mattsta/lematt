"""Dashboard footer widget displaying available keybindings."""

from rich.text import Text
from textual.widgets import Static


class KeybindingsFooter(Static):
    """Footer widget showing available keyboard shortcuts.

    Displays all available keybindings with their descriptions.
    """

    def render(self) -> Text:
        """Render the keybindings footer."""
        bindings = [
            ("q", "Quit"),
            ("r", "Refresh"),
            ("1", "Overview"),
            ("2", "Certificates"),
            ("3", "Health"),
            ("4", "Logs"),
            ("Enter", "Details"),
        ]

        result = Text()
        result.append("Keys: ", style="bold")

        for i, (key, description) in enumerate(bindings):
            if i > 0:
                result.append(" | ")
            result.append(key, style="bold cyan")
            result.append(f" {description}", style="dim")

        return result
