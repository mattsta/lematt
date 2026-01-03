"""Textual-based interactive TUI components for lematt.

This module provides a fully interactive terminal user interface built with Textual,
replacing the non-interactive Rich-based dashboard with proper keyboard/mouse handling.
"""

from lematt.tui.app import LemattDashboardApp

__all__ = [
    "LemattDashboardApp",
]
