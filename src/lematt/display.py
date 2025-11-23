"""Rich terminal display components for lematt.

This module provides beautiful, informative terminal output using the rich library.
All display components are designed to be reusable and composable.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

# Shared console instance
console = Console()


# Status styles
class StatusStyle:
    """Consistent styling for status indicators."""

    HEALTHY = Style(color="green", bold=True)
    WARNING = Style(color="yellow", bold=True)
    CRITICAL = Style(color="red", bold=True)
    UNKNOWN = Style(color="bright_black")
    INFO = Style(color="cyan")
    MUTED = Style(color="bright_black")

    ICONS = {
        "healthy": "✓",
        "warning": "⚠",
        "critical": "✗",
        "unknown": "?",
        "pending": "○",
        "running": "◉",
        "success": "✓",
        "failure": "✗",
    }

    @classmethod
    def get_style(cls, status: str) -> Style:
        """Get style for a status string."""
        status_lower = status.lower()
        if status_lower in ("healthy", "ok", "success", "valid"):
            return cls.HEALTHY
        elif status_lower in ("warning", "warn", "expiring"):
            return cls.WARNING
        elif status_lower in ("critical", "error", "failure", "expired", "missing"):
            return cls.CRITICAL
        return cls.UNKNOWN

    @classmethod
    def get_icon(cls, status: str) -> str:
        """Get icon for a status string."""
        status_lower = status.lower()
        if status_lower in ("healthy", "ok", "success", "valid"):
            return cls.ICONS["healthy"]
        elif status_lower in ("warning", "warn", "expiring"):
            return cls.ICONS["warning"]
        elif status_lower in ("critical", "error", "failure", "expired", "missing"):
            return cls.ICONS["critical"]
        return cls.ICONS["unknown"]


class CertificateDisplay(Protocol):
    """Protocol for certificate-like objects."""

    domain: str
    key_type: str
    status: str
    days_until_expiry: int | None


@dataclass
class DisplayConfig:
    """Configuration for display output."""

    show_icons: bool = True
    show_colors: bool = True
    compact: bool = False
    max_width: int | None = None


def create_certificate_table(
    certificates: list[dict],
    title: str = "Certificate Status",
    config: DisplayConfig | None = None,
) -> Table:
    """Create a rich table displaying certificate status.

    Args:
        certificates: List of certificate status dicts
        title: Table title
        config: Display configuration

    Returns:
        Rich Table object
    """
    config = config or DisplayConfig()

    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        expand=True,
    )

    table.add_column("Status", justify="center", width=8)
    table.add_column("Domain", style="bold")
    table.add_column("Type", justify="center", width=6)
    table.add_column("Expires", justify="right", width=12)
    table.add_column("Days", justify="right", width=6)

    if not config.compact:
        table.add_column("Path", style="dim", overflow="fold")

    for cert in certificates:
        status = cert.get("status", "unknown")
        domain = cert.get("domain", "unknown")
        key_type = cert.get("key_type", "?")
        days = cert.get("days_until_expiry")
        expires = cert.get("expires", cert.get("not_after", ""))
        path = cert.get("cert_path", "")

        # Format status with icon and color
        icon = StatusStyle.get_icon(status) if config.show_icons else ""
        style = StatusStyle.get_style(status) if config.show_colors else None
        status_text = Text(f"{icon} {status}", style=style)

        # Format days with color coding
        if days is not None:
            if days < 0:
                days_text = Text(f"{days}", style=StatusStyle.CRITICAL)
            elif days < 7:
                days_text = Text(str(days), style=StatusStyle.CRITICAL)
            elif days < 14:
                days_text = Text(str(days), style=StatusStyle.WARNING)
            else:
                days_text = Text(str(days), style=StatusStyle.HEALTHY)
        else:
            days_text = Text("-", style=StatusStyle.MUTED)

        # Format expiry date
        if expires:
            if isinstance(expires, str):
                expires_str = expires[:10] if len(expires) > 10 else expires
            else:
                expires_str = expires.strftime("%Y-%m-%d")
        else:
            expires_str = "-"

        if config.compact:
            table.add_row(status_text, domain, key_type, expires_str, days_text)
        else:
            table.add_row(status_text, domain, key_type, expires_str, days_text, path)

    return table


def create_health_summary(health_data: dict, config: DisplayConfig | None = None) -> Panel:
    """Create a health summary panel.

    Args:
        health_data: Health check results dict
        config: Display configuration

    Returns:
        Rich Panel object
    """
    config = config or DisplayConfig()

    status = health_data.get("status", "unknown")
    counts = health_data.get("counts", {})
    checked_at = health_data.get("checked_at", "")

    # Build status line
    icon = StatusStyle.get_icon(status)
    style = StatusStyle.get_style(status)
    status_line = Text()
    status_line.append(f"{icon} ", style=style)
    status_line.append("Overall: ", style="bold")
    status_line.append(status.upper(), style=style)

    # Build counts line
    counts_parts = []
    for key, count in counts.items():
        if key == "total":
            continue
        if count > 0:
            count_style = StatusStyle.get_style(key)
            counts_parts.append(Text(f"{count} {key}", style=count_style))

    counts_line = Text()
    counts_line.append("Certificates: ")
    for i, part in enumerate(counts_parts):
        if i > 0:
            counts_line.append(" | ")
        counts_line.append_text(part)

    total = counts.get("total", 0)
    counts_line.append(f" (total: {total})", style=StatusStyle.MUTED)

    # Combine into panel
    content = Group(status_line, counts_line)

    subtitle = f"Checked: {checked_at}" if checked_at else None
    return Panel(
        content,
        title="[bold]Health Summary[/bold]",
        subtitle=subtitle,
        border_style=style,
    )


def create_domain_tree(domains: list[dict], title: str = "Configured Domains") -> Tree:
    """Create a tree view of configured domains.

    Args:
        domains: List of domain configuration dicts
        title: Tree root label

    Returns:
        Rich Tree object
    """
    tree = Tree(f"[bold cyan]{title}[/bold cyan]")

    for i, domain in enumerate(domains, 1):
        primary = domain.get("primary", domain.get("primary_domain", "unknown"))
        sans = domain.get("sans", domain.get("san_domains", []))
        ocsp = domain.get("ocsp_staple_required", False)

        # Create domain node
        label = Text()
        label.append(f"{i}. ", style="dim")
        label.append(primary, style="bold")
        if ocsp:
            label.append(" [+ocsp]", style="green")

        domain_node = tree.add(label)

        # Add SANs as children
        if sans:
            sans_node = domain_node.add("[dim]SANs:[/dim]")
            for san in sans:
                sans_node.add(f"[cyan]{san}[/cyan]")

    return tree


def create_config_tree(config: dict, title: str = "Configuration") -> Tree:
    """Create a tree view of configuration.

    Args:
        config: Configuration dict
        title: Tree root label

    Returns:
        Rich Tree object
    """
    tree = Tree(f"[bold cyan]{title}[/bold cyan]")

    def add_dict(parent: Tree, data: dict, depth: int = 0) -> None:
        for key, value in data.items():
            if isinstance(value, dict):
                node = parent.add(f"[bold]{key}[/bold]")
                add_dict(node, value, depth + 1)
            elif isinstance(value, list):
                node = parent.add(f"[bold]{key}[/bold]")
                for item in value[:5]:  # Limit list items
                    node.add(f"[dim]{item}[/dim]")
                if len(value) > 5:
                    node.add(f"[dim]... and {len(value) - 5} more[/dim]")
            else:
                parent.add(f"{key}: [cyan]{value}[/cyan]")

    add_dict(tree, config)
    return tree


def create_renewal_progress() -> Progress:
    """Create a progress bar for certificate renewal operations.

    Returns:
        Rich Progress object
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        expand=True,
    )


def create_action_table(actions: dict, title: str = "Workflow Actions") -> Table:
    """Create a table showing configured actions.

    Args:
        actions: Actions configuration dict
        title: Table title

    Returns:
        Rich Table object
    """
    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
    )

    table.add_column("Action Group", style="bold")
    table.add_column("Domains", overflow="fold")
    table.add_column("Prepare", justify="center")
    table.add_column("Upload", justify="center")
    table.add_column("Update", justify="center")

    for name, config in actions.items():
        domains = config.get("domains", [])
        domains_str = ", ".join(domains[:3])
        if len(domains) > 3:
            domains_str += f" (+{len(domains) - 3})"
        if not domains_str:
            domains_str = "[dim]all[/dim]" if name == "default" else "[dim]-[/dim]"

        prepare = "✓" if config.get("prepare") or config.get("prepare_commands") else "-"
        upload = "✓" if (config.get("upload_certs") or config.get("upload_certs_commands") or
                        config.get("upload_keys") or config.get("upload_keys_commands")) else "-"
        update = "✓" if config.get("update") or config.get("update_commands") else "-"

        table.add_row(name, domains_str, prepare, upload, update)

    return table


def print_banner(version: str = "2.0.0", test_mode: bool = False) -> None:
    """Print the lematt banner.

    Args:
        version: Version string
        test_mode: Whether in test mode
    """
    mode_text = "[yellow]TEST MODE[/yellow]" if test_mode else "[green]PRODUCTION[/green]"

    banner = Panel(
        f"[bold cyan]lematt[/bold cyan] v{version}\n"
        f"Matt's Let's Encrypt Automation\n"
        f"Mode: {mode_text}",
        border_style="cyan",
        padding=(0, 2),
    )
    console.print(banner)


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[red]✗[/red] {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[cyan]ℹ[/cyan] {message}")
