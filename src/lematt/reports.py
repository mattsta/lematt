"""Summary reports for certificate management.

This module generates comprehensive, human-readable reports including
certificate inventory, renewal schedules, configuration summaries,
and operational status.
"""

import io
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .config import DomainActions, DomainConfig, KeyType, LemattConfig
from .display import StatusStyle, console
from .health import SystemHealth

REPORT_FORMATS = ("console", "json", "markdown")
_FORMAT_BY_SUFFIX = {".json": "json", ".md": "markdown", ".markdown": "markdown"}

# Every certificate line is issued with both key types
DEFAULT_KEY_TYPES = (KeyType.RSA, KeyType.EC)


def report_format(output_path: Path | None, requested: str | None = None) -> str:
    """The report format: as requested, else from the file extension, else console."""
    if requested:
        return requested
    if output_path is not None:
        return _FORMAT_BY_SUFFIX.get(output_path.suffix.lower(), "console")
    return "console"


def config_summary(
    config: LemattConfig,
    domains: Sequence[DomainConfig],
    actions: DomainActions | None,
    key_types: Sequence[KeyType],
) -> dict[str, Any]:
    """The settings a report shows, shared by every output format."""
    return {
        "test_mode": config.is_test,
        "acme_directory": config.acme_directory_url,
        "config_directory": str(config.config_base),
        "cert_directory": str(config.mode_dir("cert")),
        "key_directory": str(config.mode_dir("key")),
        "challenge_directory": str(config.challenge_dir),
        "account_key": str(config.account_key),
        "profile": config.profile,
        "rsa_key_bits": config.rsa_key_bits,
        "ec_curve": config.ec_curve,
        "key_types": [str(kt) for kt in key_types],
        "domain_count": len(domains),
        "san_count": sum(len(d.san_domains) for d in domains),
        "action_groups": list(actions.all_action_names()) if actions else [],
    }


# Labels for config_summary() keys in the console and Markdown reports
_SUMMARY_LABELS = {
    "test_mode": "Test mode",
    "acme_directory": "ACME directory",
    "config_directory": "Config directory",
    "cert_directory": "Certificate directory",
    "key_directory": "Key directory",
    "challenge_directory": "Challenge directory",
    "account_key": "Account key",
    "profile": "Default profile",
    "rsa_key_bits": "RSA key bits",
    "ec_curve": "EC curve",
}


def _summary_value(value: Any) -> str:
    return "CA default" if value is None else str(value)


def _group_scope(name: str) -> str:
    """Which names an action group without a domains list applies to."""
    return "every renewed certificate" if name == "every" else "unlisted names"


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    title: str = "lematt Certificate Report"
    include_inventory: bool = True
    include_schedule: bool = True
    include_config: bool = True
    include_health: bool = True
    include_actions: bool = True
    show_paths: bool = True
    show_timestamps: bool = True
    generated_at: datetime = field(default_factory=datetime.now)


@dataclass
class CertificateInventoryItem:
    """Single item in certificate inventory."""

    domain: str
    key_type: str
    status: str
    days_until_expiry: int | None
    not_after: datetime | None
    cert_path: Path
    key_path: Path
    san_domains: list[str] = field(default_factory=list)
    issuer: str | None = None
    file_size: int | None = None
    renewal_due_at: datetime | None = None  # from the renewal policy


@dataclass
class RenewalScheduleItem:
    """Single item in renewal schedule."""

    domain: str
    key_type: str
    current_expiry: datetime | None
    renewal_date: datetime | None
    days_until_renewal: int | None
    priority: str  # "immediate", "soon", "scheduled", "ok"


class ReportGenerator:
    """Generates various report types."""

    def __init__(
        self,
        config: LemattConfig,
        domains: Sequence[DomainConfig],
        health: SystemHealth | None = None,
        report_config: ReportConfig | None = None,
        key_types: Sequence[KeyType] = DEFAULT_KEY_TYPES,
    ):
        self.config = config
        self.domains = domains
        self.health = health
        self.report_config = report_config or ReportConfig()
        self.key_types = key_types

    def build_inventory(self) -> list[CertificateInventoryItem]:
        """Build certificate inventory from config and health data."""
        inventory = []

        for domain_config in self.domains:
            for key_type in self.key_types:
                # Find health data for this cert
                health_item = None
                if self.health:
                    for cert in self.health.certificates:
                        if (
                            cert.domain == domain_config.primary_domain
                            and cert.key_type == str(key_type)
                        ):
                            health_item = cert
                            break

                # Build paths
                cert_path = self.config.get_cert_path(domain_config, key_type)
                key_path = self.config.get_key_path(domain_config, key_type)

                file_size = cert_path.stat().st_size if cert_path.is_file() else None

                inventory.append(
                    CertificateInventoryItem(
                        domain=domain_config.primary_domain,
                        key_type=str(key_type),
                        status=str(health_item.status) if health_item else "unknown",
                        days_until_expiry=health_item.days_until_expiry
                        if health_item
                        else None,
                        not_after=health_item.not_after if health_item else None,
                        cert_path=cert_path,
                        key_path=key_path,
                        san_domains=domain_config.san_domains,
                        issuer=health_item.issuer if health_item else None,
                        file_size=file_size,
                        renewal_due_at=health_item.renewal_due_at
                        if health_item
                        else None,
                    )
                )

        return inventory

    def build_renewal_schedule(
        self, renewal_threshold_days: int = 30
    ) -> list[RenewalScheduleItem]:
        """Build the renewal schedule.

        Renewal dates come from lematt's renewal policy (ARI window or
        lifetime rule) when health data has them; otherwise
        ``renewal_threshold_days`` before expiry.
        """
        schedule = []
        now = datetime.now(UTC).replace(tzinfo=None)  # certificate times are UTC

        for item in self.build_inventory():
            if item.not_after:
                renewal_date = item.renewal_due_at or (
                    item.not_after - timedelta(days=renewal_threshold_days)
                )
                days_until_renewal = (renewal_date - now).days

                # Determine priority
                if days_until_renewal < 0:
                    priority = "immediate"
                elif days_until_renewal < 7:
                    priority = "soon"
                elif days_until_renewal < 14:
                    priority = "scheduled"
                else:
                    priority = "ok"
            else:
                renewal_date = None
                days_until_renewal = None
                priority = "unknown"

            schedule.append(
                RenewalScheduleItem(
                    domain=item.domain,
                    key_type=item.key_type,
                    current_expiry=item.not_after,
                    renewal_date=renewal_date,
                    days_until_renewal=days_until_renewal,
                    priority=priority,
                )
            )

        # Sort by days until renewal (None/immediate first)
        schedule.sort(
            key=lambda x: (
                x.days_until_renewal if x.days_until_renewal is not None else -9999
            )
        )

        return schedule


class ReportRenderer:
    """Renders reports in various formats."""

    def render_inventory_table(
        self,
        inventory: list[CertificateInventoryItem],
        show_paths: bool = True,
        is_test: bool = False,
    ) -> Table:
        """Render certificate inventory as a table."""
        title = "Certificate Inventory"
        if is_test:
            title = "[red]Certificate Inventory (TEST MODE)[/red]"

        table = Table(
            title=title,
            show_header=True,
            header_style="bold cyan",
            border_style="bright_black",
            expand=True,
        )

        table.add_column("Mode", justify="center", width=8, style="bold")
        table.add_column("Domain", style="bold")
        table.add_column("Type", justify="center", width=6)
        table.add_column("Status", justify="center", width=10)
        table.add_column("Expires", justify="right", width=12)
        table.add_column("Days", justify="right", width=6)
        table.add_column("SANs", justify="right", width=6)

        if show_paths:
            table.add_column("Cert Path", style="dim", overflow="fold")

        for item in inventory:
            # Status with icon
            icon = StatusStyle.get_icon(item.status)
            style = StatusStyle.get_style(item.status)
            status_text = Text(f"{icon} {item.status}", style=style)

            # Days with color
            if item.days_until_expiry is not None:
                days_style = (
                    StatusStyle.CRITICAL
                    if item.days_until_expiry < 7
                    else StatusStyle.WARNING
                    if item.days_until_expiry < 14
                    else StatusStyle.HEALTHY
                )
                days_text = Text(str(item.days_until_expiry), style=days_style)
            else:
                days_text = Text("-", style=StatusStyle.MUTED)

            # Expiry date
            expires = item.not_after.strftime("%Y-%m-%d") if item.not_after else "-"

            # SAN count
            san_count = len(item.san_domains)
            san_text = str(san_count) if san_count > 0 else "-"

            # Mode indicator
            mode_text = (
                Text("[TEST]", style="bold red")
                if is_test
                else Text("[PROD]", style="bold green")
            )

            if show_paths:
                table.add_row(
                    mode_text,
                    item.domain,
                    item.key_type.upper(),
                    status_text,
                    expires,
                    days_text,
                    san_text,
                    str(item.cert_path),
                )
            else:
                table.add_row(
                    mode_text,
                    item.domain,
                    item.key_type.upper(),
                    status_text,
                    expires,
                    days_text,
                    san_text,
                )

        return table

    def render_schedule_table(
        self, schedule: list[RenewalScheduleItem], is_test: bool = False
    ) -> Table:
        """Render renewal schedule as a table."""
        title = "Renewal Schedule"
        if is_test:
            title = "[red]Renewal Schedule (TEST MODE)[/red]"

        table = Table(
            title=title,
            show_header=True,
            header_style="bold cyan",
            border_style="bright_black",
            expand=True,
        )

        table.add_column("Mode", justify="center", width=8, style="bold")
        table.add_column("Priority", justify="center", width=12)
        table.add_column("Domain", style="bold")
        table.add_column("Type", justify="center", width=6)
        table.add_column("Current Expiry", justify="right", width=12)
        table.add_column("Renewal Date", justify="right", width=12)
        table.add_column("Days Until Renewal", justify="right", width=8)

        priority_styles = {
            "immediate": ("⚡", StatusStyle.CRITICAL),
            "soon": ("⏰", StatusStyle.WARNING),
            "scheduled": ("📅", StatusStyle.INFO),
            "ok": ("✓", StatusStyle.HEALTHY),
            "unknown": ("?", StatusStyle.UNKNOWN),
        }

        for item in schedule:
            icon, style = priority_styles.get(item.priority, ("?", StatusStyle.UNKNOWN))
            priority_text = Text(f"{icon} {item.priority}", style=style)

            expiry = (
                item.current_expiry.strftime("%Y-%m-%d") if item.current_expiry else "-"
            )
            renewal = (
                item.renewal_date.strftime("%Y-%m-%d") if item.renewal_date else "-"
            )

            if item.days_until_renewal is not None:
                if item.days_until_renewal < 0:
                    days_text = Text(
                        f"{item.days_until_renewal} (overdue)",
                        style=StatusStyle.CRITICAL,
                    )
                else:
                    days_text = Text(str(item.days_until_renewal), style=style)
            else:
                days_text = Text("-", style=StatusStyle.MUTED)

            # Mode indicator
            mode_text = (
                Text("[TEST]", style="bold red")
                if is_test
                else Text("[PROD]", style="bold green")
            )

            table.add_row(
                mode_text,
                priority_text,
                item.domain,
                item.key_type.upper(),
                expiry,
                renewal,
                days_text,
            )

        return table

    def render_config_summary(
        self, summary: dict[str, Any], actions: DomainActions | None = None
    ) -> Panel:
        """Render configuration summary (see config_summary())."""
        tree = Tree("[bold]Configuration Summary[/bold]")

        # Global settings
        global_node = tree.add("[cyan]Global Settings[/cyan]")
        for key, label in _SUMMARY_LABELS.items():
            global_node.add(f"{label}: [dim]{_summary_value(summary[key])}[/dim]")

        # Key types
        keys_node = tree.add("[cyan]Key Types[/cyan]")
        for kt in summary["key_types"]:
            keys_node.add(f"[green]✓[/green] {kt}")

        # Domains summary
        domains_node = tree.add("[cyan]Domains[/cyan]")
        domains_node.add(f"Total: {summary['domain_count']}")
        domains_node.add(f"Total SANs: {summary['san_count']}")

        # Actions summary
        if actions:
            actions_node = tree.add("[cyan]Actions[/cyan]")
            for name, action in actions.all_action_names().items():
                action_text = Text()
                action_text.append(f"{name}: ", style="bold")
                parts = []
                if action.prepare_commands:
                    parts.append("prepare")
                if action.upload_certs_commands or action.upload_keys_commands:
                    parts.append("upload")
                if action.update_commands:
                    parts.append("update")
                if parts:
                    action_text.append(", ".join(parts))
                else:
                    action_text.append("no commands", style="dim")
                actions_node.add(action_text)

        return Panel(tree, border_style="cyan")

    def render_health_summary(self, health: SystemHealth) -> Panel:
        """Render health summary panel."""
        content = Text()

        # Overall status
        icon = StatusStyle.get_icon(str(health.status))
        style = StatusStyle.get_style(str(health.status))
        content.append("Overall Status: ", style="bold")
        content.append(f"{icon} {health.status.name}\n", style=style)
        content.append("\n")

        # Certificate counts
        content.append("Certificate Status:\n", style="bold")
        content.append(f"  {StatusStyle.ICONS['healthy']} Healthy: ", style="dim")
        content.append(f"{health.healthy_count}\n", style=StatusStyle.HEALTHY)
        content.append(f"  {StatusStyle.ICONS['warning']} Warning: ", style="dim")
        content.append(f"{health.warning_count}\n", style=StatusStyle.WARNING)
        content.append(f"  {StatusStyle.ICONS['critical']} Critical: ", style="dim")
        content.append(f"{health.critical_count}\n", style=StatusStyle.CRITICAL)
        content.append(f"  {StatusStyle.ICONS['unknown']} Unknown: ", style="dim")
        content.append(f"{health.unknown_count}\n", style=StatusStyle.MUTED)
        content.append("\n")

        # Summary
        content.append(f"{health.summary}\n", style="dim")
        content.append(
            f"Checked at: {health.checked_at.strftime('%Y-%m-%d %H:%M:%S %Z')}",
            style="dim",
        )

        return Panel(
            content,
            title="[bold]Health Summary[/bold]",
            border_style=style,
        )

    def render_actions_summary(self, actions: DomainActions) -> Table:
        """Render actions configuration summary."""
        table = Table(
            title="Deployment Actions",
            show_header=True,
            header_style="bold cyan",
            border_style="bright_black",
        )

        table.add_column("Action Group", style="bold")
        table.add_column("Domains", overflow="fold")
        table.add_column("Prepare", justify="center")
        table.add_column("Upload Certs", justify="center")
        table.add_column("Upload Keys", justify="center")
        table.add_column("Update", justify="center")

        for name, action in actions.all_action_names().items():
            domains_str = (
                ", ".join(action.domains[:3])
                if action.domains
                else f"[dim]{_group_scope(name)}[/dim]"
            )
            if len(action.domains) > 3:
                domains_str += f" (+{len(action.domains) - 3})"

            def cmd_status(cmds: list | None) -> str:
                if cmds:
                    return f"[green]✓[/green] ({len(cmds)})"
                return "[dim]-[/dim]"

            table.add_row(
                name,
                domains_str,
                cmd_status(action.prepare_commands),
                cmd_status(action.upload_certs_commands),
                cmd_status(action.upload_keys_commands),
                cmd_status(action.update_commands),
            )

        return table


class Report:
    """Complete report with all sections."""

    def __init__(
        self,
        config: LemattConfig,
        domains: Sequence[DomainConfig],
        actions: DomainActions | None = None,
        health: SystemHealth | None = None,
        report_config: ReportConfig | None = None,
        key_types: Sequence[KeyType] = DEFAULT_KEY_TYPES,
    ):
        self.config = config
        self.domains = domains
        self.actions = actions
        self.health = health
        self.report_config = report_config or ReportConfig()
        self.key_types = key_types
        self.generator = ReportGenerator(
            config, domains, health, self.report_config, key_types
        )
        self.renderer = ReportRenderer()

    def config_summary(self) -> dict[str, Any]:
        return config_summary(self.config, self.domains, self.actions, self.key_types)

    def render_full_report(self) -> Group:
        """Render the complete report."""
        sections: list[Any] = []

        # Header with TEST MODE warning if applicable
        if self.config.is_test:
            header = Panel(
                Text.from_markup(
                    f"[bold red]⚠ TEST MODE - STAGING CERTIFICATES ONLY ⚠[/bold red]\n"
                    f"[bold cyan]{self.report_config.title}[/bold cyan]\n"
                    f"[dim]Generated: {self.report_config.generated_at.strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
                ),
                border_style="red",
                style="on red",
            )
        else:
            header = Panel(
                Text.from_markup(
                    f"[bold cyan]{self.report_config.title}[/bold cyan]\n"
                    f"[dim]Generated: {self.report_config.generated_at.strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
                ),
                border_style="cyan",
            )
        sections.append(header)
        sections.append(Text())

        # Health summary
        if self.report_config.include_health and self.health:
            sections.append(self.renderer.render_health_summary(self.health))
            sections.append(Text())

        # Certificate inventory
        if self.report_config.include_inventory:
            inventory = self.generator.build_inventory()
            sections.append(
                self.renderer.render_inventory_table(
                    inventory,
                    show_paths=self.report_config.show_paths,
                    is_test=self.config.is_test,
                )
            )
            sections.append(Text())

        # Renewal schedule
        if self.report_config.include_schedule:
            schedule = self.generator.build_renewal_schedule()
            sections.append(
                self.renderer.render_schedule_table(
                    schedule, is_test=self.config.is_test
                )
            )
            sections.append(Text())

        # Configuration summary
        if self.report_config.include_config:
            sections.append(
                self.renderer.render_config_summary(self.config_summary(), self.actions)
            )
            sections.append(Text())

        # Actions summary
        if self.report_config.include_actions and self.actions:
            sections.append(self.renderer.render_actions_summary(self.actions))

        return Group(*sections)

    def print_report(self) -> None:
        """Print the full report to the console."""
        console.print(self.render_full_report())

    def to_text(self, width: int = 120) -> str:
        """The console report as plain text (no colors), e.g. for a file."""
        buffer = io.StringIO()
        Console(file=buffer, width=width, color_system=None).print(
            self.render_full_report()
        )
        return buffer.getvalue()

    def render(self, format: str) -> str:
        """The report as text in one of REPORT_FORMATS."""
        renderers = {
            "console": self.to_text,
            "json": self.to_json,
            "markdown": self.to_markdown,
        }
        if format not in renderers:
            raise ValueError(f"Unknown report format: {format!r}")
        return renderers[format]()

    def to_dict(self) -> dict:
        """Export report as a dictionary."""
        inventory = self.generator.build_inventory()
        schedule = self.generator.build_renewal_schedule()

        return {
            "title": self.report_config.title,
            "generated_at": self.report_config.generated_at.isoformat(),
            "health": self.health.to_dict() if self.health else None,
            "inventory": [
                {
                    "domain": item.domain,
                    "key_type": item.key_type,
                    "status": item.status,
                    "days_until_expiry": item.days_until_expiry,
                    "not_after": item.not_after.isoformat() if item.not_after else None,
                    "cert_path": str(item.cert_path),
                    "san_domains": item.san_domains,
                    "issuer": item.issuer,
                }
                for item in inventory
            ],
            "schedule": [
                {
                    "domain": item.domain,
                    "key_type": item.key_type,
                    "current_expiry": item.current_expiry.isoformat()
                    if item.current_expiry
                    else None,
                    "renewal_date": item.renewal_date.isoformat()
                    if item.renewal_date
                    else None,
                    "days_until_renewal": item.days_until_renewal,
                    "priority": item.priority,
                }
                for item in schedule
            ],
            "config": self.config_summary(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Export report as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Export report as Markdown."""
        inventory = self.generator.build_inventory()
        schedule = self.generator.build_renewal_schedule()

        lines = [
            f"# {self.report_config.title}",
            "",
            f"*Generated: {self.report_config.generated_at.strftime('%Y-%m-%d %H:%M:%S')}*",
            "",
        ]

        # Health summary
        if self.health:
            lines.extend(
                [
                    "## Health Summary",
                    "",
                    f"**Overall Status:** {self.health.status.name}",
                    "",
                    f"- Healthy: {self.health.healthy_count}",
                    f"- Warning: {self.health.warning_count}",
                    f"- Critical: {self.health.critical_count}",
                    f"- Unknown: {self.health.unknown_count}",
                    "",
                    f"{self.health.summary}",
                    "",
                ]
            )

        # Certificate inventory
        lines.extend(
            [
                "## Certificate Inventory",
                "",
                "| Domain | Type | Status | Expires | Days | SANs | Certificate |",
                "|--------|------|--------|---------|------|------|-------------|",
            ]
        )

        for item in inventory:
            expires = item.not_after.strftime("%Y-%m-%d") if item.not_after else "-"
            days = (
                str(item.days_until_expiry)
                if item.days_until_expiry is not None
                else "-"
            )
            sans = str(len(item.san_domains)) if item.san_domains else "0"
            lines.append(
                f"| {item.domain} | {item.key_type.upper()} | {item.status} | "
                f"{expires} | {days} | {sans} | `{item.cert_path}` |"
            )

        lines.append("")

        # Renewal schedule
        lines.extend(
            [
                "## Renewal Schedule",
                "",
                "| Priority | Domain | Type | Expiry | Renewal | Days |",
                "|----------|--------|------|--------|---------|------|",
            ]
        )

        schedule_item: RenewalScheduleItem
        for schedule_item in schedule:
            expiry = (
                schedule_item.current_expiry.strftime("%Y-%m-%d")
                if schedule_item.current_expiry
                else "-"
            )
            renewal = (
                schedule_item.renewal_date.strftime("%Y-%m-%d")
                if schedule_item.renewal_date
                else "-"
            )
            days = (
                str(schedule_item.days_until_renewal)
                if schedule_item.days_until_renewal is not None
                else "-"
            )
            lines.append(
                f"| {schedule_item.priority} | {schedule_item.domain} | {schedule_item.key_type.upper()} | "
                f"{expiry} | {renewal} | {days} |"
            )

        lines.append("")

        # Configuration
        summary = self.config_summary()
        lines.extend(["## Configuration", ""])
        lines.extend(
            f"- {label}: `{_summary_value(summary[key])}`"
            for key, label in _SUMMARY_LABELS.items()
        )
        lines.extend(
            [
                f"- Key types: {', '.join(summary['key_types'])}",
                f"- Certificates: {summary['domain_count']} "
                f"({summary['san_count']} additional names)",
                "",
            ]
        )

        # Deployment actions
        if self.actions:
            lines.extend(
                [
                    "## Deployment Actions",
                    "",
                    "| Group | Domains | Prepare | Upload Certs | Upload Keys | Update |",
                    "|-------|---------|---------|--------------|-------------|--------|",
                ]
            )
            for name, action in self.actions.all_action_names().items():
                lines.append(
                    f"| {name} | {', '.join(action.domains) or _group_scope(name)} | "
                    f"{len(action.prepare_commands)} | "
                    f"{len(action.upload_certs_commands)} | "
                    f"{len(action.upload_keys_commands)} | "
                    f"{len(action.update_commands)} |"
                )
            lines.append("")

        return "\n".join(lines)


def generate_full_report(
    config: LemattConfig,
    domains: Sequence[DomainConfig],
    actions: DomainActions | None = None,
    health: SystemHealth | None = None,
    output_path: Path | None = None,
    format: str | None = None,
) -> None:
    """Print the full report, or write it to ``output_path``.

    Args:
        config: lematt configuration
        domains: Configured certificate lines
        actions: Configured action groups
        health: Optional health check results
        output_path: File to write instead of printing
        format: One of REPORT_FORMATS (default: from output_path's
            extension, else console)
    """
    report = Report(config, domains, actions, health)
    output_format = report_format(output_path, format)

    if output_path is None:
        if output_format == "console":
            report.print_report()
        else:
            sys.stdout.write(report.render(output_format) + "\n")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report.render(output_format))
    console.print(f"[green]✓[/green] {output_format} report saved to {output_path}")
