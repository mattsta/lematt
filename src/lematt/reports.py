"""Summary reports for certificate management.

This module generates comprehensive, human-readable reports including
certificate inventory, renewal schedules, configuration summaries,
and operational status.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .config import LemattConfig
from .display import DisplayConfig, StatusStyle, console
from .health import SystemHealth


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
    cert_path: str | None
    key_path: str | None
    san_domains: list[str] = field(default_factory=list)
    issuer: str | None = None
    file_size: int | None = None


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
        health: SystemHealth | None = None,
        report_config: ReportConfig | None = None,
    ):
        self.config = config
        self.health = health
        self.report_config = report_config or ReportConfig()

    def build_inventory(self) -> list[CertificateInventoryItem]:
        """Build certificate inventory from config and health data."""
        inventory = []

        for domain_config in self.config.domains:
            for key_type in self.config.key_types:
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

                # Get file size if path exists
                file_size = None
                if cert_path and Path(cert_path).exists():
                    file_size = Path(cert_path).stat().st_size

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
                    )
                )

        return inventory

    def build_renewal_schedule(
        self, renewal_threshold_days: int = 30
    ) -> list[RenewalScheduleItem]:
        """Build renewal schedule based on expiry dates."""
        schedule = []
        now = datetime.now()

        for item in self.build_inventory():
            if item.not_after:
                # Calculate renewal date (threshold days before expiry)
                renewal_date = item.not_after - timedelta(days=renewal_threshold_days)
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

    def __init__(self, display_config: DisplayConfig | None = None):
        self.display_config = display_config or DisplayConfig()

    def render_inventory_table(
        self, inventory: list[CertificateInventoryItem], show_paths: bool = True
    ) -> Table:
        """Render certificate inventory as a table."""
        table = Table(
            title="Certificate Inventory",
            show_header=True,
            header_style="bold cyan",
            border_style="bright_black",
            expand=True,
        )

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

            if show_paths:
                table.add_row(
                    item.domain,
                    item.key_type.upper(),
                    status_text,
                    expires,
                    days_text,
                    san_text,
                    item.cert_path or "-",
                )
            else:
                table.add_row(
                    item.domain,
                    item.key_type.upper(),
                    status_text,
                    expires,
                    days_text,
                    san_text,
                )

        return table

    def render_schedule_table(self, schedule: list[RenewalScheduleItem]) -> Table:
        """Render renewal schedule as a table."""
        table = Table(
            title="Renewal Schedule",
            show_header=True,
            header_style="bold cyan",
            border_style="bright_black",
            expand=True,
        )

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

            table.add_row(
                priority_text,
                item.domain,
                item.key_type.upper(),
                expiry,
                renewal,
                days_text,
            )

        return table

    def render_config_summary(self, config: LemattConfig) -> Panel:
        """Render configuration summary."""
        tree = Tree("[bold]Configuration Summary[/bold]")

        # Global settings
        global_node = tree.add("[cyan]Global Settings[/cyan]")
        global_node.add(f"Config file: [dim]{config.config_path or 'default'}[/dim]")
        global_node.add(f"Cert directory: [dim]{config.cert_directory}[/dim]")
        global_node.add(f"Webroot: [dim]{config.webroot_path}[/dim]")
        global_node.add(f"Test mode: [dim]{config.test_mode}[/dim]")

        # Key types
        keys_node = tree.add("[cyan]Key Types[/cyan]")
        for kt in config.key_types:
            keys_node.add(f"[green]✓[/green] {kt}")

        # Domains summary
        domains_node = tree.add("[cyan]Domains[/cyan]")
        domains_node.add(f"Total: {len(config.domains)}")
        san_total = sum(len(d.san_domains) for d in config.domains)
        domains_node.add(f"Total SANs: {san_total}")
        ocsp_count = sum(1 for d in config.domains if d.ocsp_staple_required)
        if ocsp_count > 0:
            domains_node.add(f"OCSP stapling: {ocsp_count}")

        # Actions summary
        if config.actions:
            actions_node = tree.add("[cyan]Actions[/cyan]")
            for name, action in config.actions.items():
                action_text = Text()
                action_text.append(f"{name}: ", style="bold")
                parts = []
                if action.prepare_commands:
                    parts.append("prepare")
                if action.upload_certs_commands or action.upload_keys_commands:
                    parts.append("upload")
                if action.update_commands:
                    parts.append("update")
                action_text.append(
                    ", ".join(parts) if parts else "[dim]no commands[/dim]"
                )
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
            f"Checked at: {health.checked_at.strftime('%Y-%m-%d %H:%M:%S')}",
            style="dim",
        )

        return Panel(
            content,
            title="[bold]Health Summary[/bold]",
            border_style=style,
        )

    def render_actions_summary(self, config: LemattConfig) -> Table:
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

        if not config.actions:
            return table

        for name, action in config.actions.items():
            domains_str = (
                ", ".join(action.domains[:3]) if action.domains else "[dim]all[/dim]"
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
        health: SystemHealth | None = None,
        report_config: ReportConfig | None = None,
    ):
        self.config = config
        self.health = health
        self.report_config = report_config or ReportConfig()
        self.generator = ReportGenerator(config, health, self.report_config)
        self.renderer = ReportRenderer()

    def render_full_report(self) -> Group:
        """Render the complete report."""
        sections = []

        # Header
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
                    inventory, show_paths=self.report_config.show_paths
                )
            )
            sections.append(Text())

        # Renewal schedule
        if self.report_config.include_schedule:
            schedule = self.generator.build_renewal_schedule()
            sections.append(self.renderer.render_schedule_table(schedule))
            sections.append(Text())

        # Configuration summary
        if self.report_config.include_config:
            sections.append(self.renderer.render_config_summary(self.config))
            sections.append(Text())

        # Actions summary
        if self.report_config.include_actions and self.config.actions:
            sections.append(self.renderer.render_actions_summary(self.config))

        return Group(*sections)

    def print_report(self) -> None:
        """Print the full report to the console."""
        console.print(self.render_full_report())

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
                    "cert_path": item.cert_path,
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
            "config": {
                "cert_directory": str(self.config.cert_directory),
                "webroot_path": str(self.config.webroot_path),
                "test_mode": self.config.test_mode,
                "key_types": [str(kt) for kt in self.config.key_types],
                "domain_count": len(self.config.domains),
                "action_groups": list(self.config.actions.keys())
                if self.config.actions
                else [],
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Export report as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, path: Path) -> None:
        """Save report as JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json())

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
                "| Domain | Type | Status | Expires | Days | SANs |",
                "|--------|------|--------|---------|------|------|",
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
                f"{expires} | {days} | {sans} |"
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

        for item in schedule:
            expiry = (
                item.current_expiry.strftime("%Y-%m-%d") if item.current_expiry else "-"
            )
            renewal = (
                item.renewal_date.strftime("%Y-%m-%d") if item.renewal_date else "-"
            )
            days = (
                str(item.days_until_renewal)
                if item.days_until_renewal is not None
                else "-"
            )
            lines.append(
                f"| {item.priority} | {item.domain} | {item.key_type.upper()} | "
                f"{expiry} | {renewal} | {days} |"
            )

        lines.append("")

        # Configuration
        lines.extend(
            [
                "## Configuration",
                "",
                f"- Certificate Directory: `{self.config.cert_directory}`",
                f"- Webroot Path: `{self.config.webroot_path}`",
                f"- Test Mode: {self.config.test_mode}",
                f"- Key Types: {', '.join(str(kt) for kt in self.config.key_types)}",
                f"- Domains: {len(self.config.domains)}",
                "",
            ]
        )

        return "\n".join(lines)

    def save_markdown(self, path: Path) -> None:
        """Save report as Markdown file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown())


def generate_quick_report(
    config: LemattConfig, health: SystemHealth | None = None
) -> None:
    """Generate and print a quick summary report.

    Args:
        config: lematt configuration
        health: Optional health check results
    """
    report = Report(
        config,
        health,
        ReportConfig(
            title="Quick Status Report",
            include_config=False,
            include_actions=False,
            show_paths=False,
        ),
    )
    report.print_report()


def generate_full_report(
    config: LemattConfig,
    health: SystemHealth | None = None,
    output_path: Path | None = None,
    format: str = "console",
) -> None:
    """Generate a full report.

    Args:
        config: lematt configuration
        health: Optional health check results
        output_path: Optional path to save report
        format: Output format (console, json, markdown)
    """
    report = Report(config, health)

    if format == "json" and output_path:
        report.save_json(output_path)
        console.print(f"[green]✓[/green] Report saved to {output_path}")
    elif format == "markdown" and output_path:
        report.save_markdown(output_path)
        console.print(f"[green]✓[/green] Report saved to {output_path}")
    else:
        report.print_report()
