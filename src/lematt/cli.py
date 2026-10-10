"""Command-line interface for lematt.

``main()`` parses arguments, runs any command that needs no configuration
(help, examples, systemd), otherwise loads the configuration once and
dispatches to the selected command, defaulting to a renewal run.
"""

import argparse
import contextlib
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from lematt.actions import ActionRunner
from lematt.config import (
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
)
from lematt.config_loader import ConfigError, ConfigLoader
from lematt.executor import CertificateExecutor, create_progress_printer
from lematt.log import EVENT, setup_logging
from lematt.manager import CertificateManager
from lematt.state import RunLockedError, StateStore

# Exit code when another renewal run holds the lock (EX_TEMPFAIL)
EXIT_RUN_LOCKED = 75


@dataclass
class Context:
    """Everything a configured command needs, loaded once."""

    args: argparse.Namespace
    loader: ConfigLoader
    config: LemattConfig
    domains: list[DomainConfig]
    actions: DomainActions


def load_configuration(
    config_path: str, *, require_write_access: bool
) -> ConfigLoader | None:
    """Load and validate the configuration, logging any problems.

    Args:
        config_path: Path given with --config (.toml selects TOML, else INI).
        require_write_access: Whether the challenge directory must exist.

    Returns:
        The loaded configuration, or None if it is unusable.
    """
    path = Path(config_path)
    loader = ConfigLoader(
        config_base=Path(os.path.realpath(path)).parent, config_file=path
    )
    try:
        loader.load()
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_path}")
        return None
    except ConfigError as e:
        logger.error(f"Config error: {e}")
        return None

    errors, warnings = loader.validate(require_write_access=require_write_access)
    for warning in warnings:
        logger.warning(f"Config warning: {warning}")
    if errors:
        for error in errors:
            logger.error(f"Config error: {error}")
        logger.error("Configuration validation failed.")
        return None
    return loader


def load_context(
    args: argparse.Namespace, *, require_write_access: bool
) -> Context | None:
    """Load configuration, domains and actions for a command."""
    loader = load_configuration(args.config, require_write_access=require_write_access)
    if loader is None:
        return None
    config = loader.get_lematt_config(
        is_test=args.is_test,
        is_cron=args.is_cron,
        is_dry_run=args.dry_run,
        force_renew=args.force_renew,
        concurrency=args.concurrency,
        verbose=args.verbose,
    )
    try:
        return Context(args, loader, config, loader.get_domains(), loader.get_actions())
    except ConfigError as e:
        logger.error(f"Config error: {e}")
        return None


def finish_report(summary: RenewalSummary, *, interrupted: bool = False) -> int:
    """Log the final run summary and return the process exit code.

    The summary is an EVENT (shown in cron mode) only when something was
    renewed or failed, so cron runs with nothing due stay silent.
    """
    changed = summary.renewed_count > 0 or summary.failed_count > 0
    logger.log(
        EVENT if changed else "INFO",
        f"{'Interrupted - Partial results' if interrupted else 'Completed'}: "
        f"{summary.total_domains} certificates - "
        f"Renewed: {summary.renewed_count}, Failed: {summary.failed_count}, "
        f"Skipped: {summary.skipped_count}",
    )
    return 1 if summary.failed_count > 0 else 0


def build_parser() -> argparse.ArgumentParser:
    """The lematt argument parser."""
    parser = argparse.ArgumentParser(
        description="Matt's Let's Encrypt Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode selection (required, mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--prod",
        dest="is_test",
        action="store_false",
        help="Use LE production endpoint (rate limited: 5 certs per exact name set per week)",
    )
    mode_group.add_argument(
        "--test",
        dest="is_test",
        action="store_true",
        help="Use LE staging endpoint (keys/certs will have 'test' suffix)",
    )

    # Execution options
    parser.add_argument(
        "--cron",
        dest="is_cron",
        action="store_true",
        help="Only produce output when changes happen",
    )
    parser.add_argument(
        "--parallel",
        dest="concurrency",
        default=1,
        type=int,
        help="Number of certificates to process in parallel (max 10)",
    )
    parser.add_argument(
        "--config",
        dest="config",
        default="conf/lematt.conf",
        help="Path to lematt.conf (other configs in same directory)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose output (show debug messages)",
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--status",
        dest="show_status",
        action="store_true",
        help="Show certificate status and exit",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Output status as JSON (use with --status)",
    )
    parser.add_argument(
        "--list-domains",
        dest="list_domains",
        action="store_true",
        help="List all configured domains and exit",
    )
    parser.add_argument(
        "--validate-config",
        dest="validate_only",
        action="store_true",
        help="Validate configuration without processing certificates",
    )
    parser.add_argument(
        "--domain",
        dest="single_domain",
        default=None,
        help="Process only a specific domain",
    )
    parser.add_argument(
        "--force-renew",
        dest="force_renew",
        action="store_true",
        help="Force renewal regardless of expiration date",
    )
    parser.add_argument(
        "--init-toml",
        dest="init_toml",
        action="store_true",
        help="Create example lematt.toml configuration file and exit",
    )

    # Systemd management
    systemd_group = parser.add_argument_group("systemd automation")
    systemd_group.add_argument(
        "--install-systemd",
        dest="install_systemd",
        action="store_true",
        help="Install systemd timer and service for automated renewals",
    )
    systemd_group.add_argument(
        "--uninstall-systemd",
        dest="uninstall_systemd",
        action="store_true",
        help="Remove systemd timer and service",
    )
    systemd_group.add_argument(
        "--systemd-status",
        dest="systemd_status",
        action="store_true",
        help="Show status of systemd timer",
    )
    systemd_group.add_argument(
        "--systemd-preset",
        dest="systemd_preset",
        choices=["default", "aggressive", "conservative", "weekly"],
        default="default",
        help="Systemd timer schedule preset (default: twice daily)",
    )

    # Health check and monitoring
    health_group = parser.add_argument_group("health checks and monitoring")
    health_group.add_argument(
        "--health-check",
        dest="health_check",
        action="store_true",
        help="Run health check on all certificates",
    )
    health_group.add_argument(
        "--check-live",
        dest="check_live",
        action="store_true",
        help="Check live certificates served by domains (with --health-check)",
    )
    health_group.add_argument(
        "--warning-days",
        dest="warning_days",
        type=int,
        default=14,
        help="Days before expiry to warn (default: 14)",
    )
    health_group.add_argument(
        "--critical-days",
        dest="critical_days",
        type=int,
        default=7,
        help="Days before expiry for critical alert (default: 7)",
    )
    health_group.add_argument(
        "--prometheus",
        dest="prometheus_output",
        action="store_true",
        help="Output health check as Prometheus metrics",
    )
    health_group.add_argument(
        "--write-health",
        dest="write_health",
        metavar="PATH",
        help="Write health status to file (for monitoring)",
    )

    # Notification configuration
    notify_group = parser.add_argument_group("notifications")
    notify_group.add_argument(
        "--init-notifications",
        dest="init_notifications",
        action="store_true",
        help="Create example notification configuration file",
    )
    notify_group.add_argument(
        "--test-notification",
        dest="test_notification",
        action="store_true",
        help="Send a test notification to verify configuration",
    )

    # Interactive UI features
    ui_group = parser.add_argument_group("interactive UI")
    ui_group.add_argument(
        "--dashboard",
        dest="dashboard",
        action="store_true",
        help="Launch interactive dashboard with live certificate status",
    )
    ui_group.add_argument(
        "--dashboard-refresh",
        dest="dashboard_refresh",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Dashboard refresh interval in seconds (default: 5)",
    )
    ui_group.add_argument(
        "--dashboard-compact",
        dest="dashboard_compact",
        action="store_true",
        help="Use compact display mode for dashboard",
    )
    ui_group.add_argument(
        "--report",
        dest="report",
        action="store_true",
        help="Generate comprehensive certificate report",
    )
    ui_group.add_argument(
        "--report-output",
        dest="report_output",
        metavar="PATH",
        help="Save report to file (auto-detects format from extension)",
    )
    ui_group.add_argument(
        "--report-format",
        dest="report_format",
        choices=["console", "json", "markdown"],
        default="console",
        help="Report output format (default: console)",
    )
    ui_group.add_argument(
        "--help-topic",
        dest="help_topic",
        metavar="TOPIC",
        nargs="?",
        const="",
        help="Show detailed help for a topic (use without argument to list topics)",
    )
    ui_group.add_argument(
        "--help-search",
        dest="help_search",
        metavar="QUERY",
        help="Search help topics for a keyword",
    )

    return parser


# ---------------------------------------------------------------------------
# Commands that need no configuration
# ---------------------------------------------------------------------------


def cmd_init_toml(args: argparse.Namespace) -> int:
    """--init-toml: write an example lematt.toml next to --config."""
    from lematt.config_loader import create_example_toml

    toml_path = Path(os.path.realpath(args.config)).parent / "lematt.toml"
    if toml_path.exists():
        logger.error(f"Config file already exists: {toml_path}")
        return 1
    create_example_toml(toml_path)
    logger.info("Edit the file and customize for your environment")
    return 0


def cmd_help_topic(args: argparse.Namespace) -> int:
    """--help-topic [TOPIC]: show a help topic (or list them)."""
    from lematt.help import print_help

    print_help(args.help_topic or None)
    return 0


def cmd_help_search(args: argparse.Namespace) -> int:
    """--help-search QUERY: search help topics."""
    from lematt.help import search_help

    search_help(args.help_search)
    return 0


def cmd_init_notifications(args: argparse.Namespace) -> int:
    """--init-notifications: write an example notify.conf next to --config."""
    from lematt.systemd import generate_notify_config

    notify_path = Path(os.path.realpath(args.config)).parent / "notify.conf"
    if notify_path.exists():
        logger.error(f"Notification config already exists: {notify_path}")
        return 1
    try:
        notify_path.parent.mkdir(parents=True, exist_ok=True)
        notify_path.write_text(generate_notify_config())
    except PermissionError:
        logger.error(f"Permission denied writing {notify_path}")
        return 1
    logger.info(f"Created notification config: {notify_path}")
    logger.info("Edit the file to configure your notification backends")
    return 0


def cmd_systemd(args: argparse.Namespace) -> int:
    """--install-systemd / --uninstall-systemd / --systemd-status."""
    from lematt.systemd import PRESETS, SystemdConfig, SystemdInstaller

    preset = PRESETS.get(args.systemd_preset, PRESETS["default"])
    systemd_config = SystemdConfig(
        calendar=preset.calendar,
        randomized_delay_sec=preset.randomized_delay_sec,
        description=preset.description,
        config_file=os.path.realpath(args.config),
        use_test_mode=args.is_test,
        notify_on_failure=True,
        notify_command="/usr/local/bin/lematt-notify.sh",
    )
    installer = SystemdInstaller(config=systemd_config, dry_run=args.dry_run)

    if args.install_systemd:
        logger.info(f"Installing systemd timer ({args.systemd_preset} preset)")
        logger.info(f"  Schedule: {systemd_config.calendar}")
        logger.info(f"  Random delay: {systemd_config.randomized_delay_sec}s")
        if not installer.install():
            logger.error("Failed to install systemd units")
            return 1
        logger.info("Systemd timer installed and enabled")
        logger.info(f"  Service: {installer.service_path}")
        logger.info(f"  Timer: {installer.timer_path}")
        logger.info("Check status with: systemctl status lematt-renew.timer")
        return 0

    if args.uninstall_systemd:
        logger.info("Uninstalling systemd timer")
        if not installer.uninstall():
            logger.error("Failed to uninstall systemd units")
            return 1
        logger.info("Systemd timer uninstalled")
        return 0

    status = installer.status()
    if args.json_output:
        print(json.dumps(status, indent=2))
        return 0
    logger.info("Systemd timer status:")
    logger.info(f"  Service installed: {status['service_installed']}")
    logger.info(f"  Timer installed: {status['timer_installed']}")
    logger.info(f"  Timer active: {status['timer_active']}")
    logger.info(f"  Timer enabled: {status['timer_enabled']}")
    if status.get("next_trigger"):
        logger.info(f"  Next trigger: {status['next_trigger']}")
    if status.get("last_trigger"):
        logger.info(f"  Last trigger: {status['last_trigger']}")
    return 0


# ---------------------------------------------------------------------------
# Commands that use the configuration
# ---------------------------------------------------------------------------


def cmd_validate(ctx: Context) -> int:
    """--validate-config: summarize the (already validated) configuration."""
    logger.info("Configuration is valid!")
    logger.info(f"  Config base: {ctx.config.config_base}")
    logger.info(f"  Challenge dir: {ctx.config.challenge_dir}")
    logger.info(f"  Account key: {ctx.config.account_key}")
    logger.info(f"  RSA key bits: {ctx.config.rsa_key_bits}")
    logger.info(f"  EC curve: {ctx.config.ec_curve}")
    logger.info(f"  Domains configured: {len(ctx.domains)}")
    logger.info(f"  Action configs: {len(ctx.actions.all_action_names())}")
    return 0


def cmd_list_domains(ctx: Context) -> int:
    """--list-domains: print the configured certificates."""
    if ctx.args.json_output:
        print(
            json.dumps(
                [
                    {
                        "primary": d.primary_domain,
                        "sans": d.san_domains,
                        "all_domains": d.all_domains,
                    }
                    for d in ctx.domains
                ],
                indent=2,
            )
        )
        return 0
    logger.info(f"Configured domains ({len(ctx.domains)} certificates):")
    logger.info("-" * 60)
    for i, d in enumerate(ctx.domains, 1):
        logger.info(f"{i:3}. {d.primary_domain}")
        if d.san_domains:
            logger.info(f"     SANs: {', '.join(d.san_domains)}")
    return 0


def cmd_health(ctx: Context) -> int:
    """--health-check: check certificates; exit 0/1/2 for healthy/warning/critical."""
    from lematt.health import (
        HealthChecker,
        HealthStatus,
        PrometheusMetrics,
        write_health_status_file,
    )

    args = ctx.args
    checker = HealthChecker(
        config=ctx.config,
        warning_days=args.warning_days,
        critical_days=args.critical_days,
    )
    health = checker.check_all_certificates(ctx.domains)

    if args.check_live:
        logger.info("Checking live certificates...")
        for domain_config in ctx.domains:
            live = checker.check_live_certificate(domain_config.primary_domain)
            health.certificates.append(live)
            if live.status == HealthStatus.CRITICAL:
                health.status = HealthStatus.CRITICAL
            elif (
                live.status == HealthStatus.WARNING
                and health.status == HealthStatus.HEALTHY
            ):
                health.status = HealthStatus.WARNING

    if args.prometheus_output:
        print(PrometheusMetrics(health).generate())
    elif args.json_output:
        print(json.dumps(health.to_dict(), indent=2))
    else:
        icons = {
            HealthStatus.HEALTHY: "✓",
            HealthStatus.WARNING: "⚠",
            HealthStatus.CRITICAL: "✗",
            HealthStatus.UNKNOWN: "?",
        }
        logger.info(f"Health Check: {icons.get(health.status, '?')} {health.status}")
        logger.info(health.summary)
        logger.info("-" * 60)
        for cert in health.certificates:
            logger.info(
                f"  {icons.get(cert.status, '?')} {cert.domain} ({cert.key_type}): {cert.message}"
            )

    if args.write_health:
        health_path = Path(args.write_health)
        fmt = "prometheus" if args.prometheus_output else "json"
        write_health_status_file(health, health_path, format=fmt)
        logger.info(f"Wrote health status to {health_path}")

    if health.status == HealthStatus.CRITICAL:
        return 2
    if health.status == HealthStatus.WARNING:
        return 1
    return 0


def cmd_dashboard(ctx: Context) -> int:
    """--dashboard: interactive terminal dashboard."""
    from lematt.health import HealthChecker
    from lematt.tui.app import DashboardConfig, LemattDashboardApp

    args = ctx.args
    app = LemattDashboardApp(
        health_checker=HealthChecker(
            config=ctx.config,
            warning_days=args.warning_days,
            critical_days=args.critical_days,
        ),
        domains=ctx.domains,
        config=DashboardConfig(
            refresh_interval=args.dashboard_refresh,
            compact_mode=args.dashboard_compact,
            warning_days=args.warning_days,
            critical_days=args.critical_days,
        ),
    )
    with contextlib.suppress(KeyboardInterrupt):
        app.run()
    return 0


def cmd_report(ctx: Context) -> int:
    """--report: inventory and renewal report (console, JSON or Markdown)."""
    from lematt.health import HealthChecker
    from lematt.reports import generate_full_report

    args = ctx.args
    config = ctx.config
    # The report reads these alongside the settings
    config.domains = ctx.domains  # type: ignore[attr-defined]
    config.key_types = [KeyType.RSA, KeyType.EC]  # type: ignore[attr-defined]
    config.actions = ctx.actions  # type: ignore[attr-defined]

    health = HealthChecker(
        config=config,
        warning_days=args.warning_days,
        critical_days=args.critical_days,
    ).check_all_certificates(ctx.domains)

    output_path = Path(args.report_output) if args.report_output else None
    output_format = args.report_format
    if output_path and output_path.suffix == ".json":
        output_format = "json"
    elif output_path and output_path.suffix in (".md", ".markdown"):
        output_format = "markdown"

    generate_full_report(
        config=config, health=health, output_path=output_path, format=output_format
    )
    return 0


def cmd_test_notification(ctx: Context) -> int:
    """--test-notification: send a test event to each configured backend."""
    from lematt.notifications import NotificationConfig, NotificationEvent

    # Settings live in the TOML [notifications] table: the --config file
    # itself when it's TOML, else a lematt.toml beside it
    settings = ctx.loader.notifications
    toml_path = ctx.loader.config_base / "lematt.toml"
    if not settings and ctx.loader.format == "ini" and toml_path.exists():
        notify_loader = ConfigLoader(ctx.loader.config_base, config_file=toml_path)
        try:
            notify_loader.load()
        except ConfigError as e:
            logger.error(f"Config error: {e}")
            return 1
        settings = notify_loader.notifications

    notify_config = NotificationConfig()
    if settings:
        notify_config = NotificationConfig(
            email_to=settings.get("email_to"),
            email_from=settings.get("email_from", "lematt@localhost"),
            webhook_url=settings.get("webhook_url"),
            webhook_format=settings.get("webhook_format", "slack"),
            pagerduty_key=settings.get("pagerduty_key"),
            ntfy_topic=settings.get("ntfy_topic"),
            ntfy_server=settings.get("ntfy_server", "https://ntfy.sh"),
            custom_command=settings.get("custom_command"),
            journald_enabled=settings.get("journald_enabled", True),
        )

    manager = notify_config.create_manager()
    if not manager.backends:
        logger.error("No notification backends configured")
        logger.error("Configure notifications in lematt.toml [notifications] section")
        return 1

    logger.info(f"Testing {len(manager.backends)} notification backend(s)...")
    event = NotificationEvent(
        event_type="info",
        title="Test Notification",
        message="This is a test notification from lematt",
        details={"test": True, "config_path": str(ctx.loader.config_base)},
    )
    manager.notify_on_success = True  # deliver even though it's not a failure
    results = manager.notify(event)

    for backend_name, success in results.items():
        logger.info(f"  {'✓' if success else '✗'} {backend_name}")
    failures = sum(1 for ok in results.values() if not ok)
    if failures:
        logger.warning(f"Some notifications failed: {failures}/{len(results)}")
        return 1
    logger.info(f"All notifications sent successfully: {len(results)}")
    return 0


def selected_domains(ctx: Context) -> list[DomainConfig] | None:
    """The certificates to act on (all, or the one --domain names)."""
    wanted = ctx.args.single_domain
    if not wanted:
        return ctx.domains
    selected = [d for d in ctx.domains if wanted in d.all_domains]
    if not selected:
        logger.error(f"Domain '{wanted}' not found in configuration")
        return None
    logger.info(f"Processing single domain: {wanted}")
    return selected


def cmd_status(ctx: Context) -> int:
    """--status: certificate expiry table (or JSON)."""
    domains = selected_domains(ctx)
    if domains is None:
        return 1
    status = CertificateManager(ctx.config).show_status(
        domains, json_output=ctx.args.json_output
    )
    if ctx.args.json_output and status:
        print(json.dumps(status, indent=2))
    return 0


def cmd_renew(ctx: Context) -> int:
    """Default command: renew due certificates, then run deployment actions."""
    args, config = ctx.args, ctx.config
    domains = selected_domains(ctx)
    if domains is None:
        return 1

    if not args.is_cron:
        prefix = (
            "[TEST MODE — DO NOT USE TEST CERTS IN PRODUCTION] " if args.is_test else ""
        )
        logger.info(f"{prefix}Welcome to LE Matt!")
        if args.dry_run:
            logger.info("[DRY-RUN MODE - No changes will be made]")
        logger.info("Using domain list:")
        for domain in domains:
            logger.info(f"\t{domain}")

    if not os.path.isfile(config.account_key):
        logger.error(f"Account key doesn't exist: {config.account_key}")
        logger.error("Create with: openssl genrsa 4096 > key.pem")
        return 1

    if config.is_dry_run:
        return run_renewal(ctx, domains)
    try:
        with StateStore(Path(config.state_dir)).run_lock():
            return run_renewal(ctx, domains)
    except RunLockedError as e:
        logger.warning(f"Not starting: {e}")
        return EXIT_RUN_LOCKED


def run_renewal(ctx: Context, domains: list[DomainConfig]) -> int:
    """Process ``domains``, then deploy what was renewed; return the exit code."""
    args, config = ctx.args, ctx.config
    CertificateManager(config).ensure_directories()
    action_runner = ActionRunner(config, actions=ctx.actions)
    executor = CertificateExecutor(
        config=config,
        max_workers=config.concurrency,
        progress_callback=None
        if args.is_cron
        else create_progress_printer(args.verbose),
    )

    interrupted = False
    try:
        summary = executor.process_batch(domains=domains, domain_actions=ctx.actions)
    except KeyboardInterrupt:
        # Still deploy whatever was renewed before the interrupt
        logger.warning("Interrupted by user - processing successful renewals...")
        interrupted = True
        summary = executor.summary

    exit_code = finish_report(summary, interrupted=interrupted)

    # Deploy renewed certificates (uploads, reloads), even after an interrupt
    if summary.results:
        try:
            action_runner.process_updated_certs(summary.results)
        except Exception as e:
            logger.error(f"Error running after-issue hooks: {e}")
            if not interrupted:
                raise

    if interrupted:
        logger.warning("Exiting due to interrupt - after-issue hooks completed")
        return 130  # conventional exit code for SIGINT
    return exit_code


type Predicate = Callable[[argparse.Namespace], object]

# Checked in order; the first match runs
STANDALONE_COMMANDS: list[tuple[Predicate, Callable[[argparse.Namespace], int]]] = [
    (lambda a: a.init_toml, cmd_init_toml),
    (lambda a: a.help_topic is not None, cmd_help_topic),
    (lambda a: a.help_search, cmd_help_search),
    (lambda a: a.init_notifications, cmd_init_notifications),
    (
        lambda a: a.install_systemd or a.uninstall_systemd or a.systemd_status,
        cmd_systemd,
    ),
]

# (selected?, command, read-only: doesn't need the challenge directory)
CONFIGURED_COMMANDS: list[tuple[Predicate, Callable[[Context], int], bool]] = [
    (lambda a: a.validate_only, cmd_validate, True),
    (lambda a: a.list_domains, cmd_list_domains, True),
    (lambda a: a.health_check, cmd_health, True),
    (lambda a: a.dashboard, cmd_dashboard, True),
    (lambda a: a.report, cmd_report, True),
    (lambda a: a.test_notification, cmd_test_notification, False),
    (lambda a: a.show_status, cmd_status, True),
]


def main(argv: Sequence[str] | None = None) -> int:
    """Run lematt; returns the process exit code."""
    args = build_parser().parse_args(argv)
    setup_logging(verbose=args.verbose, cron=args.is_cron, test_mode=args.is_test)

    for selected, standalone in STANDALONE_COMMANDS:
        if selected(args):
            return standalone(args)

    command: Callable[[Context], int] = cmd_renew
    read_only = False
    for selected, configured, is_read_only in CONFIGURED_COMMANDS:
        if selected(args):
            command, read_only = configured, is_read_only
            break

    ctx = load_context(args, require_write_access=not read_only)
    if ctx is None:
        return 1
    return command(ctx)


if __name__ == "__main__":
    sys.exit(main())
