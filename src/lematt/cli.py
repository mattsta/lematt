"""Command-line interface for lematt.

This module provides the CLI entry point and argument parsing
for the lematt certificate management tool.
"""

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

from loguru import logger

from lematt.actions import ActionRunner
from lematt.config import KeyType, RenewalSummary
from lematt.config_loader import ConfigError, ConfigLoader
from lematt.executor import CertificateExecutor, create_progress_printer
from lematt.log import EVENT, setup_logging
from lematt.manager import CertificateManager

# Rich display imports (lazy loaded for commands that need them)
HAS_RICH = True
try:
    from rich.console import Console

    console: Console | None = Console()
except ImportError:
    HAS_RICH = False
    console = None


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


def main() -> int:
    """Main entry point for lematt CLI.

    Returns:
        Exit code (0 for success, 1 for error).
    """
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

    args = parser.parse_args()

    # Set up logging
    setup_logging(verbose=args.verbose, cron=args.is_cron, test_mode=args.is_test)

    # Handle --init-toml: create example config and exit
    if args.init_toml:
        from lematt.config_loader import create_example_toml

        config_dir = Path(os.path.dirname(os.path.realpath(args.config)))
        toml_path = config_dir / "lematt.toml"
        if toml_path.exists():
            logger.error(f"Config file already exists: {toml_path}")
            return 1
        create_example_toml(toml_path)
        logger.info("Edit the file and customize for your environment")
        return 0

    # Handle --help-topic: show contextual help
    if args.help_topic is not None:
        if not HAS_RICH:
            logger.error(
                "Rich library required for help display. Install with: pip install rich"
            )
            return 1
        from lematt.help import print_help

        print_help(args.help_topic or None)
        return 0

    # Handle --help-search: search help topics
    if args.help_search:
        if not HAS_RICH:
            logger.error(
                "Rich library required for help display. Install with: pip install rich"
            )
            return 1
        from lematt.help import search_help

        search_help(args.help_search)
        return 0

    # Handle --init-notifications: create notification config
    if args.init_notifications:
        from lematt.systemd import generate_notify_config

        # Use config directory (same as domains, actions.conf, etc.)
        config_base = os.path.dirname(os.path.realpath(args.config))
        notify_path = Path(config_base) / "notify.conf"
        if notify_path.exists():
            logger.error(f"Notification config already exists: {notify_path}")
            return 1
        try:
            notify_path.parent.mkdir(parents=True, exist_ok=True)
            notify_path.write_text(generate_notify_config())
            logger.info(f"Created notification config: {notify_path}")
            logger.info("Edit the file to configure your notification backends")
        except PermissionError:
            logger.error(f"Permission denied writing {notify_path}")
            return 1
        return 0

    # Handle systemd commands (don't need full config)
    if args.install_systemd or args.uninstall_systemd or args.systemd_status:
        from lematt.systemd import PRESETS, SystemdConfig, SystemdInstaller

        config_path = os.path.realpath(args.config)

        # Get preset or use default
        preset_config = PRESETS.get(args.systemd_preset, PRESETS["default"])

        # Create config with actual config file path
        systemd_config = SystemdConfig(
            calendar=preset_config.calendar,
            randomized_delay_sec=preset_config.randomized_delay_sec,
            description=preset_config.description,
            config_file=config_path,
            use_test_mode=args.is_test,
            notify_on_failure=True,
            notify_command="/usr/local/bin/lematt-notify.sh",
        )

        installer = SystemdInstaller(config=systemd_config, dry_run=args.dry_run)

        if args.install_systemd:
            logger.info(f"Installing systemd timer ({args.systemd_preset} preset)")
            logger.info(f"  Schedule: {systemd_config.calendar}")
            logger.info(f"  Random delay: {systemd_config.randomized_delay_sec}s")
            if installer.install():
                logger.info("Systemd timer installed and enabled")
                logger.info(f"  Service: {installer.service_path}")
                logger.info(f"  Timer: {installer.timer_path}")
                logger.info("Check status with: systemctl status lematt-renew.timer")
            else:
                logger.error("Failed to install systemd units")
                return 1
            return 0

        if args.uninstall_systemd:
            logger.info("Uninstalling systemd timer")
            if installer.uninstall():
                logger.info("Systemd timer uninstalled")
            else:
                logger.error("Failed to uninstall systemd units")
                return 1
            return 0

        if args.systemd_status:
            status = installer.status()
            if args.json_output:
                print(json.dumps(status, indent=2))
            else:
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

    # Read-only commands don't need the challenge directory
    read_only_mode = (
        args.dashboard
        or args.health_check
        or args.show_status
        or args.report
        or args.list_domains
        or args.validate_only
    )

    loader = load_configuration(args.config, require_write_access=not read_only_mode)
    if loader is None:
        return 1
    config_base = str(loader.config_base)
    lematt_config = loader.get_lematt_config(
        is_test=args.is_test,
        is_cron=args.is_cron,
        is_dry_run=args.dry_run,
        force_renew=args.force_renew,
        concurrency=args.concurrency,
        verbose=args.verbose,
    )
    try:
        domains = loader.get_domains()
        domain_actions = loader.get_actions()
    except ConfigError as e:
        logger.error(f"Config error: {e}")
        return 1

    # Handle --validate-config: just validate and exit
    if args.validate_only:
        logger.info("Configuration is valid!")
        logger.info(f"  Config base: {config_base}")
        logger.info(f"  Challenge dir: {lematt_config.challenge_dir}")
        logger.info(f"  Account key: {lematt_config.account_key}")
        logger.info(f"  RSA key bits: {lematt_config.rsa_key_bits}")
        logger.info(f"  EC curve: {lematt_config.ec_curve}")
        logger.info(f"  Domains configured: {len(domains)}")
        logger.info(f"  Action configs: {len(domain_actions.all_action_names())}")
        return 0

    # Handle --list-domains: list all configured domains and exit
    if args.list_domains:
        if args.json_output:
            domain_list = []
            for d in domains:
                domain_list.append(
                    {
                        "primary": d.primary_domain,
                        "sans": d.san_domains,
                        "all_domains": d.all_domains,
                    }
                )
            print(json.dumps(domain_list, indent=2))  # JSON data output to stdout
        else:
            logger.info(f"Configured domains ({len(domains)} certificates):")
            logger.info("-" * 60)
            for i, d in enumerate(domains, 1):
                logger.info(f"{i:3}. {d.primary_domain}")
                if d.san_domains:
                    logger.info(f"     SANs: {', '.join(d.san_domains)}")
        return 0

    # Handle --health-check: run health checks on certificates
    if args.health_check:
        from lematt.health import (
            HealthChecker,
            HealthStatus,
            PrometheusMetrics,
            write_health_status_file,
        )

        checker = HealthChecker(
            config=lematt_config,
            warning_days=args.warning_days,
            critical_days=args.critical_days,
        )

        # Check file-based certificates
        health = checker.check_all_certificates(domains)

        # Optionally check live certificates
        if args.check_live:
            logger.info("Checking live certificates...")
            for domain_config in domains:
                live_health = checker.check_live_certificate(
                    domain_config.primary_domain
                )
                health.certificates.append(live_health)
                if live_health.status in (HealthStatus.CRITICAL, HealthStatus.WARNING):
                    if live_health.status == HealthStatus.CRITICAL:
                        health.status = HealthStatus.CRITICAL
                    elif health.status == HealthStatus.HEALTHY:
                        health.status = HealthStatus.WARNING

        # Output results
        if args.prometheus_output:
            metrics = PrometheusMetrics(health)
            print(metrics.generate())
        elif args.json_output:
            print(json.dumps(health.to_dict(), indent=2))
        else:
            status_icon = {
                HealthStatus.HEALTHY: "✓",
                HealthStatus.WARNING: "⚠",
                HealthStatus.CRITICAL: "✗",
                HealthStatus.UNKNOWN: "?",
            }
            logger.info(
                f"Health Check: {status_icon.get(health.status, '?')} {health.status}"
            )
            logger.info(health.summary)
            logger.info("-" * 60)
            for cert in health.certificates:
                icon = status_icon.get(cert.status, "?")
                logger.info(f"  {icon} {cert.domain} ({cert.key_type}): {cert.message}")

        # Write to file if requested
        if args.write_health:
            health_path = Path(args.write_health)
            fmt = "prometheus" if args.prometheus_output else "json"
            write_health_status_file(health, health_path, format=fmt)
            logger.info(f"Wrote health status to {health_path}")

        # Return appropriate exit code for monitoring
        if health.status == HealthStatus.CRITICAL:
            return 2
        elif health.status == HealthStatus.WARNING:
            return 1
        return 0

    # Handle --dashboard: launch interactive dashboard
    if args.dashboard:
        if not HAS_RICH:
            logger.error(
                "Rich library required for dashboard. Install with: pip install rich"
            )
            return 1

        from lematt.health import HealthChecker
        from lematt.tui.app import DashboardConfig, LemattDashboardApp

        health_checker = HealthChecker(
            config=lematt_config,
            warning_days=args.warning_days,
            critical_days=args.critical_days,
        )

        dashboard_config = DashboardConfig(
            refresh_interval=args.dashboard_refresh,
            compact_mode=args.dashboard_compact,
            warning_days=args.warning_days,
            critical_days=args.critical_days,
        )

        app = LemattDashboardApp(
            health_checker=health_checker,
            domains=domains,
            config=dashboard_config,
        )

        # Run the app - keyboard shortcuts shown in footer
        with contextlib.suppress(KeyboardInterrupt):
            app.run()
        return 0

    # Handle --report: generate certificate report
    if args.report:
        if not HAS_RICH:
            logger.error(
                "Rich library required for reports. Install with: pip install rich"
            )
            return 1

        from lematt.health import HealthChecker
        from lematt.reports import generate_full_report

        report_lematt_config = lematt_config

        # Add dynamic attributes for report generation
        report_lematt_config.domains = domains  # type: ignore[attr-defined]
        report_lematt_config.key_types = [KeyType.RSA, KeyType.EC]  # type: ignore[attr-defined]
        report_lematt_config.actions = domain_actions  # type: ignore[attr-defined]

        # Get health data for report
        health_checker = HealthChecker(
            config=report_lematt_config,
            warning_days=args.warning_days,
            critical_days=args.critical_days,
        )
        health = health_checker.check_all_certificates(domains)

        # Determine output format
        output_format = args.report_format
        output_path = Path(args.report_output) if args.report_output else None

        # Auto-detect format from extension if path provided
        if output_path:
            if output_path.suffix == ".json":
                output_format = "json"
            elif output_path.suffix in (".md", ".markdown"):
                output_format = "markdown"

        generate_full_report(
            config=report_lematt_config,
            health=health,
            output_path=output_path,
            format=output_format,
        )
        return 0

    # Handle --test-notification: send test notification
    if args.test_notification:
        from lematt.notifications import (
            NotificationConfig,
            NotificationEvent,
        )

        # Notification settings live in the TOML [notifications] table: the
        # --config file itself when it's TOML, else lematt.toml beside it
        notify_config = NotificationConfig()
        nc = loader.notifications
        toml_path = Path(config_base) / "lematt.toml"
        if not nc and loader.format == "ini" and toml_path.exists():
            notify_loader = ConfigLoader(Path(config_base), config_file=toml_path)
            try:
                notify_loader.load()
            except ConfigError as e:
                logger.error(f"Config error: {e}")
                return 1
            nc = notify_loader.notifications
        if nc:
            notify_config = NotificationConfig(
                email_to=nc.get("email_to"),
                email_from=nc.get("email_from", "lematt@localhost"),
                webhook_url=nc.get("webhook_url"),
                webhook_format=nc.get("webhook_format", "slack"),
                pagerduty_key=nc.get("pagerduty_key"),
                ntfy_topic=nc.get("ntfy_topic"),
                ntfy_server=nc.get("ntfy_server", "https://ntfy.sh"),
                custom_command=nc.get("custom_command"),
                journald_enabled=nc.get("journald_enabled", True),
            )

        manager = notify_config.create_manager()

        if not manager.backends:
            logger.error("No notification backends configured")
            logger.error(
                "Configure notifications in lematt.toml [notifications] section"
            )
            return 1

        logger.info(f"Testing {len(manager.backends)} notification backend(s)...")

        event = NotificationEvent(
            event_type="info",
            title="Test Notification",
            message="This is a test notification from lematt",
            details={"test": True, "config_path": str(config_base)},
        )

        # Force notification even for info events
        manager.notify_on_success = True
        results = manager.notify(event)

        success_count = sum(1 for v in results.values() if v)
        failure_count = sum(1 for v in results.values() if not v)

        for backend_name, success in results.items():
            check_mark = "✓" if success else "✗"
            logger.info(f"  {check_mark} {backend_name}")

        if failure_count > 0:
            logger.warning(f"Some notifications failed: {failure_count}/{len(results)}")
            return 1

        logger.info(f"All notifications sent successfully: {success_count}")
        return 0

    configured_domains = domains

    # Filter to single domain if requested
    if args.single_domain:
        filtered = [
            d
            for d in configured_domains
            if args.single_domain in d.all_domains
            or d.primary_domain == args.single_domain
        ]
        if not filtered:
            logger.error(f"Domain '{args.single_domain}' not found in configuration")
            return 1
        configured_domains = filtered
        logger.info(f"Processing single domain: {args.single_domain}")

    # Create manager
    cert_manager = CertificateManager(lematt_config)

    # Show status and exit if requested
    if args.show_status:
        status_data = cert_manager.show_status(
            configured_domains, json_output=args.json_output
        )
        if args.json_output and status_data:
            print(json.dumps(status_data, indent=2))  # JSON data output to stdout
        return 0

    # Display welcome message
    if not args.is_cron:
        prefix = (
            "[TEST MODE — DO NOT USE TEST CERTS IN PRODUCTION] " if args.is_test else ""
        )
        logger.info(f"{prefix}Welcome to LE Matt!")
        if args.dry_run:
            logger.info("[DRY-RUN MODE - No changes will be made]")
        logger.info("Using domain list:")
        for domain in configured_domains:
            logger.info(f"\t{domain}")

    # Verify account key exists
    if not os.path.isfile(lematt_config.account_key):
        logger.error(f"Account key doesn't exist: {lematt_config.account_key}")
        logger.error("Create with: openssl genrsa 4096 > key.pem")
        return 1

    # Ensure directories exist
    cert_manager.ensure_directories()

    # Actions run after the batch for every renewed certificate
    action_runner = ActionRunner(lematt_config, actions=domain_actions)

    # Process certificates using the robust executor
    progress_callback = (
        create_progress_printer(verbose=args.verbose) if not args.is_cron else None
    )

    executor = CertificateExecutor(
        config=lematt_config,
        max_workers=lematt_config.concurrency,
        progress_callback=progress_callback,
    )

    interrupted = False
    try:
        summary = executor.process_batch(
            domains=configured_domains,
            domain_actions=action_runner.domain_actions,
        )
    except KeyboardInterrupt:
        # Gracefully handle interrupt - still run hooks for successful renewals
        logger.warning("Interrupted by user - processing successful renewals...")
        interrupted = True
        summary = executor.summary

    exit_code = finish_report(summary, interrupted=interrupted)

    # CRITICAL: Process updated certificates (run after-issue hooks)
    # This must run even if interrupted to ensure successful renewals are deployed
    if summary.results:
        try:
            action_runner.process_updated_certs(summary.results)
        except Exception as e:
            logger.error(f"Error running after-issue hooks: {e}")
            if not interrupted:
                raise

    # Exit with error code if interrupted
    if interrupted:
        logger.warning("Exiting due to interrupt - after-issue hooks completed")
        sys.exit(130)  # Standard exit code for SIGINT

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
