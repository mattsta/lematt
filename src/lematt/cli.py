"""Command-line interface for lematt.

``main()`` parses arguments, runs any command that needs no configuration
(help, examples, systemd), otherwise loads the configuration once and
dispatches to the selected command, defaulting to a renewal run.
"""

import argparse
import contextlib
import dataclasses
import datetime
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from lematt.acme import REVOCATION_REASONS
from lematt.actions import ActionRunner
from lematt.config import (
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
)
from lematt.config_loader import ConfigError, ConfigLoader, action_group_overlaps
from lematt.crypto import get_certificate_info
from lematt.executor import CertificateExecutor, create_progress_printer
from lematt.log import EVENT, setup_logging
from lematt.manager import CertificateManager
from lematt.notifications import (
    NotificationConfig,
    NotificationManager,
    run_notifications,
)
from lematt.reports import REPORT_FORMATS
from lematt.state import RunLockedError, StateStore, parse_timestamp, utcnow

# Exit code when another renewal run holds the lock (EX_TEMPFAIL)
EXIT_RUN_LOCKED = 75

# --health-check exit code when it can't check (monitoring-plugin UNKNOWN)
EXIT_HEALTH_UNKNOWN = 3

USAGE_EXAMPLES = """\
examples:
  uv run lematt --test --validate-config      check the configuration
  uv run lematt --test                        renew against staging
  uv run lematt --prod --status               when each certificate renews
  uv run lematt --prod --cron                 scheduled production run
  uv run lematt --help-topic                  list detailed help topics
"""


@dataclass
class Context:
    """Everything a configured command needs, loaded once."""

    args: argparse.Namespace
    loader: ConfigLoader
    config: LemattConfig
    domains: list[DomainConfig]
    actions: DomainActions


def load_configuration(
    config_path: Path, *, require_write_access: bool
) -> ConfigLoader | None:
    """Load and validate the configuration, logging any problems.

    Args:
        config_path: Path given with --config (.toml selects TOML, else INI).
        require_write_access: Whether the challenge directory must exist.

    Returns:
        The loaded configuration, or None if it is unusable.
    """
    loader = ConfigLoader(
        config_base=config_path.resolve().parent, config_file=config_path
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
        domains, actions = loader.get_domains(), loader.get_actions()
    except ConfigError as e:
        logger.error(f"Config error: {e}")
        return None
    for warning in action_group_overlaps(domains, actions):
        logger.warning(f"Config warning: {warning}")
    return Context(args, loader, config, domains, actions)


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
        epilog=USAGE_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Mode selection (mutually exclusive; main() requires one unless the
    # command doesn't depend on it, see MODELESS_COMMANDS)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--prod",
        dest="is_test",
        action="store_false",
        default=None,
        help="Use LE production endpoint (rate limited: 5 certs per exact name set per week)",
    )
    mode_group.add_argument(
        "--test",
        dest="is_test",
        action="store_true",
        default=None,
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
        metavar="N",
        help="Process up to N certificate lines in parallel (max 10)",
    )
    parser.add_argument(
        "--config",
        dest="config",
        type=Path,
        default=Path("conf/lematt.conf"),
        metavar="PATH",
        help="lematt.conf or a .toml file; domains, actions.conf and keys live "
        "next to it (default: conf/lematt.conf)",
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
        help="JSON output for --status, --list-domains, --health-check and "
        "--systemd-status",
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
        metavar="NAME",
        help="Only the certificate lines containing NAME",
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
    parser.add_argument(
        "--caa-records",
        dest="caa_records",
        action="store_true",
        help="Print recommended CAA DNS records (Let's Encrypt, this account, http-01)",
    )

    # Systemd management
    systemd_group = parser.add_argument_group("systemd automation")
    systemd_group.add_argument(
        "--print-systemd-units",
        dest="print_systemd_units",
        action="store_true",
        help="Print the systemd service and timer units (to install elsewhere)",
    )
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
        choices=["default", "aggressive", "conservative"],
        default="default",
        help="Systemd timer schedule preset (default: twice daily)",
    )

    # Revocation
    revoke_group = parser.add_argument_group("revocation")
    revoke_group.add_argument(
        "--revoke",
        dest="revoke",
        action="store_true",
        help="Revoke the certificates of --domain (asks for confirmation)",
    )
    revoke_group.add_argument(
        "--reason",
        dest="revoke_reason",
        choices=list(REVOCATION_REASONS),
        default="unspecified",
        help="Revocation reason (default: unspecified)",
    )
    revoke_group.add_argument(
        "--key-type",
        dest="key_type",
        choices=["rsa", "ec"],
        default=None,
        help="Only revoke this key type's certificate (default: both)",
    )
    revoke_group.add_argument(
        "--sign-with-certificate-key",
        dest="sign_with_certificate_key",
        action="store_true",
        help="Sign the revocation with the certificate's key instead of the account key",
    )
    revoke_group.add_argument(
        "--replace",
        dest="replace",
        action="store_true",
        help="After revoking, issue replacements (new keys for keyCompromise) and deploy them",
    )
    revoke_group.add_argument(
        "--yes",
        dest="assume_yes",
        action="store_true",
        help="Don't ask for confirmation (required when not on a terminal)",
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
        metavar="N",
        default=None,
        help="Warn below N days left (default: when renewal is overdue)",
    )
    health_group.add_argument(
        "--critical-days",
        dest="critical_days",
        type=int,
        metavar="N",
        default=None,
        help="Critical below N days left (default: under 1/10 of the lifetime)",
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
        type=Path,
        metavar="PATH",
        help="Write health status to file (for monitoring)",
    )

    # Notification configuration
    notify_group = parser.add_argument_group("notifications")
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
        type=Path,
        metavar="PATH",
        help="Write the report to PATH instead of printing it",
    )
    ui_group.add_argument(
        "--report-format",
        dest="report_format",
        choices=REPORT_FORMATS,
        default=None,
        help="Report format (default: from the --report-output extension: "
        ".json, .md/.markdown, else console text)",
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

    toml_path = args.config.resolve().parent / "lematt.toml"
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


def cmd_systemd(args: argparse.Namespace) -> int:
    """--print-systemd-units / --install-systemd / --uninstall-systemd / --systemd-status."""
    from lematt.systemd import PRESETS, SystemdConfig, SystemdInstaller

    preset = PRESETS.get(args.systemd_preset, PRESETS["default"])
    systemd_config = SystemdConfig(
        calendar=preset.calendar,
        randomized_delay_sec=preset.randomized_delay_sec,
        description=preset.description,
        config_file=args.config.resolve(),
        use_test_mode=args.is_test,
    )
    installer = SystemdInstaller(config=systemd_config, dry_run=args.dry_run)

    if args.print_systemd_units:
        for path, content in installer.generate_units().items():
            print(f"# {path}\n{content}")
        return 0

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
    """--validate-config: check what a run needs, then summarize the configuration.

    Settings, domains, actions and the challenge directory were validated
    while loading; this adds the account key, which only runs read.
    """
    from lematt.acme import AccountKey

    key_path = ctx.config.account_key
    try:
        AccountKey.from_file(key_path)
    except FileNotFoundError:
        logger.error(f"Config error: Account key doesn't exist: {key_path}")
        logger.error(f"  Create it with: openssl genrsa 4096 > {key_path}")
        return 1
    except (OSError, ValueError, TypeError) as e:
        logger.error(f"Config error: Account key can't be used: {key_path}: {e}")
        return 1

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
                        "profile": ctx.config.profile_for(d),
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
        if profile := ctx.config.profile_for(d):
            logger.info(f"     Profile: {profile}")
    return 0


def cmd_health(ctx: Context) -> int:
    """--health-check: check certificates; exit 0/1/2/3 for healthy/warning/critical/unknown."""
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
        notification_manager=notification_manager(ctx),
    )
    health = checker.check_all_certificates(ctx.domains)

    if args.check_live:
        logger.info("Checking live certificates...")
        health.extend(
            [checker.check_live_certificate(d.primary_domain) for d in ctx.domains]
        )

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
        health_path = args.write_health
        fmt = "prometheus" if args.prometheus_output else "json"
        write_health_status_file(health, health_path, format=fmt)
        logger.info(f"Wrote health status to {health_path}")

    return health.exit_code


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
    health = HealthChecker(
        config=ctx.config,
        warning_days=args.warning_days,
        critical_days=args.critical_days,
    ).check_all_certificates(ctx.domains)

    generate_full_report(
        config=ctx.config,
        domains=ctx.domains,
        actions=ctx.actions,
        health=health,
        output_path=args.report_output,
        format=args.report_format,
    )
    return 0


def notification_manager(ctx: Context) -> NotificationManager | None:
    """Backends from the TOML [notifications] table, or None if not configured."""
    try:
        settings = ctx.loader.notification_settings()
    except ConfigError as e:
        logger.error(f"Config error: {e}")
        return None
    if settings is None:
        return None
    return NotificationConfig.from_settings(settings).create_manager()


def cmd_test_notification(ctx: Context) -> int:
    """--test-notification: send a test event to each configured backend."""
    from lematt.notifications import NotificationEvent

    manager = notification_manager(ctx)
    if not manager or not manager.backends:
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
    results = manager.notify(event)

    for backend in manager.backends:
        if backend.name in results:
            logger.info(f"  {'✓' if results[backend.name] else '✗'} {backend.name}")
        else:
            logger.info(
                f"  - {backend.name}: skipped (it doesn't send {event.event_type} events)"
            )
    failures = sum(1 for ok in results.values() if not ok)
    if failures:
        logger.warning(f"Some notifications failed: {failures}/{len(results)}")
        return 1
    logger.info(f"All notifications sent successfully: {len(results)}")
    return 0


def caa_names(domains: list[DomainConfig]) -> list[str]:
    """Configured names, minus those covered by a configured parent.

    CAA records apply to subdomains too (resolvers climb the tree), so a
    record at example.com also covers www.example.com.
    """
    names = sorted({name for d in domains for name in d.all_domains}, key=len)
    chosen: list[str] = []
    for name in names:
        if not any(name.endswith(f".{parent}") for parent in chosen):
            chosen.append(name)
    return sorted(chosen)


def cmd_caa_records(ctx: Context) -> int:
    """--caa-records: CAA records limiting issuance to this account (RFC 8657)."""
    from lematt.acme import AccountKey

    config = ctx.config
    account_url = None
    try:
        thumbprint = AccountKey.from_file(config.account_key).thumbprint
        saved = StateStore(config.state_dir).load_account(
            config.acme_directory_url, thumbprint
        )
        account_url = saved.account_url if saved else None
    except (OSError, ValueError) as e:
        logger.warning(f"Could not read the account key: {e}")

    value = "letsencrypt.org"
    if account_url:
        value += f"; accounturi={account_url}"
    else:
        logger.warning(
            "No saved ACME account for this mode yet (it is recorded on the first "
            "renewal); records below omit accounturi"
        )
    value += "; validationmethods=http-01"

    print("; Only Let's Encrypt may issue for these names, only to lematt's")
    print("; account, and only after http-01 validation (RFC 8659 / RFC 8657).")
    print("; lematt issues no wildcards; uncomment issuewild to forbid them for")
    print("; everyone (only if nothing else issues wildcards for these names).")
    for name in caa_names(ctx.domains):
        print(f'{name}.\tIN\tCAA\t0 issue "{value}"')
        print(f';{name}.\tIN\tCAA\t0 issuewild ";"')
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


def cmd_revoke(ctx: Context) -> int:
    """--revoke: revoke a configured certificate line's certificates.

    Shows what will be revoked and asks for confirmation (``--yes`` skips
    it). Revocation is recorded in state, which makes the certificates due
    for renewal; ``--replace`` renews them right away (with new keys for
    keyCompromise) and runs the deployment actions.
    """
    args, config = ctx.args, ctx.config
    if not args.single_domain:
        logger.error("--revoke needs --domain NAME (a name on the certificate)")
        return 1
    if args.replace and args.revoke_reason == "cessationOfOperation":
        logger.error("--replace contradicts --reason cessationOfOperation")
        return 1
    domains = selected_domains(ctx)
    if domains is None:
        return 1

    manager = CertificateManager(config)
    key_types = [KeyType.from_string(args.key_type)] if args.key_type else list(KeyType)
    targets = []
    for domain_config in domains:
        for key_type in key_types:
            captured = manager.capture(domain_config, key_type)
            if captured is None:
                logger.warning(
                    f"No {key_type} certificate for {domain_config}; skipping"
                )
            else:
                targets.append(captured)
    if not targets:
        logger.error("Nothing to revoke")
        return 1

    signer = "certificate key" if args.sign_with_certificate_key else "ACME account"
    logger.info(
        f"Revoking {len(targets)} certificate(s), reason {args.revoke_reason}, signed by {signer}:"
    )
    for captured in targets:
        info = get_certificate_info(
            config.get_cert_path(captured.domain_config, captured.key_type)
        )
        logger.info(
            f"  {captured.domain_config} [{captured.key_type}] serial {info.serial_hex}, "
            f"expires {info.not_after:%Y-%m-%d}, names {', '.join(info.san_domains)}"
        )
    if args.replace:
        rotation = " with new keys" if args.revoke_reason == "keyCompromise" else ""
        logger.info(f"Then issue replacements{rotation} and run deployment actions")

    if not config.is_dry_run and not args.assume_yes:
        if not sys.stdin.isatty():
            logger.error("Refusing to revoke without confirmation; pass --yes")
            return 1
        if input("Type 'revoke' to continue: ").strip() != "revoke":
            logger.warning("Aborted; nothing was revoked")
            return 1

    if config.is_dry_run:
        for captured in targets:
            manager.revoke(captured, args.revoke_reason)
        return 0

    store = StateStore(config.state_dir)
    try:
        with store.run_lock():
            started = utcnow().replace(microsecond=0)
            session = manager.new_session()
            outcomes = [
                manager.revoke(
                    captured,
                    args.revoke_reason,
                    sign_with_certificate_key=args.sign_with_certificate_key,
                    session=session,
                )
                for captured in targets
            ]
            exit_code = 0 if all(o.ok for o in outcomes) else 1
            if args.replace and any(o.ok for o in outcomes):
                # Revoked certificates are now due; keyCompromise needs new keys
                replace_config = dataclasses.replace(
                    config,
                    always_generate_new_keys=config.always_generate_new_keys
                    or args.revoke_reason == "keyCompromise",
                )
                replace_ctx = dataclasses.replace(ctx, config=replace_config)
                exit_code = max(
                    exit_code, run_renewal(replace_ctx, domains, notify=False)
                )
            send_run_notifications(ctx, since=started)
            return exit_code
    except RunLockedError as e:
        logger.warning(f"Not starting: {e}")
        return EXIT_RUN_LOCKED


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

    if not config.account_key.is_file():
        logger.error(f"Account key doesn't exist: {config.account_key}")
        logger.error("Create with: openssl genrsa 4096 > key.pem")
        return 1

    if config.is_dry_run:
        return run_renewal(ctx, domains)
    try:
        store = StateStore(config.state_dir)
        with store.run_lock():
            store.rotate_history()
            return run_renewal(ctx, domains)
    except RunLockedError as e:
        logger.warning(f"Not starting: {e}")
        return EXIT_RUN_LOCKED


def send_run_notifications(ctx: Context, *, since: datetime.datetime) -> None:
    """Notify configured backends about this run (failures, early renewals...)."""
    manager = notification_manager(ctx)
    if manager is None:
        return
    store = StateStore(ctx.config.state_dir)
    history = [
        entry
        for entry in store.history()
        if (at := parse_timestamp(entry.get("at"))) and at >= since
    ]
    for event in run_notifications(history):
        manager.notify(event)


def run_renewal(
    ctx: Context, domains: list[DomainConfig], *, notify: bool = True
) -> int:
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

    started = utcnow().replace(microsecond=0)
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

    if notify and not config.is_dry_run:
        send_run_notifications(ctx, since=started)

    if interrupted:
        logger.warning("Exiting due to interrupt - after-issue hooks completed")
        return 130  # conventional exit code for SIGINT
    return exit_code


type Predicate = Callable[[argparse.Namespace], object]

# Checked in order; the first match runs
# Commands that don't depend on --prod/--test (or on a loaded configuration)
MODELESS_COMMANDS: list[tuple[Predicate, Callable[[argparse.Namespace], int]]] = [
    (lambda a: a.init_toml, cmd_init_toml),
    (lambda a: a.help_topic is not None, cmd_help_topic),
    (lambda a: a.help_search, cmd_help_search),
]

# Commands that need the mode but not a loaded configuration
STANDALONE_COMMANDS: list[tuple[Predicate, Callable[[argparse.Namespace], int]]] = [
    (
        lambda a: (
            a.print_systemd_units
            or a.install_systemd
            or a.uninstall_systemd
            or a.systemd_status
        ),
        cmd_systemd,
    ),
]

# (selected?, command, read-only: doesn't need the challenge directory;
#  --validate-config checks it like a run would)
CONFIGURED_COMMANDS: list[tuple[Predicate, Callable[[Context], int], bool]] = [
    (lambda a: a.validate_only, cmd_validate, False),
    (lambda a: a.list_domains, cmd_list_domains, True),
    (lambda a: a.health_check, cmd_health, True),
    (lambda a: a.dashboard, cmd_dashboard, True),
    (lambda a: a.report, cmd_report, True),
    (lambda a: a.test_notification, cmd_test_notification, True),
    (lambda a: a.revoke, cmd_revoke, False),
    (lambda a: a.show_status, cmd_status, True),
    (lambda a: a.caa_records, cmd_caa_records, True),
]


def main(argv: Sequence[str] | None = None) -> int:
    """Run lematt; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    for selected, modeless in MODELESS_COMMANDS:
        if selected(args):
            setup_logging(verbose=args.verbose)
            return modeless(args)

    if args.is_test is None:
        parser.error("one of the arguments --prod --test is required")
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
        # Monitoring reads a health check that couldn't run as UNKNOWN, not WARNING
        return EXIT_HEALTH_UNKNOWN if args.health_check else 1
    return command(ctx)


if __name__ == "__main__":
    sys.exit(main())
