"""Command-line interface for lematt.

This module provides the CLI entry point and argument parsing
for the lematt certificate management tool.
"""

import argparse
import atexit
import configparser
import contextlib
import json
import os
import sys
from pathlib import Path

from loguru import logger

from lematt.actions import ActionRunner
from lematt.config import DomainConfig, LemattConfig
from lematt.executor import CertificateExecutor, create_progress_printer
from lematt.log import setup_logging
from lematt.manager import CertificateManager

# Global action runner for emergency cleanup
_global_action_runner: ActionRunner | None = None


def _emergency_cleanup() -> None:
    """Emergency cleanup handler to kill any remaining prepare processes."""
    if _global_action_runner is not None:
        try:
            _global_action_runner.cleanup_prepare()
        except Exception:
            pass  # Suppress errors during exit


# Register emergency cleanup handler
atexit.register(_emergency_cleanup)

# Rich display imports (lazy loaded for commands that need them)
HAS_RICH = True
try:
    from rich.console import Console

    console: Console | None = Console()
except ImportError:
    HAS_RICH = False
    console = None


def load_domains(config_base: str) -> list[DomainConfig]:
    """Load domain configuration from the domains file.

    Supports per-domain OCSP stapling configuration:
    - +ocsp : Enable OCSP Must-Staple for this certificate
    - -ocsp : Explicitly disable OCSP Must-Staple (default)

    Example:
        example.com www mail +ocsp
        other.com www -ocsp

    Args:
        config_base: Base configuration directory.

    Returns:
        List of DomainConfig objects.
    """
    domains: list[DomainConfig] = []
    domains_file = f"{config_base}/domains"

    with open(domains_file) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()

            # Extract OCSP flags
            ocsp_required = False
            domain_parts: list[str] = []
            for part in parts:
                if part == "+ocsp":
                    ocsp_required = True
                elif part == "-ocsp":
                    ocsp_required = False
                else:
                    domain_parts.append(part)

            if not domain_parts:
                logger.warning(f"Skipping empty domain line {line_num}")
                continue

            if len(domain_parts) > 100:
                logger.error(
                    f"Domain limit is 100 per certificate, "
                    f"but configured {len(domain_parts)}: {domain_parts}"
                )
                sys.exit(1)

            primary = domain_parts[0]
            sans: list[str] = []

            for domain in domain_parts[1:]:
                # Shorthand: subdomain without dot gets primary appended
                if "." not in domain:
                    domain = f"{domain}.{primary}"
                sans.append(domain)

            domains.append(
                DomainConfig(
                    primary_domain=primary,
                    san_domains=sans,
                    ocsp_staple_required=ocsp_required,
                )
            )

    return domains


def validate_config(
    config: configparser.SectionProxy,
    config_base: str,
    require_write_access: bool = True,
) -> bool:
    """Validate configuration values and provide helpful error messages.

    Args:
        config: Configuration section.
        config_base: Base configuration directory.
        require_write_access: Whether write access to challenge dir is required.
                             Set to False for read-only operations (dashboard, health-check, etc.)

    Returns:
        True if configuration is valid.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Required keys - accountKey always required, challenge dir only if write access needed
    required_keys = ["accountKey"]
    if require_write_access:
        required_keys.append("challengeDropDir")

    for key in required_keys:
        if key not in config or not config[key]:
            errors.append(f"Missing required config: '{key}'")

    # Validate challenge directory (only if write access needed)
    if require_write_access and "challengeDropDir" in config:
        challenge_dir = config["challengeDropDir"]
        if not os.path.isdir(challenge_dir):
            errors.append(f"Challenge directory does not exist: {challenge_dir}")
            errors.append(f"  Create it with: mkdir -p {challenge_dir}")

    # Validate RSA key size
    if "keyBitsRSA" in config:
        try:
            key_bits = int(config["keyBitsRSA"])
            if key_bits < 2048:
                warnings.append(
                    f"RSA key size {key_bits} is insecure. Use at least 2048 bits."
                )
            elif key_bits > 4096:
                warnings.append(
                    f"RSA key size {key_bits} may cause performance issues. 2048-4096 recommended."
                )
        except ValueError:
            errors.append(
                f"Invalid keyBitsRSA value: {config['keyBitsRSA']} (must be integer)"
            )

    # Validate curve
    valid_curves = ["prime256v1", "secp256r1", "secp384r1", "secp521r1"]
    if "curve" in config:
        curve = config["curve"]
        if curve not in valid_curves:
            warnings.append(
                f"EC curve '{curve}' may not be widely supported: {valid_curves}"
            )

    # Validate reauthorizeDays
    if "reauthorizeDays" in config:
        try:
            days = float(config["reauthorizeDays"])
            if days < 1:
                warnings.append(f"reauthorizeDays={days} is very aggressive.")
            elif days > 89:
                warnings.append(
                    f"reauthorizeDays={days} exceeds LE cert lifetime (90 days)."
                )
        except ValueError:
            errors.append(f"Invalid reauthorizeDays value: {config['reauthorizeDays']}")

    # Check domains file
    domains_file = f"{config_base}/domains"
    if not os.path.isfile(domains_file):
        errors.append(f"Domains file not found: {domains_file}")

    # Check actions.conf
    actions_file = f"{config_base}/actions.conf"
    if not os.path.isfile(actions_file):
        errors.append(f"Actions config not found: {actions_file}")

    for warning in warnings:
        logger.warning(f"Config warning: {warning}")

    if errors:
        for error in errors:
            logger.error(f"Config error: {error}")
        logger.error("Configuration validation failed.")
        sys.exit(1)

    return True


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
        help="Use LE production endpoint (5 duplicate certs/domain/week limit)",
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

        print_help(args.help_topic if args.help_topic else None)
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

    # Load configuration
    config_base = os.path.dirname(os.path.realpath(args.config))

    conf = configparser.ConfigParser()
    conf["DEFAULT"] = {
        "reauthorizeDays": "15",
        "keyBitsRSA": "2048",
        "alwaysGenerateNewKeys": "no",
        "generateNewCertsAfterDays": "0",
        "curve": "prime256v1",
    }

    if not conf.read(args.config):
        logger.error(f"Config file not found: {args.config}")
        return 1

    config = conf["config"]

    # Determine if we're in read-only mode (no challenge dir needed)
    read_only_mode = (
        args.dashboard
        or args.health_check
        or args.show_status
        or args.report
        or args.list_domains
        or args.validate_only
    )

    validate_config(config, config_base, require_write_access=not read_only_mode)

    # Handle --validate-config: just validate and exit
    if args.validate_only:
        logger.info("Configuration is valid!")
        logger.info(f"  Config base: {config_base}")
        logger.info(f"  Challenge dir: {config['challengeDropDir']}")
        logger.info(f"  Account key: {config['accountKey']}")
        logger.info(f"  RSA key bits: {config['keyBitsRSA']}")
        logger.info(f"  EC curve: {config['curve']}")
        # Try loading domains to validate that too
        try:
            domains = load_domains(config_base)
            logger.info(f"  Domains configured: {len(domains)}")
            # Try loading actions to validate that too
            temp_config = LemattConfig(
                config_base=config_base,
                challenge_dir=config.get(
                    "challengeDropDir", "/tmp/lematt-challenges"
                ),  # May not exist in read-only mode
                account_key=config["accountKey"],
            )
            action_runner = ActionRunner(temp_config)
            action_runner.load_actions()
            action_count = len(action_runner.actions.all_action_names())
            logger.info(f"  Action configs: {action_count}")
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return 1
        return 0

    # Handle --list-domains: list all configured domains and exit
    if args.list_domains:
        domains = load_domains(config_base)
        if args.json_output:
            domain_list = []
            for d in domains:
                domain_list.append(
                    {
                        "primary": d.primary_domain,
                        "sans": d.san_domains,
                        "all_domains": d.all_domains,
                        "ocsp_staple_required": d.ocsp_staple_required,
                    }
                )
            print(json.dumps(domain_list, indent=2))  # JSON data output to stdout
        else:
            logger.info(f"Configured domains ({len(domains)} certificates):")
            logger.info("-" * 60)
            for i, d in enumerate(domains, 1):
                ocsp_marker = " [+ocsp]" if d.ocsp_staple_required else ""
                if d.san_domains:
                    sans_str = ", ".join(d.san_domains)
                    logger.info(f"{i:3}. {d.primary_domain}{ocsp_marker}")
                    logger.info(f"     SANs: {sans_str}")
                else:
                    logger.info(f"{i:3}. {d.primary_domain}{ocsp_marker}")
        return 0

    # Handle --health-check: run health checks on certificates
    if args.health_check:
        from lematt.health import (
            HealthChecker,
            HealthStatus,
            PrometheusMetrics,
            write_health_status_file,
        )

        domains = load_domains(config_base)

        # Build minimal config for path generation
        rsa_bits = int(config["keyBitsRSA"])
        curve = config["curve"]
        health_config = LemattConfig(
            config_base=config_base,
            challenge_dir=config.get(
                "challengeDropDir", "/tmp/lematt-challenges"
            ),  # Dummy value for read-only
            account_key=config["accountKey"],
            rsa_key_bits=rsa_bits,
            ec_curve=curve,
            rsa_tag=config.get("rsaTag", f"rsa{rsa_bits}"),
            curve_tag=config.get("curveTag", curve),
            is_test=args.is_test,
        )

        checker = HealthChecker(
            config=health_config,
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

        domains = load_domains(config_base)

        # Build config for health checking
        rsa_bits = int(config["keyBitsRSA"])
        curve = config["curve"]
        dash_config = LemattConfig(
            config_base=config_base,
            challenge_dir=config.get(
                "challengeDropDir", "/tmp/lematt-challenges"
            ),  # Dummy value for read-only
            account_key=config["accountKey"],
            rsa_key_bits=rsa_bits,
            ec_curve=curve,
            rsa_tag=config.get("rsaTag", f"rsa{rsa_bits}"),
            curve_tag=config.get("curveTag", curve),
            is_test=args.is_test,
        )

        health_checker = HealthChecker(
            config=dash_config,
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

        domains = load_domains(config_base)

        # Build config
        rsa_bits = int(config["keyBitsRSA"])
        curve = config["curve"]
        report_lematt_config = LemattConfig(
            config_base=config_base,
            challenge_dir=config.get(
                "challengeDropDir", "/tmp/lematt-challenges"
            ),  # Dummy value for read-only
            account_key=config["accountKey"],
            rsa_key_bits=rsa_bits,
            ec_curve=curve,
            rsa_tag=config.get("rsaTag", f"rsa{rsa_bits}"),
            curve_tag=config.get("curveTag", curve),
            is_test=args.is_test,
        )

        # Add dynamic attributes for report generation
        from lematt.config import KeyType

        report_lematt_config.domains = domains  # type: ignore[attr-defined]
        report_lematt_config.key_types = [KeyType.RSA, KeyType.EC]  # type: ignore[attr-defined]

        # Get health data for report
        health_checker = HealthChecker(
            config=report_lematt_config,
            warning_days=args.warning_days,
            critical_days=args.critical_days,
        )
        health = health_checker.check_all_certificates(domains)

        # Load actions for report (optional)
        action_runner = ActionRunner(report_lematt_config)
        try:
            action_runner.load_actions()
            # Store actions for report if available
            report_lematt_config.actions = action_runner.actions  # type: ignore[attr-defined]
        except Exception:
            pass  # Actions not required for report

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

        # Try to load notification config from TOML if available
        notify_config = NotificationConfig()

        # Check for TOML config with notification settings
        toml_path = Path(config_base) / "lematt.toml"
        if toml_path.exists():
            import tomllib

            with open(toml_path, "rb") as f:
                toml_data = tomllib.load(f)
            if "notifications" in toml_data:
                nc = toml_data["notifications"]
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

    # Build LemattConfig
    rsa_bits = int(config["keyBitsRSA"])
    curve = config["curve"]

    lematt_config = LemattConfig(
        config_base=config_base,
        challenge_dir=config["challengeDropDir"],
        account_key=config["accountKey"],
        reauthorize_days=float(config["reauthorizeDays"]),
        generate_new_certs_after_days=float(config["generateNewCertsAfterDays"]),
        always_generate_new_keys=config.getboolean(
            "alwaysGenerateNewKeys", fallback=False
        ),
        rsa_key_bits=rsa_bits,
        ec_curve=curve,
        rsa_tag=config.get("rsaTag", f"rsa{rsa_bits}"),
        curve_tag=config.get("curveTag", curve),
        is_test=args.is_test,
        is_cron=args.is_cron,
        is_dry_run=args.dry_run,
        force_renew=args.force_renew,
        concurrency=min(args.concurrency, 10),  # Cap at 10
        verbose=args.verbose,
    )

    # Load domains
    configured_domains = load_domains(config_base)

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

    # Load actions
    action_runner = ActionRunner(lematt_config)
    action_runner.load_actions()

    # Register for emergency cleanup on exit
    global _global_action_runner
    _global_action_runner = action_runner

    # Process certificates using the robust executor
    progress_callback = (
        create_progress_printer(verbose=args.verbose) if not args.is_cron else None
    )

    executor = CertificateExecutor(
        config=lematt_config,
        max_workers=lematt_config.concurrency,
        rate_limit=10.0,  # Conservative: 10 requests/second
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
        summary = executor._summary

    # Log final summary
    logger.info(
        f"{'Interrupted - Partial results' if interrupted else 'Completed'}: "
        f"{summary.total_domains} certificates - "
        f"Renewed: {summary.renewed_count}, Failed: {summary.failed_count}, "
        f"Skipped: {summary.skipped_count}"
    )

    # CRITICAL: Process updated certificates (run after-issue hooks)
    # This must run even if interrupted to ensure successful renewals are deployed
    if summary.results:
        try:
            action_runner.process_updated_certs(summary.results)
        except Exception as e:
            logger.error(f"Error running after-issue hooks: {e}")
            if not interrupted:
                raise

    # CRITICAL: Ensure all prepare processes are cleaned up
    try:
        action_runner.cleanup_prepare()
        logger.debug("Cleaned up all prepare processes")
    except Exception as e:
        logger.warning(f"Error during prepare process cleanup: {e}")

    # Exit with error code if interrupted
    if interrupted:
        logger.warning("Exiting due to interrupt - after-issue hooks completed")
        sys.exit(130)  # Standard exit code for SIGINT

    return 0


if __name__ == "__main__":
    sys.exit(main())
