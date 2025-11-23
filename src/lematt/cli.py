"""Command-line interface for lematt.

This module provides the CLI entry point and argument parsing
for the lematt certificate management tool.
"""

import argparse
import configparser
import logging
import multiprocessing
import os
import sys

from lematt.actions import ActionRunner
from lematt.config import DomainConfig, KeyType, LemattConfig
from lematt.manager import CertificateManager

logger = logging.getLogger("lematt")


def setup_logging(is_cron: bool = False, verbose: bool = False) -> None:
    """Configure logging handlers based on runtime mode.

    Args:
        is_cron: Whether running in cron mode (minimal output).
        verbose: Whether to show debug messages.
    """
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)

    if is_cron:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        formatter = logging.Formatter("%(message)s")

    console_handler = logging.StreamHandler(sys.stdout)
    if is_cron:
        console_handler.setLevel(logging.WARNING)
    elif verbose:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def load_domains(config_base: str) -> list[DomainConfig]:
    """Load domain configuration from the domains file.

    Args:
        config_base: Base configuration directory.

    Returns:
        List of DomainConfig objects.
    """
    domains: list[DomainConfig] = []
    domains_file = f"{config_base}/domains"

    with open(domains_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) > 100:
                print(
                    f"Error! Domain limit is 100 per certificate, "
                    f"but configured {len(parts)}: {parts}"
                )
                sys.exit(1)

            primary = parts[0]
            sans: list[str] = []

            for domain in parts[1:]:
                # Shorthand: subdomain without dot gets primary appended
                if "." not in domain:
                    domain = f"{domain}.{primary}"
                sans.append(domain)

            domains.append(DomainConfig(primary_domain=primary, san_domains=sans))

    return domains


def validate_config(
    config: configparser.SectionProxy,
    config_base: str,
) -> bool:
    """Validate configuration values and provide helpful error messages.

    Args:
        config: Configuration section.
        config_base: Base configuration directory.

    Returns:
        True if configuration is valid.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Required keys
    required_keys = ["challengeDropDir", "accountKey"]
    for key in required_keys:
        if key not in config or not config[key]:
            errors.append(f"Missing required config: '{key}'")

    # Validate challenge directory
    if "challengeDropDir" in config:
        challenge_dir = config["challengeDropDir"]
        if not os.path.isdir(challenge_dir):
            errors.append(f"Challenge directory does not exist: {challenge_dir}")
            errors.append(f"  Create it with: mkdir -p {challenge_dir}")

    # Validate RSA key size
    if "keyBitsRSA" in config:
        try:
            key_bits = int(config["keyBitsRSA"])
            if key_bits < 2048:
                warnings.append(f"RSA key size {key_bits} is insecure. Use at least 2048 bits.")
            elif key_bits > 4096:
                warnings.append(
                    f"RSA key size {key_bits} may cause performance issues. 2048-4096 recommended."
                )
        except ValueError:
            errors.append(f"Invalid keyBitsRSA value: {config['keyBitsRSA']} (must be integer)")

    # Validate curve
    valid_curves = ["prime256v1", "secp256r1", "secp384r1", "secp521r1"]
    if "curve" in config:
        curve = config["curve"]
        if curve not in valid_curves:
            warnings.append(f"EC curve '{curve}' may not be widely supported: {valid_curves}")

    # Validate reauthorizeDays
    if "reauthorizeDays" in config:
        try:
            days = float(config["reauthorizeDays"])
            if days < 1:
                warnings.append(f"reauthorizeDays={days} is very aggressive.")
            elif days > 89:
                warnings.append(f"reauthorizeDays={days} exceeds LE cert lifetime (90 days).")
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


def process_domain_worker(
    domain_config: DomainConfig,
    key_type_str: str,
    lematt_config: LemattConfig,
    domain_actions: dict,
) -> dict:
    """Worker function for parallel domain processing.

    Args:
        domain_config: The domain configuration.
        key_type_str: Key type as string ('rsa' or 'ec').
        lematt_config: The lematt configuration.
        domain_actions: Domain action mappings.

    Returns:
        Dictionary with domain and result information.
    """
    key_type = KeyType.from_string(key_type_str)
    manager = CertificateManager(lematt_config)
    result = manager.process_domain(domain_config, key_type, domain_actions)

    # Return serializable result
    return {
        "domain": result.domain,
        "key_type": str(result.key_type),
        "success": result.success,
        "renewed": result.renewed,
        "cert_path": result.cert_path,
        "key_path": result.key_path,
        "error_message": result.error_message,
        "all_domains": domain_config.all_domains,
    }


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

    args = parser.parse_args()

    # Set up logging
    setup_logging(is_cron=args.is_cron, verbose=args.verbose)

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
    validate_config(config, config_base)

    # Build LemattConfig
    rsa_bits = int(config["keyBitsRSA"])
    curve = config["curve"]

    lematt_config = LemattConfig(
        config_base=config_base,
        challenge_dir=config["challengeDropDir"],
        account_key=config["accountKey"],
        reauthorize_days=float(config["reauthorizeDays"]),
        generate_new_certs_after_days=float(config["generateNewCertsAfterDays"]),
        always_generate_new_keys=config.getboolean("alwaysGenerateNewKeys"),
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
            if args.single_domain in d.all_domains or d.primary_domain == args.single_domain
        ]
        if not filtered:
            logger.error(f"Domain '{args.single_domain}' not found in configuration")
            return 1
        configured_domains = filtered
        logger.info(f"Processing single domain: {args.single_domain}")

    # Create manager
    manager = CertificateManager(lematt_config)

    # Show status and exit if requested
    if args.show_status:
        manager.show_status(configured_domains)
        return 0

    # Display welcome message
    if not args.is_cron:
        prefix = "[TEST MODE — DO NOT USE TEST CERTS IN PRODUCTION] " if args.is_test else ""
        print(f"{prefix}Welcome to LE Matt!")
        if args.dry_run:
            print("[DRY-RUN MODE - No changes will be made]")
        print("Using domain list:")
        for domain in configured_domains:
            print(f"\t{domain}")

    # Verify account key exists
    if not os.path.isfile(lematt_config.account_key):
        logger.error(f"Account key doesn't exist: {lematt_config.account_key}")
        logger.error("Create with: openssl genrsa 4096 > key.pem")
        return 1

    # Ensure directories exist
    manager.ensure_directories()

    # Load actions
    action_runner = ActionRunner(lematt_config)
    action_runner.load_actions()

    # Process certificates
    if lematt_config.concurrency > 1:
        # Parallel processing
        with multiprocessing.Pool(processes=lematt_config.concurrency) as pool:
            # Create work items
            work_items = [
                (domain, key_type, lematt_config, action_runner.domain_actions)
                for domain in configured_domains
                for key_type in ["rsa", "ec"]
            ]

            results = pool.starmap(
                lambda d, k, c, a: process_domain_worker(d, k, c, a),
                work_items,
            )
    else:
        # Sequential processing
        summary = manager.process_all_domains(configured_domains, action_runner.domain_actions)
        results = summary.results

    # Process updated certificates (run actions)
    if lematt_config.concurrency > 1:
        # Convert worker results back to CertificateResult objects
        from lematt.config import CertificateResult

        cert_results = []
        for r in results:
            if r["renewed"] and r["success"]:
                # Find the matching domain config
                for dc in configured_domains:
                    if dc.primary_domain == r["domain"]:
                        cert_results.append(
                            CertificateResult(
                                domain_config=dc,
                                key_type=KeyType.from_string(r["key_type"]),
                                success=r["success"],
                                renewed=r["renewed"],
                                cert_path=r["cert_path"],
                                key_path=r["key_path"],
                                error_message=r["error_message"],
                            )
                        )
                        break
        action_runner.process_updated_certs(cert_results)
    else:
        action_runner.process_updated_certs(summary.results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
