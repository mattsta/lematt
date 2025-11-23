"""Configuration file loaders for lematt.

This module provides support for loading configuration from both
INI (legacy) and TOML (modern) formats.
"""

import configparser
import tomllib
from dataclasses import dataclass, field
from pathlib import Path  # noqa: TC003 - used at runtime in dataclass

from loguru import logger

from lematt.config import ActionConfig, DomainActions, DomainConfig, LemattConfig


@dataclass
class ConfigLoader:
    """Unified configuration loader supporting INI and TOML formats.

    TOML format is recommended for new configurations as it provides:
    - Native list/array support (no JSON escaping needed)
    - Better type inference
    - More readable structure
    - Comments support

    Example TOML config (lematt.toml):

        [config]
        challenge_dir = "/var/www/acme-challenge"
        account_key = "/etc/lematt/account.key"
        reauthorize_days = 15
        key_bits_rsa = 2048
        ec_curve = "prime256v1"

        [[domains]]
        primary = "example.com"
        sans = ["www", "mail"]
        ocsp_staple_required = false

        [[domains]]
        primary = "other.com"
        ocsp_staple_required = true

        [actions.default]
        update = ["systemctl reload nginx"]

        [actions.webservers]
        domains = ["example.com", "other.com"]
        upload_certs = ["rsync -avz CERTS /etc/ssl/certs/"]
        update = ["systemctl reload nginx", "systemctl reload apache2"]
    """

    config_base: Path
    _config_data: dict = field(default_factory=dict)
    _format: str = field(default="ini")

    def load(self) -> None:
        """Load configuration from available config file.

        Tries TOML first (lematt.toml), falls back to INI (lematt.conf).
        """
        toml_path = self.config_base / "lematt.toml"
        ini_path = self.config_base / "lematt.conf"

        if toml_path.exists():
            self._load_toml(toml_path)
            self._format = "toml"
            logger.debug(f"Loaded TOML config from {toml_path}")
        elif ini_path.exists():
            self._load_ini(ini_path)
            self._format = "ini"
            logger.debug(f"Loaded INI config from {ini_path}")
        else:
            raise FileNotFoundError(
                f"No configuration file found. Expected {toml_path} or {ini_path}"
            )

    def _load_toml(self, path: Path) -> None:
        """Load configuration from TOML file."""
        with open(path, "rb") as f:
            self._config_data = tomllib.load(f)

    def _load_ini(self, path: Path) -> None:
        """Load configuration from INI file and convert to common format."""
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = {
            "reauthorizeDays": "15",
            "keyBitsRSA": "2048",
            "alwaysGenerateNewKeys": "no",
            "generateNewCertsAfterDays": "0",
            "curve": "prime256v1",
        }
        parser.read(path)

        # Convert INI to common dict format
        if "config" in parser:
            config = parser["config"]
            self._config_data["config"] = {
                "challenge_dir": config.get("challengeDropDir", ""),
                "account_key": config.get("accountKey", ""),
                "reauthorize_days": float(config.get("reauthorizeDays", "15")),
                "generate_new_certs_after_days": float(config.get("generateNewCertsAfterDays", "0")),
                "always_generate_new_keys": config.getboolean("alwaysGenerateNewKeys", fallback=False),
                "key_bits_rsa": int(config.get("keyBitsRSA", "2048")),
                "ec_curve": config.get("curve", "prime256v1"),
                "rsa_tag": config.get("rsaTag", ""),
                "curve_tag": config.get("curveTag", ""),
            }

    def get_lematt_config(
        self,
        *,
        is_test: bool = False,
        is_cron: bool = False,
        is_dry_run: bool = False,
        force_renew: bool = False,
        concurrency: int = 1,
        verbose: bool = False,
    ) -> LemattConfig:
        """Build LemattConfig from loaded configuration.

        Args:
            is_test: Use staging endpoint.
            is_cron: Minimize output.
            is_dry_run: Don't make actual changes.
            force_renew: Force certificate renewal.
            concurrency: Number of parallel workers.
            verbose: Enable verbose logging.

        Returns:
            LemattConfig instance.
        """
        config = self._config_data.get("config", {})

        rsa_bits = config.get("key_bits_rsa", 2048)
        ec_curve = config.get("ec_curve", "prime256v1")

        return LemattConfig(
            config_base=str(self.config_base),
            challenge_dir=config.get("challenge_dir", ""),
            account_key=config.get("account_key", ""),
            reauthorize_days=config.get("reauthorize_days", 15.0),
            generate_new_certs_after_days=config.get("generate_new_certs_after_days", 0.0),
            always_generate_new_keys=config.get("always_generate_new_keys", False),
            rsa_key_bits=rsa_bits,
            ec_curve=ec_curve,
            rsa_tag=config.get("rsa_tag") or f"rsa{rsa_bits}",
            curve_tag=config.get("curve_tag") or ec_curve,
            is_test=is_test,
            is_cron=is_cron,
            is_dry_run=is_dry_run,
            force_renew=force_renew,
            concurrency=min(concurrency, 10),
            verbose=verbose,
        )

    def get_domains(self) -> list[DomainConfig]:
        """Load domain configurations.

        For TOML: reads from [[domains]] array in config.
        For INI: reads from separate domains file.

        Returns:
            List of DomainConfig instances.
        """
        if self._format == "toml" and "domains" in self._config_data:
            return self._load_domains_from_toml()
        return self._load_domains_from_file()

    def _load_domains_from_toml(self) -> list[DomainConfig]:
        """Load domains from TOML [[domains]] array."""
        domains: list[DomainConfig] = []

        for entry in self._config_data.get("domains", []):
            primary = entry.get("primary", "")
            if not primary:
                continue

            sans = entry.get("sans", [])
            # Expand shorthand SANs
            expanded_sans: list[str] = []
            for san in sans:
                if "." not in san:
                    san = f"{san}.{primary}"
                expanded_sans.append(san)

            domains.append(
                DomainConfig(
                    primary_domain=primary,
                    san_domains=expanded_sans,
                    ocsp_staple_required=entry.get("ocsp_staple_required", False),
                )
            )

        return domains

    def _load_domains_from_file(self) -> list[DomainConfig]:
        """Load domains from separate domains file."""
        domains_file = self.config_base / "domains"
        if not domains_file.exists():
            return []

        domains: list[DomainConfig] = []

        with open(domains_file) as f:
            for line in f:
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
                    continue

                primary = domain_parts[0]
                sans: list[str] = []

                for domain in domain_parts[1:]:
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

    def get_actions(self) -> DomainActions:
        """Load action configurations.

        For TOML: reads from [actions.*] tables in config.
        For INI: reads from separate actions.conf file.

        Returns:
            DomainActions instance.
        """
        if self._format == "toml" and "actions" in self._config_data:
            return self._load_actions_from_toml()
        return self._load_actions_from_ini()

    def _load_actions_from_toml(self) -> DomainActions:
        """Load actions from TOML [actions.*] tables."""
        actions_data = self._config_data.get("actions", {})
        result = DomainActions()

        for name, config in actions_data.items():
            action_config = ActionConfig(
                name=name,
                prepare_commands=config.get("prepare", []),
                upload_certs_commands=config.get("upload_certs", []),
                upload_keys_commands=config.get("upload_keys", []),
                update_commands=config.get("update", []),
                ocsp_staple_required=config.get("ocsp_staple_required", False),
                domains=config.get("domains", []),
            )

            if name == "default":
                result.default = action_config
            elif name == "every":
                result.every = action_config
            else:
                # Map domains to this action config
                for domain in action_config.domains:
                    result.domain_configs[domain] = action_config

        return result

    def _load_actions_from_ini(self) -> DomainActions:
        """Load actions from INI actions.conf file."""
        import json

        actions_file = self.config_base / "actions.conf"
        if not actions_file.exists():
            return DomainActions()

        parser = configparser.ConfigParser()
        parser.read(actions_file)

        result = DomainActions()

        # Get default OCSP setting
        default_ocsp = False
        if "default" in parser and "ocspStapleRequired" in parser["default"]:
            default_ocsp = parser["default"].getboolean("ocspStapleRequired")
        parser["DEFAULT"] = {"ocspStapleRequired": str(default_ocsp)}

        def extract_commands(section: configparser.SectionProxy, key: str) -> list[str]:
            if key in section:
                return json.loads(section[key])
            return []

        for section in parser.sections():
            section_config = parser[section]

            action_config = ActionConfig(
                name=section,
                prepare_commands=extract_commands(section_config, "prepare"),
                upload_certs_commands=extract_commands(section_config, "uploadCerts"),
                upload_keys_commands=extract_commands(section_config, "uploadKeys"),
                update_commands=extract_commands(section_config, "update"),
                ocsp_staple_required=section_config.getboolean("ocspStapleRequired"),
            )

            if section == "default":
                result.default = action_config
            elif section == "every":
                result.every = action_config
            else:
                domains = section_config.get("domains", "").split()
                action_config.domains = domains
                for domain in domains:
                    result.domain_configs[domain] = action_config

        return result


def create_example_toml(path: Path) -> None:
    """Create an example TOML configuration file.

    Args:
        path: Path to write the example config.
    """
    example = '''# lematt TOML configuration
# This is the modern configuration format for lematt.

[config]
# ACME challenge directory (must be served at /.well-known/acme-challenge/)
challenge_dir = "/var/www/html/.well-known/acme-challenge"

# Account key for Let's Encrypt (create with: openssl genrsa 4096 > account.key)
account_key = "/etc/lematt/account.key"

# Renew certificates this many days before expiration (default: 15)
reauthorize_days = 15

# RSA key size (2048, 3072, or 4096)
key_bits_rsa = 2048

# EC curve (prime256v1, secp384r1, or secp521r1)
ec_curve = "prime256v1"

# Always generate new keys on renewal (default: false)
always_generate_new_keys = false

# Domain configurations
# Each [[domains]] entry creates one certificate

[[domains]]
primary = "example.com"
sans = ["www", "mail"]  # Shorthand: "www" expands to "www.example.com"
ocsp_staple_required = false

[[domains]]
primary = "api.example.com"
# No SANs - single domain certificate
ocsp_staple_required = true

# Action configurations
# Define what happens after certificates are renewed

[actions.default]
# Default actions run for any domain not in a specific action group
update = [
    "systemctl reload nginx",
]

[actions.webservers]
# Domains using this action group
domains = ["example.com"]
# Upload certificates to remote servers
upload_certs = [
    "rsync -avz CERTS user@webserver:/etc/ssl/certs/",
]
upload_keys = [
    "rsync -avz KEYS user@webserver:/etc/ssl/private/",
]
# Run commands after upload
update = [
    "ssh user@webserver 'systemctl reload nginx'",
]

[actions.every]
# Actions that run for EVERY renewed certificate
update = [
    "/usr/local/bin/backup-certs.sh",
]

# Notification configuration
# Configure alerting for renewal failures and expiry warnings

[notifications]
# Email notifications (requires sendmail or SMTP configured)
# email_to = "admin@example.com"
# email_from = "lematt@example.com"

# Webhook notifications (Slack, Discord, etc.)
# webhook_url = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
# webhook_format = "slack"  # slack, discord, or generic

# PagerDuty integration (only alerts on failures)
# pagerduty_key = "your-integration-key"

# Ntfy push notifications (https://ntfy.sh)
# ntfy_topic = "my-cert-alerts"
# ntfy_server = "https://ntfy.sh"

# Custom notification command
# custom_command = "/usr/local/bin/my-notify-script.sh"

# Journald logging (enabled by default)
journald_enabled = true

# When to send notifications
notify_on_failure = true
notify_on_warning = true
notify_on_success = false

# Systemd timer configuration (used by --install-systemd)

[systemd]
# Timer schedule (default: twice daily at midnight and noon)
# calendar = "*-*-* 00,12:00:00"

# Random delay to spread load (seconds)
# randomized_delay_sec = 3600

# Run missed timers on boot
# persistent = true
'''
    path.write_text(example)
    logger.info(f"Created example TOML config at {path}")
