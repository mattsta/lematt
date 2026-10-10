"""Configuration file loading for lematt.

One loader reads every supported layout and produces the typed objects
the rest of lematt uses:

- INI: ``lematt.conf`` plus the ``domains`` and ``actions.conf`` files in
  the same directory.
- TOML: ``lematt.toml`` with ``[config]``, optional inline ``[[domains]]``
  and ``[actions.*]`` tables (falling back to the ``domains`` and
  ``actions.conf`` files when those are absent).

Invalid configuration raises :class:`ConfigError` with an operator-facing
message.
"""

import configparser
import json
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from lematt.config import (
    ActionConfig,
    DomainActions,
    DomainConfig,
    LemattConfig,
    drop_obsolete_domain_flags,
    warn_obsolete_config_keys,
)

MAX_NAMES_PER_CERTIFICATE = 100

# Per-certificate options allowed on domains-file lines (KEY=VALUE tokens)
DOMAIN_OPTIONS = ("profile",)
PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Curves Let's Encrypt accepts for certificate keys
SUPPORTED_CURVES = ("prime256v1", "secp256r1", "secp384r1")

# Sections with fixed meaning in actions configuration
RESERVED_ACTION_SECTIONS = ("default", "every")

INI_DEFAULTS = {
    "keyBitsRSA": "2048",
    "alwaysGenerateNewKeys": "no",
    "generateNewCertsAfterDays": "0",
    "curve": "prime256v1",
}


TOML_SETTING_TYPES: dict[str, type | tuple[type, ...]] = {
    "challenge_dir": str,
    "account_key": str,
    "reauthorize_days": (int, float),
    "generate_new_certs_after_days": (int, float),
    "always_generate_new_keys": bool,
    "key_bits_rsa": int,
    "ec_curve": str,
    "rsa_tag": str,
    "curve_tag": str,
    "profile": str,
}
TOML_TYPE_NAMES: dict[type | tuple[type, ...], str] = {
    str: "a string",
    int: "an integer",
    (int, float): "a number",
    bool: "true or false",
}


class ConfigError(ValueError):
    """The configuration is invalid; the message explains what to fix."""


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------


def _string_list(value: Any, where: str) -> list[str]:
    """A TOML array of strings (a bare string is an error, not characters)."""
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: must be a list of strings")
    return list(value)


def check_profile(profile: Any, where: str) -> str | None:
    """Validate an ACME profile name (offered profiles are checked at order time)."""
    if profile is None:
        return None
    if not isinstance(profile, str) or not PROFILE_NAME.match(profile):
        raise ConfigError(f"{where}: invalid profile name {profile!r}")
    return profile


def make_domain_config(
    names: list[str], where: str, *, profile: str | None = None
) -> DomainConfig:
    """Build a certificate definition from its names (primary first).

    Names without a dot are shorthand for ``<name>.<primary>``.
    """
    if len(names) > MAX_NAMES_PER_CERTIFICATE:
        raise ConfigError(
            f"{where}: {len(names)} names configured, but a certificate holds "
            f"at most {MAX_NAMES_PER_CERTIFICATE}"
        )
    primary = names[0]
    sans = [name if "." in name else f"{name}.{primary}" for name in names[1:]]
    return DomainConfig(primary_domain=primary, san_domains=sans, profile=profile)


def load_domains_file(path: Path) -> list[DomainConfig]:
    """Parse a domains file: one certificate per line, primary name first.

    A ``profile=NAME`` token selects the certificate's ACME profile.
    """
    domains: list[DomainConfig] = []
    with path.open() as f:
        for line_num, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            where = f"{path}:{line_num}"
            names, options = [], {}
            for token in drop_obsolete_domain_flags(line.split(), where):
                key, sep, value = token.partition("=")
                if not sep:
                    names.append(token)
                elif key in DOMAIN_OPTIONS:
                    options[key] = value
                else:
                    raise ConfigError(
                        f"{where}: unknown option '{key}' (known: {', '.join(DOMAIN_OPTIONS)})"
                    )
            if not names:
                logger.warning(f"{where}: skipping line without domain names")
                continue
            profile = check_profile(options.get("profile"), where)
            domains.append(make_domain_config(names, where, profile=profile))
    return domains


def domains_from_toml(entries: Iterable[dict[str, Any]]) -> list[DomainConfig]:
    """Build certificate definitions from TOML ``[[domains]]`` entries."""
    domains: list[DomainConfig] = []
    for index, entry in enumerate(entries, 1):
        where = f"lematt.toml [[domains]] #{index}"
        primary = entry.get("primary")
        if not primary:
            raise ConfigError(f"{where}: missing 'primary'")
        warn_obsolete_config_keys(entry, f"lematt.toml [[domains]] {primary}")
        profile = check_profile(entry.get("profile"), where)
        domains.append(
            make_domain_config(
                [primary, *_string_list(entry.get("sans", []), f"{where} sans")],
                where,
                profile=profile,
            )
        )
    return domains


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def _add_action_section(
    result: DomainActions, action: ActionConfig, where: str
) -> None:
    """Place one parsed section into the action layout, enforcing its rules."""
    if action.name in RESERVED_ACTION_SECTIONS:
        if action.domains:
            raise ConfigError(f"{where}: 'domains' is not allowed in this section")
        if action.name == "default":
            result.default = action
        else:
            result.every = action
        return

    if not action.domains:
        raise ConfigError(f"{where}: missing 'domains' (which domains it applies to)")
    for domain in action.domains:
        result.domain_configs[domain] = action


def _ini_commands(values: configparser.SectionProxy, key: str, where: str) -> list[str]:
    """Read an actions.conf command list (a JSON list of strings)."""
    if key not in values:
        return []
    try:
        parsed = json.loads(values[key])
    except json.JSONDecodeError as e:
        raise ConfigError(
            f"{where}: '{key}' must be a JSON list of commands ({e})"
        ) from e
    if not isinstance(parsed, list) or not all(isinstance(c, str) for c in parsed):
        raise ConfigError(f"{where}: '{key}' must be a JSON list of strings")
    return parsed


def load_actions_ini(path: Path) -> DomainActions:
    """Parse actions.conf (missing file means no actions)."""
    parser = configparser.ConfigParser()
    parser.read(path)
    result = DomainActions()

    for section in parser.sections():
        values = parser[section]
        where = f"{path.name} [{section}]"
        warn_obsolete_config_keys(values, where)
        action = ActionConfig(
            name=section,
            prepare_commands=_ini_commands(values, "prepare", where),
            upload_certs_commands=_ini_commands(values, "uploadCerts", where),
            upload_keys_commands=_ini_commands(values, "uploadKeys", where),
            update_commands=_ini_commands(values, "update", where),
            domains=values.get("domains", "").split(),
        )
        _add_action_section(result, action, where)

    return result


def actions_from_toml(tables: dict[str, dict[str, Any]]) -> DomainActions:
    """Build the action layout from TOML ``[actions.*]`` tables."""
    result = DomainActions()
    for name, table in tables.items():
        where = f"lematt.toml [actions.{name}]"
        warn_obsolete_config_keys(table, where)
        action = ActionConfig(
            name=name,
            prepare_commands=_string_list(table.get("prepare", []), f"{where} prepare"),
            upload_certs_commands=_string_list(
                table.get("upload_certs", []), f"{where} upload_certs"
            ),
            upload_keys_commands=_string_list(
                table.get("upload_keys", []), f"{where} upload_keys"
            ),
            update_commands=_string_list(table.get("update", []), f"{where} update"),
            domains=_string_list(table.get("domains", []), f"{where} domains"),
        )
        _add_action_section(result, action, where)
    return result


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


@dataclass
class ConfigLoader:
    """Load lematt configuration from INI or TOML.

    Pass ``config_file`` to load a specific file; its extension selects the
    format (``.toml`` is TOML, anything else INI). Without it, ``load()``
    looks in ``config_base`` for ``lematt.toml`` and then ``lematt.conf``.

    Example TOML config (lematt.toml):

        [config]
        challenge_dir = "/var/www/acme-challenge"
        account_key = "/etc/lematt/account.key"
        reauthorize_days = 15

        [[domains]]
        primary = "example.com"
        sans = ["www", "mail"]

        [actions.default]
        update = ["systemctl reload nginx"]

        [actions.webservers]
        domains = ["example.com"]
        upload_certs = ["rsync -avz CERTS /etc/ssl/certs/"]
    """

    config_base: Path
    config_file: Path | None = None
    _config_data: dict[str, Any] = field(default_factory=dict)
    _format: str = field(default="ini")

    @property
    def format(self) -> str:
        """The loaded format: ``"ini"`` or ``"toml"``."""
        return self._format

    @property
    def settings(self) -> dict[str, Any]:
        """Normalized ``[config]`` settings (snake_case keys)."""
        return dict(self._config_data.get("config", {}))

    @property
    def notifications(self) -> dict[str, Any]:
        """The TOML ``[notifications]`` table, if any."""
        return dict(self._config_data.get("notifications", {}))

    def notification_settings(self) -> dict[str, Any] | None:
        """Notification settings, or None if notifications aren't configured.

        They live in a TOML ``[notifications]`` table: the configuration file
        itself when it is TOML, otherwise a ``lematt.toml`` next to it.
        """
        if "notifications" in self._config_data:
            return self.notifications
        companion = self.config_base / "lematt.toml"
        if self._format != "ini" or not companion.is_file():
            return None
        loader = ConfigLoader(self.config_base, config_file=companion)
        loader.load()
        return loader.notifications if "notifications" in loader._config_data else None

    def load(self) -> None:
        """Read the configuration file.

        Raises:
            FileNotFoundError: The configuration file doesn't exist.
            ConfigError: The file can't be parsed or has invalid values.
        """
        if self.config_file is not None:
            path = self.config_file
            if not path.is_file():
                raise FileNotFoundError(f"Config file not found: {path}")
            self._format = "toml" if path.suffix == ".toml" else "ini"
        else:
            toml_path = self.config_base / "lematt.toml"
            ini_path = self.config_base / "lematt.conf"
            if toml_path.exists():
                path, self._format = toml_path, "toml"
            elif ini_path.exists():
                path, self._format = ini_path, "ini"
            else:
                raise FileNotFoundError(
                    f"No configuration file found. Expected {toml_path} or {ini_path}"
                )

        if self._format == "toml":
            self._load_toml(path)
        else:
            self._load_ini(path)
        logger.debug(f"Loaded {self._format.upper()} config from {path}")

    def _load_toml(self, path: Path) -> None:
        try:
            with path.open("rb") as f:
                self._config_data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{path}: {e}") from e

        for key, value in self._config_data.get("config", {}).items():
            expected = TOML_SETTING_TYPES.get(key)
            if expected is None:
                logger.warning(f"{path}: ignoring unknown [config] key '{key}'")
            elif not isinstance(value, expected) or isinstance(value, bool) != (
                expected is bool
            ):
                raise ConfigError(
                    f"{path}: [config] {key} must be {TOML_TYPE_NAMES[expected]}"
                )

    def _load_ini(self, path: Path) -> None:
        parser = configparser.ConfigParser()
        parser["DEFAULT"] = INI_DEFAULTS
        try:
            parser.read(path)
        except configparser.Error as e:
            raise ConfigError(f"{path}: {e}") from e
        if "config" not in parser:
            raise ConfigError(f"{path}: missing [config] section")

        config = parser["config"]

        def number[T: (int, float)](key: str, kind: type[T]) -> T:
            try:
                return kind(config[key])
            except ValueError as e:
                raise ConfigError(
                    f"{path}: invalid {key} value: {config[key]!r}"
                ) from e

        try:
            always_new_keys = config.getboolean("alwaysGenerateNewKeys")
        except ValueError as e:
            raise ConfigError(f"{path}: alwaysGenerateNewKeys must be yes/no") from e

        self._config_data = {
            "config": {
                "challenge_dir": config.get("challengeDropDir", ""),
                "account_key": config.get("accountKey", ""),
                "reauthorize_days": (
                    number("reauthorizeDays", float)
                    if "reauthorizeDays" in config
                    else None
                ),
                "generate_new_certs_after_days": number(
                    "generateNewCertsAfterDays", float
                ),
                "always_generate_new_keys": always_new_keys,
                "key_bits_rsa": number("keyBitsRSA", int),
                "ec_curve": config.get("curve"),
                "rsa_tag": config.get("rsaTag", ""),
                "curve_tag": config.get("curveTag", ""),
                "profile": check_profile(config.get("profile") or None, str(path)),
            }
        }

    def validate(
        self, *, require_write_access: bool = True
    ) -> tuple[list[str], list[str]]:
        """Check loaded settings; return ``(errors, warnings)``.

        Args:
            require_write_access: Whether the challenge directory is needed
                (False for read-only commands like --status).
        """
        errors: list[str] = []
        warnings: list[str] = []
        config = self.settings
        ini = self._format == "ini"

        def key_name(ini_key: str, toml_key: str) -> str:
            return ini_key if ini else toml_key

        required = [("accountKey", "account_key")]
        if require_write_access:
            required.append(("challengeDropDir", "challenge_dir"))
        for ini_key, toml_key in required:
            if not config.get(toml_key):
                errors.append(
                    f"Missing required config: '{key_name(ini_key, toml_key)}'"
                )

        raw_challenge_dir = config.get("challenge_dir")
        challenge_dir = Path(raw_challenge_dir) if raw_challenge_dir else None
        if require_write_access and challenge_dir and not challenge_dir.is_dir():
            errors.append(f"Challenge directory does not exist: {challenge_dir}")
            errors.append(f"  Create it with: mkdir -p {challenge_dir}")

        key_bits = config.get("key_bits_rsa", 2048)
        if key_bits < 2048:
            warnings.append(
                f"RSA key size {key_bits} is insecure. Use at least 2048 bits."
            )
        elif key_bits > 4096:
            warnings.append(
                f"RSA key size {key_bits} may cause performance issues. 2048-4096 recommended."
            )

        curve = config.get("ec_curve", "prime256v1")
        if curve not in SUPPORTED_CURVES:
            warnings.append(
                f"EC curve '{curve}' is not accepted by Let's Encrypt: {list(SUPPORTED_CURVES)}"
            )

        days = config.get("reauthorize_days")
        if days is not None and days < 1:
            warnings.append(f"reauthorizeDays={days} is very aggressive.")

        if not (self._format == "toml" and "domains" in self._config_data):
            domains_file = self.config_base / "domains"
            if not domains_file.is_file():
                errors.append(f"Domains file not found: {domains_file}")
        if not (self._format == "toml" and "actions" in self._config_data):
            actions_file = self.config_base / "actions.conf"
            if not actions_file.is_file():
                errors.append(f"Actions config not found: {actions_file}")

        return errors, warnings

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
        """Build the runtime LemattConfig from the loaded settings."""
        config = self.settings
        rsa_bits = config.get("key_bits_rsa", 2048)
        ec_curve = config.get("ec_curve", "prime256v1")

        return LemattConfig(
            config_base=self.config_base,
            challenge_dir=config.get("challenge_dir", ""),
            account_key=config.get("account_key", ""),
            reauthorize_days=config.get("reauthorize_days"),
            generate_new_certs_after_days=config.get(
                "generate_new_certs_after_days", 0.0
            ),
            always_generate_new_keys=config.get("always_generate_new_keys", False),
            rsa_key_bits=rsa_bits,
            ec_curve=ec_curve,
            rsa_tag=config.get("rsa_tag") or f"rsa{rsa_bits}",
            curve_tag=config.get("curve_tag") or ec_curve,
            profile=check_profile(config.get("profile"), "[config] profile"),
            is_test=is_test,
            is_cron=is_cron,
            is_dry_run=is_dry_run,
            force_renew=force_renew,
            concurrency=min(concurrency, 10),
            verbose=verbose,
        )

    def get_domains(self) -> list[DomainConfig]:
        """Certificate definitions: TOML ``[[domains]]`` or the domains file."""
        if self._format == "toml" and "domains" in self._config_data:
            return domains_from_toml(self._config_data["domains"])
        domains_file = self.config_base / "domains"
        if not domains_file.is_file():
            return []
        return load_domains_file(domains_file)

    def get_actions(self) -> DomainActions:
        """Action layout: TOML ``[actions.*]`` tables or actions.conf."""
        if self._format == "toml" and "actions" in self._config_data:
            return actions_from_toml(self._config_data["actions"])
        return load_actions_ini(self.config_base / "actions.conf")


def create_example_toml(path: Path) -> None:
    """Create an example TOML configuration file.

    Args:
        path: Path to write the example config.
    """
    example = """# lematt TOML configuration
# This is the modern configuration format for lematt.

[config]
# ACME challenge directory (must be served at /.well-known/acme-challenge/)
challenge_dir = "/var/www/html/.well-known/acme-challenge"

# Account key for Let's Encrypt (create with: openssl genrsa 4096 > account.key)
account_key = "/etc/lematt/account.key"

# Renewal timing follows the CA (ARI renewal windows, else 1/3 of the
# certificate lifetime remaining). Optionally renew earlier, this many days
# before expiry:
# reauthorize_days = 30

# RSA key size (2048, 3072, or 4096)
key_bits_rsa = 2048

# EC curve (prime256v1 or secp384r1)
ec_curve = "prime256v1"

# Always generate new keys on renewal (default: false)
always_generate_new_keys = false

# Domain configurations
# Each [[domains]] entry creates one certificate

[[domains]]
primary = "example.com"
sans = ["www", "mail"]  # Shorthand: "www" expands to "www.example.com"

[[domains]]
primary = "api.example.com"
# No SANs - single domain certificate

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
"""
    path.write_text(example)
    logger.info(f"Created example TOML config at {path}")
