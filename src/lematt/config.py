"""Configuration dataclasses for lematt.

This module provides type-safe configuration and result dataclasses
for certificate management operations.
"""

import datetime
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum, auto


class KeyType(Enum):
    """Enumeration of supported key types."""

    RSA = auto()
    EC = auto()

    @classmethod
    def from_string(cls, s: str) -> KeyType:
        """Convert string to KeyType enum."""
        mapping = {"rsa": cls.RSA, "ec": cls.EC}
        if s.lower() not in mapping:
            raise ValueError(f"Invalid key type: '{s}' - must be 'rsa' or 'ec'")
        return mapping[s.lower()]

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class CertificateInfo:
    """Information about a certificate's status and expiration."""

    exists: bool
    path: str
    not_after: datetime.datetime | None = None
    not_before: datetime.datetime | None = None
    subject_cn: str | None = None
    san_domains: list[str] = field(default_factory=list)
    issuer: str | None = None
    serial_number: str | None = None
    parse_error: str | None = None

    @property
    def days_until_expiry(self) -> int | None:
        """Calculate days until certificate expires."""
        if not self.not_after:
            return None
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        return (self.not_after - now).days

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        days = self.days_until_expiry
        return days is not None and days < 0

    @property
    def needs_renewal(self) -> bool:
        """Check if certificate needs renewal (within 30 days of expiry)."""
        days = self.days_until_expiry
        return days is None or days < 30


@dataclass
class DomainConfig:
    """Configuration for a domain or set of SAN domains."""

    primary_domain: str
    san_domains: list[str] = field(default_factory=list)
    ocsp_staple_required: bool = False

    @property
    def all_domains(self) -> list[str]:
        """Get all domains including primary and SANs."""
        return [self.primary_domain, *self.san_domains]

    @property
    def is_san_cert(self) -> bool:
        """Check if this is a SAN certificate."""
        return len(self.san_domains) > 0

    @property
    def filename_base(self) -> str:
        """Generate the base filename for this domain config."""
        if self.is_san_cert:
            return "_".join(self.all_domains)
        return self.primary_domain

    def __str__(self) -> str:
        if self.is_san_cert:
            return f"{self.primary_domain} (+{len(self.san_domains)} SANs)"
        return self.primary_domain


@dataclass
class ActionConfig:
    """Configuration for pre/post certificate actions."""

    name: str
    prepare_commands: list[str] = field(default_factory=list)
    upload_certs_commands: list[str] = field(default_factory=list)
    upload_keys_commands: list[str] = field(default_factory=list)
    update_commands: list[str] = field(default_factory=list)
    ocsp_staple_required: bool = False
    domains: list[str] = field(default_factory=list)

    def has_actions(self) -> bool:
        """Check if any actions are configured."""
        return bool(
            self.prepare_commands
            or self.upload_certs_commands
            or self.upload_keys_commands
            or self.update_commands
        )

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for backward compatibility."""
        return {
            "actionName": self.name,
            "prepare": self.prepare_commands,
            "uploadCerts": self.upload_certs_commands,
            "uploadKeys": self.upload_keys_commands,
            "update": self.update_commands,
            "ocspStapleRequired": self.ocsp_staple_required,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object], name: str = "default") -> ActionConfig:
        """Create ActionConfig from dictionary."""
        return cls(
            name=str(data.get("actionName", name)),
            prepare_commands=list(data.get("prepare", [])),  # type: ignore[arg-type]
            upload_certs_commands=list(data.get("uploadCerts", [])),  # type: ignore[arg-type]
            upload_keys_commands=list(data.get("uploadKeys", [])),  # type: ignore[arg-type]
            update_commands=list(data.get("update", [])),  # type: ignore[arg-type]
            ocsp_staple_required=bool(data.get("ocspStapleRequired", False)),
        )


@dataclass
class DomainActions:
    """Container for all domain action configurations.

    This replaces the arbitrary dict[str, dict] pattern with a proper dataclass.
    """

    default: ActionConfig = field(default_factory=lambda: ActionConfig(name="default"))
    every: ActionConfig | None = None
    domain_configs: dict[str, ActionConfig] = field(default_factory=dict)

    def get_for_domain(self, domain: str) -> ActionConfig:
        """Get the action configuration for a domain."""
        return self.domain_configs.get(domain, self.default)

    def get_ocsp_required(self, domain: str) -> bool:
        """Get OCSP stapling requirement for a domain."""
        config = self.get_for_domain(domain)
        return config.ocsp_staple_required

    def all_action_names(self) -> dict[str, ActionConfig]:
        """Get all named action configurations."""
        result: dict[str, ActionConfig] = {"default": self.default}
        if self.every:
            result["every"] = self.every
        for _domain, config in self.domain_configs.items():
            if config.name not in result:
                result[config.name] = config
        return result


@dataclass
class WorkerResult:
    """Result from a certificate worker process.

    This is a serializable dataclass used for IPC between the main process
    and worker processes. It replaces the arbitrary dict pattern.
    """

    domain: str
    key_type: str
    success: bool
    renewed: bool
    cert_path: str | None = None
    key_path: str | None = None
    error_message: str | None = None
    all_domains: list[str] = field(default_factory=list)
    exception: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for process serialization."""
        return {
            "domain": self.domain,
            "key_type": self.key_type,
            "success": self.success,
            "renewed": self.renewed,
            "cert_path": self.cert_path,
            "key_path": self.key_path,
            "error_message": self.error_message,
            "all_domains": self.all_domains,
            "exception": self.exception,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> WorkerResult:
        """Create WorkerResult from dictionary."""
        return cls(
            domain=str(data["domain"]),
            key_type=str(data["key_type"]),
            success=bool(data["success"]),
            renewed=bool(data["renewed"]),
            cert_path=data.get("cert_path") if data.get("cert_path") else None,  # type: ignore[arg-type]
            key_path=data.get("key_path") if data.get("key_path") else None,  # type: ignore[arg-type]
            error_message=data.get("error_message") if data.get("error_message") else None,  # type: ignore[arg-type]
            all_domains=list(data.get("all_domains", [])),  # type: ignore[arg-type]
            exception=data.get("exception") if data.get("exception") else None,  # type: ignore[arg-type]
        )


@dataclass
class LemattConfig:
    """Global configuration for lematt."""

    # Paths
    config_base: str
    challenge_dir: str
    account_key: str

    # Certificate settings
    reauthorize_days: float = 15.0
    generate_new_certs_after_days: float = 0.0
    always_generate_new_keys: bool = False

    # Key settings
    rsa_key_bits: int = 2048
    ec_curve: str = "prime256v1"
    rsa_tag: str = ""
    curve_tag: str = ""

    # Runtime settings
    is_test: bool = False
    is_cron: bool = False
    is_dry_run: bool = False
    force_renew: bool = False
    concurrency: int = 1
    verbose: bool = False

    # ACME endpoints
    staging_url: str = "https://acme-staging-v02.api.letsencrypt.org/directory"
    production_url: str = "https://acme-v02.api.letsencrypt.org/directory"

    def __post_init__(self) -> None:
        """Set default tags if not provided."""
        if not self.rsa_tag:
            self.rsa_tag = f"rsa{self.rsa_key_bits}"
        if not self.curve_tag:
            self.curve_tag = self.ec_curve

    @property
    def acme_directory_url(self) -> str:
        """Get the appropriate ACME directory URL."""
        return self.staging_url if self.is_test else self.production_url

    @property
    def reauthorize_timedelta(self) -> timedelta:
        """Get the reauthorization window as a timedelta."""
        if self.generate_new_certs_after_days > 0:
            return timedelta(days=90) - timedelta(days=self.generate_new_certs_after_days)
        return timedelta(days=self.reauthorize_days)

    def get_subdir(self, subdir: str) -> str:
        """Get the appropriate subdirectory based on test/prod mode."""
        base = "test/" if self.is_test else "prod/"
        return base + subdir

    def get_cert_path(self, domain_config: DomainConfig, key_type: KeyType) -> str:
        """Generate the certificate file path."""
        tag = self.rsa_tag if key_type == KeyType.RSA else self.curve_tag
        test_suffix = ".test" if self.is_test else ""
        return f"{self.config_base}/{self.get_subdir('cert')}/{domain_config.filename_base}-cert-combined.{tag}{test_suffix}.pem"

    def get_key_path(self, domain_config: DomainConfig, key_type: KeyType) -> str:
        """Generate the private key file path."""
        tag = self.rsa_tag if key_type == KeyType.RSA else self.curve_tag
        test_suffix = ".test" if self.is_test else ""
        return f"{self.config_base}/{self.get_subdir('key')}/{domain_config.filename_base}-key.{tag}{test_suffix}.pem"

    def get_csr_path(self, domain_config: DomainConfig, key_type: KeyType) -> str:
        """Generate the CSR file path."""
        tag = self.rsa_tag if key_type == KeyType.RSA else self.curve_tag
        test_suffix = ".test" if self.is_test else ""
        return f"{self.config_base}/{self.get_subdir('csr')}/{domain_config.filename_base}-csr.{tag}{test_suffix}.csr"


@dataclass
class CertificateResult:
    """Result of a certificate generation/renewal operation."""

    domain_config: DomainConfig
    key_type: KeyType
    success: bool
    renewed: bool = False
    cert_path: str | None = None
    key_path: str | None = None
    error_message: str | None = None

    @property
    def domain(self) -> str:
        return self.domain_config.primary_domain


@dataclass
class RenewalSummary:
    """Summary of all certificate renewal operations."""

    total_domains: int = 0
    renewed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    results: list[CertificateResult] = field(default_factory=list)

    def add_result(self, result: CertificateResult) -> None:
        """Add a result to the summary."""
        self.results.append(result)
        self.total_domains += 1
        if result.renewed:
            if result.success:
                self.renewed_count += 1
            else:
                self.failed_count += 1
        else:
            self.skipped_count += 1

    @property
    def all_successful(self) -> bool:
        return self.failed_count == 0
