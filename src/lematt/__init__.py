"""lematt - Matt's Let's Encrypt Automation.

A self-contained certificate management system for automating Let's Encrypt
certificate provisioning, renewal, and deployment.

Features:
- Generate and renew RSA and EC certificates
- Parallel certificate provisioning with configurable concurrency
- SAN/SNI/UCC support for up to 100 domains per certificate
- Flexible deployment actions (rsync, ssh, service reloads)
- Native cryptography support (optional) for ~5x performance
- Test mode with LE staging endpoint
- Robust concurrent processing with error isolation and rate limiting
"""

__version__ = "2.0.0"
__author__ = "Matt"

from lematt.actions import ActionRunner
from lematt.config import (
    ActionConfig,
    CertificateInfo,
    CertificateResult,
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
    WorkerResult,
)
from lematt.config_loader import ConfigLoader, create_example_toml
from lematt.crypto import (
    HAS_CRYPTOGRAPHY,
    create_csr,
    generate_private_key,
    get_certificate_info,
)
from lematt.executor import (
    BatchProgress,
    CertificateExecutor,
    RateLimiter,
    TaskProgress,
    TaskStatus,
)
from lematt.health import (
    CertificateHealth,
    HealthChecker,
    HealthStatus,
    PrometheusMetrics,
    SystemHealth,
)
from lematt.log import logger, setup_logging
from lematt.manager import CertificateManager
from lematt.notifications import (
    NotificationConfig,
    NotificationEvent,
    NotificationManager,
)
from lematt.systemd import (
    PRESETS as SYSTEMD_PRESETS,
)
from lematt.systemd import (
    SystemdConfig,
    SystemdInstaller,
)

__all__ = [
    # Version
    "__version__",
    # Logging
    "logger",
    "setup_logging",
    # Config dataclasses
    "KeyType",
    "CertificateInfo",
    "DomainConfig",
    "DomainActions",
    "ActionConfig",
    "LemattConfig",
    "CertificateResult",
    "RenewalSummary",
    "WorkerResult",
    # Crypto
    "HAS_CRYPTOGRAPHY",
    "generate_private_key",
    "get_certificate_info",
    "create_csr",
    # Manager
    "CertificateManager",
    # Actions
    "ActionRunner",
    # Config loader
    "ConfigLoader",
    "create_example_toml",
    # Executor
    "CertificateExecutor",
    "BatchProgress",
    "TaskProgress",
    "TaskStatus",
    "RateLimiter",
    # Health checks
    "HealthChecker",
    "HealthStatus",
    "CertificateHealth",
    "SystemHealth",
    "PrometheusMetrics",
    # Notifications
    "NotificationConfig",
    "NotificationEvent",
    "NotificationManager",
    # Systemd
    "SystemdConfig",
    "SystemdInstaller",
    "SYSTEMD_PRESETS",
]
