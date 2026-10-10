"""lematt - Matt's Let's Encrypt Automation.

A self-contained certificate management system for automating Let's Encrypt
certificate provisioning, renewal, and deployment.

Features:
- Generate and renew RSA and EC certificates
- Parallel certificate provisioning with configurable concurrency
- SAN/SNI/UCC support for up to 100 domains per certificate
- Flexible deployment actions (rsync, ssh, service reloads)
- Keys, CSRs and certificate parsing via the cryptography library
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
)
from lematt.config_loader import ConfigLoader, create_example_toml
from lematt.crypto import (
    create_csr,
    generate_private_key,
    get_certificate_info,
)

# UI/Display components
from lematt.display import (
    DisplayConfig,
    StatusStyle,
    console,
    create_action_table,
    create_certificate_table,
    create_config_tree,
    create_domain_tree,
    create_health_summary,
    create_renewal_progress,
    print_banner,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from lematt.executor import (
    BatchProgress,
    CertificateExecutor,
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
from lematt.help import (
    HELP_TOPICS,
    HelpCategory,
    HelpRenderer,
    HelpSystem,
    HelpTopic,
    get_quick_help,
    print_help,
    search_help,
)
from lematt.log import logger, setup_logging
from lematt.manager import CertificateManager
from lematt.notifications import (
    NotificationConfig,
    NotificationEvent,
    NotificationManager,
)
from lematt.reports import (
    CertificateInventoryItem,
    RenewalScheduleItem,
    Report,
    ReportConfig,
    ReportGenerator,
    ReportRenderer,
    generate_full_report,
    generate_quick_report,
)
from lematt.systemd import (
    PRESETS as SYSTEMD_PRESETS,
)
from lematt.systemd import (
    SystemdConfig,
    SystemdInstaller,
)
from lematt.tui.app import DashboardConfig, LemattDashboardApp

__all__ = [
    # Crypto
    "HELP_TOPICS",
    "SYSTEMD_PRESETS",
    "ActionConfig",
    # Actions
    "ActionRunner",
    "BatchProgress",
    # Executor
    "CertificateExecutor",
    "CertificateHealth",
    "CertificateInfo",
    "CertificateInventoryItem",
    # Manager
    "CertificateManager",
    "CertificateResult",
    # Config loader
    "ConfigLoader",
    # Dashboard
    "DashboardConfig",
    "DisplayConfig",
    "DomainActions",
    "DomainConfig",
    # Health checks
    "HealthChecker",
    "HealthStatus",
    "HelpCategory",
    "HelpRenderer",
    # Help system
    "HelpSystem",
    "HelpTopic",
    # Config dataclasses
    "KeyType",
    "LemattConfig",
    "LemattDashboardApp",
    # Notifications
    "NotificationConfig",
    "NotificationEvent",
    "NotificationManager",
    "PrometheusMetrics",
    "RenewalScheduleItem",
    "RenewalSummary",
    # Reports
    "Report",
    "ReportConfig",
    "ReportGenerator",
    "ReportRenderer",
    "StatusStyle",
    "SystemHealth",
    # Systemd
    "SystemdConfig",
    "SystemdInstaller",
    "TaskProgress",
    "TaskStatus",
    # Version
    "__version__",
    # Display components
    "console",
    "create_action_table",
    "create_certificate_table",
    "create_config_tree",
    "create_csr",
    "create_domain_tree",
    "create_example_toml",
    "create_health_summary",
    "create_renewal_progress",
    "generate_full_report",
    "generate_private_key",
    "generate_quick_report",
    "get_certificate_info",
    "get_quick_help",
    # Logging
    "logger",
    "print_banner",
    "print_error",
    "print_help",
    "print_info",
    "print_success",
    "print_warning",
    "search_help",
    "setup_logging",
]
