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
"""

__version__ = "2.0.0"
__author__ = "Matt"

from lematt.actions import ActionRunner
from lematt.config import (
    ActionConfig,
    CertificateInfo,
    CertificateResult,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
)
from lematt.crypto import (
    HAS_CRYPTOGRAPHY,
    create_csr,
    generate_private_key,
    get_certificate_info,
)
from lematt.manager import CertificateManager

__all__ = [
    # Version
    "__version__",
    # Config dataclasses
    "KeyType",
    "CertificateInfo",
    "DomainConfig",
    "ActionConfig",
    "LemattConfig",
    "CertificateResult",
    "RenewalSummary",
    # Crypto
    "HAS_CRYPTOGRAPHY",
    "generate_private_key",
    "get_certificate_info",
    "create_csr",
    # Manager
    "CertificateManager",
    # Actions
    "ActionRunner",
]
