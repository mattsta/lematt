#!/usr/bin/env python3

"""Maintain your LE infrastructure with config files and behaviors.

This was originally a shell script but got converted to python as
more conditions and exceptions became necessary.

lematt generates both rsa keys/certs AND ec keys/certs because modern systems
accept them all at once. You'll end up with two certs and two keys generated for
each input domain you configure.

Brief (very brief) overview of acronyms and terms:
    - LE: Let's Encrypt - CA issuing free DV certs, subject to rate limits
    - CA: Certificate Authority - an issuer/signer of certificates
    - DV: Domain Validated - just verifies you can control hosting and/or email
    - SAN: subjectAltName - how one certificate supports multiple domain names
    - SNI: Server Name Indication - TLS virtual hosting by giving clients SANs
    - TLS: Transport Layer Security - the "s" in "https" allowing encryption
    - UCC: Unified Communications Certificate - X.509 TLS certificate with SANs
    - X.509: an archaic, but sadly universal, file format for certificates
    - CSR: Certificate Signing Request - how CAs sign public keys and domains
    - PEM: "Privacy-Enhanced E-Mail" - a file format for base64 encoded data
    - RSA: historically standard Internet-wide public key encryption system
    - EC: Elliptic Curve - a more modern public key encryption system
    - OCSP: Online Certificate Status Protocol - realtime CRL; signed responses
    - Staple: include CA-signed OCSP status with your cert when clients connect
    - CRL: Certificate Revocation List - a way to check if certs are revoked
"""

import argparse
import collections
import configparser
import contextlib
import datetime
import itertools
import json
import logging
import multiprocessing
import os
import pathlib
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from configparser import SectionProxy
from dataclasses import dataclass, field
from datetime import timedelta  # make some lines shorter
from enum import Enum, auto
from typing import Any

import acme_tiny  # distributed with lematt

# Try to import cryptography for native crypto operations
# Falls back to openssl subprocess if not available
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ============================================================================
# Data Classes for Type-Safe Configuration and Results
# ============================================================================


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
        return [self.primary_domain] + self.san_domains

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

    def __post_init__(self):
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
            return timedelta(days=90) - timedelta(
                days=self.generate_new_certs_after_days
            )
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


# ============================================================================
# Cryptography Library Functions (optional, falls back to openssl)
# ============================================================================


def generate_rsa_key_native(bits: int = 2048) -> bytes:
    """Generate RSA private key using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=bits, backend=default_backend()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_ec_key_native(curve_name: str = "prime256v1") -> bytes:
    """Generate EC private key using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    # Map curve names to cryptography curve objects
    curve_map = {
        "prime256v1": ec.SECP256R1(),
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }

    if curve_name not in curve_map:
        raise ValueError(f"Unsupported curve: {curve_name}")

    private_key = ec.generate_private_key(
        curve_map[curve_name], backend=default_backend()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def parse_certificate_native(cert_path: str) -> CertificateInfo:
    """Parse certificate using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    if not os.path.isfile(cert_path):
        return CertificateInfo(exists=False, path=cert_path)

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Extract subject CN
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            cn = None

        # Extract SAN domains
        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_domains = [
                name.value for name in san_ext.value if isinstance(name, x509.DNSName)
            ]
        except x509.ExtensionNotFound:
            pass

        # Extract issuer
        try:
            issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            issuer = None

        return CertificateInfo(
            exists=True,
            path=cert_path,
            not_after=cert.not_valid_after_utc.replace(tzinfo=None)
            if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_after.replace(tzinfo=None),
            not_before=cert.not_valid_before_utc.replace(tzinfo=None)
            if hasattr(cert, "not_valid_before_utc")
            else cert.not_valid_before.replace(tzinfo=None),
            subject_cn=cn,
            san_domains=san_domains,
            issuer=issuer,
            serial_number=str(cert.serial_number),
        )
    except Exception as e:
        return CertificateInfo(exists=True, path=cert_path, parse_error=str(e))


def generate_csr_native(
    private_key_path: str, domains: list[str], ocsp_must_staple: bool = False
) -> bytes:
    """Generate CSR using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Build CSR
    primary_domain = domains[0]
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, primary_domain),
            ]
        )
    )

    # Add SAN extension if multiple domains
    if len(domains) > 1 or True:  # Always add SAN for consistency
        san_names = [x509.DNSName(d) for d in domains]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )

    # Add OCSP Must-Staple if requested
    if ocsp_must_staple:
        builder = builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    # Sign and return
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)


# ============================================================================
# Unified Crypto Functions (native with openssl fallback)
# ============================================================================


def generate_private_key(
    key_type: KeyType,
    config: LemattConfig | None = None,
    rsa_bits: int = 2048,
    ec_curve: str = "prime256v1",
) -> bytes:
    """Generate a private key, using native crypto if available."""
    if HAS_CRYPTOGRAPHY:
        if key_type == KeyType.RSA:
            return generate_rsa_key_native(rsa_bits)
        else:
            return generate_ec_key_native(ec_curve)
    else:
        # Fall back to openssl subprocess
        if key_type == KeyType.RSA:
            result = subprocess.run(
                ["openssl", "genrsa", str(rsa_bits)], capture_output=True, check=True
            )
        else:
            result = subprocess.run(
                ["openssl", "ecparam", "-genkey", "-name", ec_curve],
                capture_output=True,
                check=True,
            )
        return result.stdout


def get_certificate_info(cert_path: str) -> CertificateInfo:
    """Get certificate information, using native crypto if available."""
    if HAS_CRYPTOGRAPHY:
        return parse_certificate_native(cert_path)

    # Fall back to openssl subprocess
    if not os.path.isfile(cert_path):
        return CertificateInfo(exists=False, path=cert_path)

    try:
        # Get expiration date
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                cert_path,
                "-noout",
                "-enddate",
                "-startdate",
                "-subject",
                "-issuer",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        info = CertificateInfo(exists=True, path=cert_path)
        ssl_date_fmt = r"%b %d %H:%M:%S %Y %Z"

        for line in result.stdout.strip().split("\n"):
            if line.startswith("notAfter="):
                with contextlib.suppress(ValueError):
                    info.not_after = datetime.datetime.strptime(line[9:], ssl_date_fmt)
            elif line.startswith("notBefore="):
                with contextlib.suppress(ValueError):
                    info.not_before = datetime.datetime.strptime(
                        line[10:], ssl_date_fmt
                    )
            elif line.startswith("subject="):
                # Extract CN from subject
                import re

                cn_match = re.search(r"CN\s*=\s*([^,/]+)", line)
                if cn_match:
                    info.subject_cn = cn_match.group(1).strip()
            elif line.startswith("issuer="):
                import re

                cn_match = re.search(r"CN\s*=\s*([^,/]+)", line)
                if cn_match:
                    info.issuer = cn_match.group(1).strip()

        # Get SAN domains
        try:
            san_result = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
                capture_output=True,
                text=True,
                check=True,
            )
            import re

            san_match = re.search(
                r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", san_result.stdout
            )
            if san_match:
                san_line = san_match.group(1)
                info.san_domains = [
                    d.replace("DNS:", "").strip()
                    for d in san_line.split(",")
                    if d.strip().startswith("DNS:")
                ]
        except subprocess.CalledProcessError:
            pass

        return info

    except (subprocess.CalledProcessError, OSError) as e:
        return CertificateInfo(exists=True, path=cert_path, parse_error=str(e))


def create_csr(
    private_key_path: str,
    domains: list[str],
    output_path: str,
    ocsp_must_staple: bool = False,
) -> bool:
    """Create a CSR, using native crypto if available."""
    if HAS_CRYPTOGRAPHY:
        try:
            csr_bytes = generate_csr_native(private_key_path, domains, ocsp_must_staple)
            with open(output_path, "wb") as f:
                f.write(csr_bytes)
            return True
        except Exception as e:
            logger.warning(
                f"Native CSR generation failed, falling back to openssl: {e}"
            )

    # Fall back to openssl subprocess
    primary_domain = domains[0]
    use_san = len(domains) > 1

    san_config = ""
    cmd_san = ""
    if use_san:
        alt_names = [f"DNS:{domain}" for domain in domains]
        san_config = ",".join(alt_names)
        cmd_san = "-reqexts SAN"

    ocsp_line = ""
    if ocsp_must_staple:
        ocsp_line = "1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05"

    stdin_config = f"""[req]
distinguished_name=req_dn

[req_dn]

[v3_req]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
{ocsp_line}

[SAN]
subjectAltName={san_config}"""

    try:
        cmd = f"openssl req -new -sha256 -key {private_key_path} -subj /CN={primary_domain} {cmd_san} -config -"
        result = subprocess.run(
            cmd.split(), input=stdin_config.encode(), capture_output=True, check=True
        )
        with open(output_path, "wb") as f:
            f.write(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"CSR generation failed: {e}")
        return False


# Configure module-level logger
logger = logging.getLogger("lematt")
logger.setLevel(logging.DEBUG)  # Allow all levels; handlers will filter

MIN_VERSION = (3, 6)
if sys.version_info < MIN_VERSION:
    # Why only 3.6 or later? 3.6 introduced F-strings we
    # use for f"hello {var}" formatting everywhere.
    # Sure, we could have used one of the other 20 kinds of
    # python string formatting methods, but we didn't.
    print("Sorry, lematt requires Python 3.6 or later.")
    sys.exit(1)


def setup_logging(is_cron: bool = False, verbose: bool = False) -> None:
    """Configure logging handlers based on runtime mode."""
    # Clear any existing handlers
    logger.handlers.clear()

    # Create formatter
    if is_cron:
        # Simpler format for cron (typically captured in logs)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        # More detailed format for interactive use
        formatter = logging.Formatter("%(message)s")

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if is_cron:
        console_handler.setLevel(logging.WARNING)  # Only warnings and above for cron
    elif verbose:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def log(what: str, mode: str = "", update: bool = False) -> None:
    """Log a message with optional mode prefix.

    Args:
        what: The message to log
        mode: Optional category/mode prefix (e.g., "CMD", "RETRY", "ERROR")
        update: If True, always log even in cron mode (treated as important)
    """
    # Handle empty messages (visual separators)
    if not what:
        if not IS_CRON:
            print()
        return

    # Build the message
    prefix = "[TEST] " if IS_TEST else "> "

    mode_str = f"[{mode}] " if mode else ""

    message = f"{prefix}{mode_str}{what}"

    # Determine log level based on mode and update flag
    if mode in ("ERROR", "FAIL"):
        logger.error(message)
    elif mode in ("WARN", "WARNING"):
        logger.warning(message)
    elif update:
        logger.info(message)
    else:
        logger.debug(message)


def getSubdir(subdir: str) -> str:
    """Return the appropriate subdirectory path based on test/prod mode."""
    base = "test/" if IS_TEST else "prod/"

    return base + subdir


def loadDomainActions() -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Read actions.conf and parse actions into usable dicts."""
    domainActions = {}
    domainActionNames = {}
    updaters = configparser.ConfigParser()
    updaters.read(f"{configBase}/actions.conf")

    def extractAndPopulate(sectionName, override, actions):
        if sectionName in override:
            commands = json.loads(override[sectionName])
            actions[sectionName] = commands

    defaultOCSP = False
    if "ocspStapleRequired" in updaters["default"]:
        defaultOCSP = updaters["default"]["ocspStapleRequired"]

    def errIfIn(what, things, sect):
        if what in things:
            print(f"Error: '{what}' entry not allowed in section [{sect}]")
            sys.exit(1)

    # Usage sanity check
    for uda in ["default", "every"]:
        preActions = updaters[uda]
        errIfIn("domains", preActions, uda)

        if uda == "every":
            errIfIn("ocspStapleRequired", preActions, uda)

    # Use ConfigParser magic to make a global dict 'default' for this key
    # so we don't have to guard "if val in dict" everywhere.
    updaters["DEFAULT"] = {"ocspStapleRequired": defaultOCSP}

    # Use '.sections()' here because if we iterate 'updaters' directly,
    # we get the meta 'DEFAULT' key which we don't want to process.
    # '.sections()' only returns user-created sections.
    for uda in updaters.sections():
        preActions = updaters[uda]
        actions = {"actionName": uda}
        domainActionNames[uda] = actions

        if not (uda == "default" or uda == "every"):
            # If not in the default section, get domains this override
            # should apply towards.
            domains = preActions["domains"].split()

        # Extract override sections present (all optional)
        extractAndPopulate("prepare", preActions, actions)
        extractAndPopulate("update", preActions, actions)
        extractAndPopulate("uploadCerts", preActions, actions)
        extractAndPopulate("uploadKeys", preActions, actions)

        # Irrelevant for section 'every', but no harm done:
        actions["ocspStapleRequired"] = preActions.getboolean("ocspStapleRequired")

        # If default section, populate default domainActions
        if uda == "default" or uda == "every":
            domainActions[uda] = actions
        else:
            # else, attach actions to each domain inside this override
            for domain in domains:
                # log(f"Populating exceptions for {domain} as: {actions}")
                domainActions[domain] = actions

    return domainActions, domainActionNames


def gendir(subname: str) -> None:
    """Create a directory hierarchy but don't complain if already exists."""
    adir = pathlib.Path(f"{configBase}/{subname}")
    adir.mkdir(parents=True, exist_ok=True)


def run(
    thing: str, shell: bool = False, output: bool = True, stdinSend: str | None = None
) -> subprocess.CompletedProcess:
    """Run any string as a command (maybe as shell for env/expansion too)."""
    log(f"Running: {thing}", "CMD", update=True)
    if stdinSend:
        # use 'repr' because we want to print the string with visible \n
        # instead of exploding the formatted string across ten lines
        log(f"WITH STDIN: {repr(stdinSend)}", "CMD", update=True)

    # If running with shell=True, command must be a single string
    # the shell itself will parse and do glob expansion, etc.
    # If running with shell=False, command must be a list of strings
    # where command[0] is the executable and command[1:] will be
    # the command's argv array.
    command = thing
    if not shell:
        command = thing.split()

    return subprocess.run(
        command,
        check=output,
        shell=shell,
        input=stdinSend.encode() if stdinSend else None,
        # note: we could use 'text=True' here to avoid .encode(),
        #       but text=True is only Python 3.7 and as of right now we
        #       work fine in Python 3.6. Seems adding one line invaliding
        #       our entire current Python version is a bit extreme.
        capture_output=True,
    )


def runAsync(thing, shell=False):
    log(f"Running: {thing}", "CMD-ASYNC", update=True)

    command = thing
    if not shell:
        command = thing.split()

    return subprocess.Popen(command, shell=shell)


def runAndWrite(thing, writeTo, perm=0o644, shell=False, stdinSend=None):
    ran = run(thing, shell=shell, stdinSend=stdinSend)

    # Python doesn't have a clean way of opening files with
    # pre-determined file permissions, so we get to do this instead...
    with os.fdopen(os.open(writeTo, os.O_WRONLY | os.O_CREAT, perm), "w") as w:
        w.write(ran.stdout.decode("utf-8"))


def customizeName(
    subdir: str, name: str, subtype: str, enctype: str, ext: str = "pem"
) -> str:
    """Generate a customized filename for keys, certs, or CSRs."""
    if enctype not in ("rsa", "ec"):
        raise ValueError(f"Invalid enctype: '{enctype}' - must be 'rsa' or 'ec'")

    return "{}/{}/{}-{}.{}{}.{}".format(
        configBase,
        getSubdir(subdir),
        name,
        subtype,
        RSA_TAG if enctype == "rsa" else CURVE_TAG,
        ".test" if IS_TEST else "",
        ext,
    )


def generateCSR(privateKey, domains, outfile):
    useSAN = len(domains) > 1

    def needsOCSP():
        def required(domain):
            if domain in domainActions:
                return domainActions[domain]["ocspStapleRequired"]

            return domainActions["default"]["ocspStapleRequired"]

        # do a quick loop to make sure all SAN domains have
        # the same 'ocspStapleRequired' value.
        # Since OCSP is a value of the entire certificate, we can't
        # mix and match domain configs and OCSP values.
        # Mixing can be dangerous because some servers don't staple,
        # but if the cert requires it, the service would be unusable
        # (i.e. dovecot and postfix don't staple, but nginx does)
        hasOCSP = required(domains[0])
        for domain in domains[1:]:
            if required(domain) != hasOCSP:
                print("Error: All SAN domains don't have the same OCSP config!")
                print(f"Verify all domains have same OCSP settings: {domains}")
                sys.exit(1)

        return hasOCSP

    subjectAltNames = ""
    cmdSAN = ""
    if useSAN:
        # Assemble list of all domains (including the primary CN) for SANing
        altNames = [f"DNS:{domain}" for domain in domains]
        subjectAltNames = ",".join(altNames)
        cmdSAN = "-reqexts SAN"

    # Use first domain as the primary common name
    domain = domains[0]

    ocspRequired = ""
    if needsOCSP():
        ocspRequired = "1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05"
        # openssl >= 1.1 supports the cleaner syntax below instead of OIDs,
        # but we can't guarantee most users have a compatible version yet:
        # ocspRequired = "tlsfeature = status_request"

    # Mock an in-line config real quick...
    # This is a bit weird because openssl doesn't support alt names
    # on the command line — it only supports them by reading a file
    # or by reading from stdin, so we mock a config file on stdin
    # for openssl to parse.
    #
    # If you're curious about the contents of the CSR itself, re-create the
    # generated command line with a given stdin and append -text to get
    # a human text representation of the CSR.
    runAndWrite(
        f"openssl req -new -sha256 -key {privateKey} -subj /CN={domain} "
        f"{cmdSAN} -config -",
        outfile,
        stdinSend=f"""[req]
distinguished_name=req_dn

[req_dn]

[v3_req]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
{ocspRequired}

[SAN]
subjectAltName={subjectAltNames}""",
    )


def generateCSRSingleDomain(privateKey, domain, outfile):
    assert isinstance(domain, str)
    generateCSR(privateKey, [domain], outfile)


def generateCSRWithSAN(privateKey, domains, outfile):
    assert isinstance(domains, list)
    generateCSR(privateKey, domains, outfile)


# unused, but may be useful in the future
def certFromNetwork(hostname):
    """Get cert expiration against a live server"""
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )

    conn.settimeout(3)

    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    conn.close()

    assert isinstance(ssl_info, dict)
    return ssl_info


def certFromFile(certPath: str) -> bool | dict[str, str]:
    """Get cert expiration from local file."""
    # If cert doesn't exist, it must be requested...
    certExists = os.path.isfile(certPath)
    if not certExists:
        return True

    # Parse certificate to extract expiration date
    # We use openssl to avoid relying on private Python APIs
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", certPath, "-noout", "-enddate"],
            capture_output=True,
            text=True,
            check=True,
        )
        # Output format: "notAfter=Mar 15 12:00:00 2024 GMT"
        enddate_line = result.stdout.strip()
        if enddate_line.startswith("notAfter="):
            date_str = enddate_line[9:]  # Remove "notAfter=" prefix
            return {"notAfter": date_str}
    except (subprocess.CalledProcessError, OSError) as e:
        log(f"Warning: Could not parse certificate {certPath}: {e}", "WARN")
        # If we can't parse, assume renewal is needed
        return True

    return True


def certNeedsRenewal(
    certDetails: bool | dict[str, str], utcnow: datetime.datetime
) -> bool:
    """Check if a certificate needs renewal based on expiration date."""
    # The first check guards against True from 'certFromFile()'.
    # (if cert doesn't exist, we obviously need to request one)
    if not isinstance(certDetails, dict):
        return True

    def timeRemaining(expires):
        return expires - utcnow

    def needsRenewNow(expires):
        remaining = timeRemaining(expires)

        if remaining < timedelta(days=0):
            # cert has already expired!
            return True

        return remaining < REAUTHORIZE_DAYS_IN_ADVANCE

    # Future - Past (now), ideally
    ssl_date_fmt = r"%b %d %H:%M:%S %Y %Z"

    expirationAsDate = datetime.datetime.strptime(certDetails["notAfter"], ssl_date_fmt)

    return needsRenewNow(expirationAsDate)


class CertificateRequestError(Exception):
    """Raised when certificate request fails after all retries."""

    pass


def requestCert(
    csr: str, outCert: str, isTest: bool = False, max_retries: int = 3
) -> bool:
    directory = STAGING if isTest else PRODUCTION

    # This is where we can plug in different cert request methods.
    # Right now we just pulled in acme_tiny which is a simple
    # http-01 wrapper around openssl subprocesses.
    # We can add dns-01 fairly easily if we add a way to ingest
    # DNS API credentials then integrate with both DNS APIs themselves
    # (can easily adapt from other LE requesting systems) then
    # send acme dns-01 requests to LE too.
    last_error = None
    for attempt in range(max_retries):
        try:
            signedCert = acme_tiny.get_crt(
                ACCOUNT_KEY, csr, CHALLENGE_DIR, directory_url=directory
            )
            # Success - write the certificate
            with open(outCert, "w") as writeMe:
                writeMe.write(signedCert)
            return True
        except Exception as e:
            last_error = e
            wait_time = 2**attempt  # Exponential backoff: 1, 2, 4 seconds
            if attempt < max_retries - 1:
                log(
                    f"Certificate request failed (attempt {attempt + 1}/{max_retries}): {e}",
                    "RETRY",
                )
                log(f"Retrying in {wait_time} seconds...", "RETRY")
                time.sleep(wait_time)
            else:
                log(
                    f"Certificate request failed after {max_retries} attempts: {e}",
                    "ERROR",
                    update=True,
                )

    # All retries exhausted
    log(f"FAILED FOR CSR: {csr}", "ERROR", update=True)
    log(f"Last error: {last_error}", "ERROR", update=True)
    return False


def prepareDomainForUpdate(domain):
    if domain in domainActions:
        actions = domainActions[domain]
    else:
        actions = domainActions["default"]

    allActions = domainActions.get("every", [])

    def prepare(acts):
        return [runAsync(X.replace("DOMAIN", domain)) for X in acts["prepare"]]

    prepared = []
    if "prepare" in actions:
        prepared.extend(prepare(actions))

    if "prepare" in allActions:
        prepared.extend(prepare(allActions))

    return prepared


def prepareDomainsForUpdate(domains):
    prepared = []
    for domain in domains:
        prepare = prepareDomainForUpdate(domain)
        if prepare:
            prepared.extend(prepare)

    return prepared


def unprepareDomainForUpdate(prepared):
    if prepared:
        for prepare in prepared:
            prepare.kill()

        # Why does printing stdout from Popen cause our
        # terminal session to go all weird?
        # Reset terminal semantics...
        try:
            run("stty sane")
        except (subprocess.CalledProcessError, OSError):
            # This may not work if run detached from a shell
            # (like via cron). Ignore stty failures.
            pass


def generateKeysAndCertsAndRequestSignedCerts(configuredDomain, domainActions, keyType):
    # Now do the cert update (or cert generation, along with key generation) for
    # both RSA and EC keys:
    updatedCerts = {}

    # Use timestamp for detecting expired certs or certs needing renewal soon
    # Note: Using timezone-aware UTC time (datetime.utcnow() is deprecated in Python 3.12+)
    utcnow = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)

    def updateDomainForKeyType(domain, keyType):
        # If this is a SAN request, combine all domains for filenames
        if isinstance(domain, list):
            # Do our best to preserve the order of SAN domains even
            # if they change.
            # Otherwise, if the order gets rearranged, we would generate
            # entirely new keys and certs even though they cover the
            # same set of domains.
            # Basically: convert SANs into a set, sort it, use that as
            # filename appended to the CN name for persisting set uniqueness.
            deduplicatedSANs = list(set(domain[1:]))
            deduplicatedSANs.sort(key=sortByDomain)
            deduplicatedSANs.insert(0, domain[0])
            domains = deduplicatedSANs
            domain = "_".join(domains)  # "_" <-- eyelashes bot supreme
        else:
            domains = []

        if "." not in domain:
            raise ValueError(
                f"Invalid domain name: '{domain}' - must contain at least one period"
            )
        privateKey = customizeName("key", domain, "key", keyType)
        cert = customizeName("cert", domain, "cert-combined", keyType)
        csr = customizeName("csr", domain, "csr", keyType, "csr")
        isEC = keyType == "ec"

        def generateKey():
            """Either: use key if exists or create new if requested"""
            if ALWAYS_NEW_KEYS or not os.path.isfile(privateKey):
                if isEC:
                    log(f"Generating EC {CURVE} key...", keyType)
                    runAndWrite(
                        f"openssl ecparam -genkey -name {CURVE}",
                        privateKey,
                        0o600,
                    )
                else:
                    log(f"Generating RSA {KEYBITS_RSA} key...", keyType)
                    runAndWrite(f"openssl genrsa {KEYBITS_RSA}", privateKey, 0o600)

            # also link the combined key into symlinks for each domain
            # the key represents for easier configuration management...
            for d in domains:
                singleDomainKey = customizeName("key", d, "key", keyType)

                # Atomically replace symlink to avoid race conditions
                keyNameOnly = os.path.basename(privateKey)
                log(
                    f"Linking {keyNameOnly} to {singleDomainKey}",
                    keyType,
                    update=True,
                )
                # Create symlink atomically using a temp file
                temp_link = tempfile.mktemp(dir=os.path.dirname(singleDomainKey))
                try:
                    os.symlink(keyNameOnly, temp_link)
                    os.replace(temp_link, singleDomainKey)  # Atomic replacement
                except OSError as e:
                    log(
                        f"Warning: Could not create symlink {singleDomainKey}: {e}",
                        "WARN",
                    )
                    with contextlib.suppress(OSError):
                        os.unlink(temp_link)

        def generateCSR_():
            """Either: use CSR if exists or create new if requested"""
            if ALWAYS_NEW_KEYS or not os.path.isfile(csr):
                log("Generating CSR...", keyType)
                if domains:
                    generateCSRWithSAN(privateKey, domains, csr)
                else:
                    generateCSRSingleDomain(privateKey, domain, csr)

        log(f"Checking certificate for {domain}...", keyType)

        needs_renewal = certNeedsRenewal(certFromFile(cert), utcnow)
        if FORCE_RENEW:
            log("Force renewal requested", keyType, update=True)
            needs_renewal = True

        if not needs_renewal:
            log("Not renewing!", keyType)
            return updatedCerts

        log(f"Renewing {domain}!", keyType, update=True)

        # In dry-run mode, just report what would happen
        if IS_DRY_RUN:
            log(f"[DRY-RUN] Would generate key: {privateKey}", keyType, update=True)
            log(f"[DRY-RUN] Would generate CSR: {csr}", keyType, update=True)
            log(f"[DRY-RUN] Would request certificate: {cert}", keyType, update=True)
            if domains:
                for d in domains:
                    log(
                        f"[DRY-RUN] Would create symlink for: {d}", keyType, update=True
                    )
            return updatedCerts

        generateKey()
        generateCSR_()

        if domains:
            prepared = prepareDomainsForUpdate(domains)
        else:
            prepared = prepareDomainForUpdate(domain)

        cert_success = requestCert(csr, cert, IS_TEST)

        # Clean up prepare processes regardless of cert success
        unprepareDomainForUpdate(prepared)

        if not cert_success:
            log(
                f"Skipping symlinks and updates for {domain} due to cert failure",
                keyType,
                update=True,
            )
            return updatedCerts

        # Also create individually named symlinks for each domain pointing
        # back to the primary bundle where it originates.
        # (makes adding/removing domains from SAN certs easier since each
        #  addition or removal completely changes the combined cert name, which
        #  then requires a full reconfig of everywhere they are used, but if we
        #  use symlinks to the bundles, we can add/remove certs without reconfig)
        for d in domains:
            singleDomainCert = customizeName("cert", d, "cert-combined", keyType)

            # Atomically replace symlink to avoid race conditions
            certNameOnly = os.path.basename(cert)
            log(f"Linking {certNameOnly} to {singleDomainCert}", keyType, update=True)
            # Create symlink atomically using a temp file
            temp_link = tempfile.mktemp(dir=os.path.dirname(singleDomainCert))
            try:
                os.symlink(certNameOnly, temp_link)
                os.replace(temp_link, singleDomainCert)  # Atomic replacement
            except OSError as e:
                log(
                    f"Warning: Could not create symlink {singleDomainCert}: {e}", "WARN"
                )
                with contextlib.suppress(OSError):
                    os.unlink(temp_link)

        # NOTE: if you have DUPLICATE certificates like a single
        #       domain certificate with the same in another cert's SANs,
        #       you will trigger actions for whichever domain is processed last.
        # e.g.
        #       mail.mysite.com
        #       mysite.com mail.mysite.com
        # The above would generate keys and certs for mail.mysite.com twice
        # (with the second key being on the SAN cert of mysite.com),
        # but your triggered actions would deliver mysite.com* keys and certs
        # to mail.mysite.com.
        if domains:
            # attach all domains to our update dict so we can report on why
            # update actions are happening per-domain

            # We use tuples here because tuples can be members of
            # sets, which lets us easily deduplicate repeated SAN-vs-CN
            # mappings later (lists can't be members of sets).
            for d in domains:
                updatedCerts[d] = tuple(domains)
        else:
            updatedCerts[domain] = tuple([domain])

    if keyType not in ("rsa", "ec"):
        raise ValueError(f"Invalid keyType: '{keyType}' - must be 'rsa' or 'ec'")

    updateDomainForKeyType(configuredDomain, keyType)
    log("")  # visually break with a newline between processed domains

    return updatedCerts


def sortByDomain(x):
    # Sort domain names by their top-down sort order, but ignore actual TLD.
    # e.g. mail.hello.there.com will get a sort tuple of:
    #      (there hello mail)
    parts = x.split(".")
    parts.reverse()
    return tuple(parts[1:])


# 'domainActions' is a map of domain names -> action description maps
# 'domainActionNames' is a map of action names -> action description maps
# action maps have element 'actionName' to map domainActions->domainNameActions
# for deduplicating final cert/key copying and update actions.
def updateKeysAndCertsAndServices(domainActions, domainActionNames, updatedCerts):
    # No updated certs? No need to update anything!
    if not updatedCerts:
        return

    # If certs were updated, run their associated update actions...
    def runUploadsAndUpdates(updatedDomains, actions):
        assert isinstance(actions, dict)

        firstDomains = []

        # We only copy keys/certs based on the CN name which is ud[0]
        for ud in updatedDomains:
            firstDomains.append(ud[0])

        # We want to run ALL replaces and ONE update at the end
        # in aggregated/combined/unified commands instead of running
        # N copies and N updates if we were processing all cert updates
        # individually.
        # Note: We use shlex.quote() for domain names to prevent shell injection,
        # but preserve the glob pattern (*) which needs to be expanded by the shell.
        replaceCert = " ".join(
            [
                shlex.quote(f"{configBase}/{getSubdir('cert')}/{ud}") + "*"
                for uds in updatedDomains
                for ud in uds
            ]
        )
        replaceKey = " ".join(
            [
                shlex.quote(f"{configBase}/{getSubdir('key')}/{ud}") + "*"
                for uds in updatedDomains
                for ud in uds
            ]
        )

        # Quote domain names to prevent shell injection
        replaceDomainsCN = " ".join(shlex.quote(d) for d in firstDomains)

        # Flatten the 'updatedDomains' list of lists so we can just join it all
        replaceDomainsALL = " ".join(
            shlex.quote(d) for d in set(itertools.chain(*updatedDomains))
        )

        # This loop basically flattens nested updatedDomains and annotates
        # which ones are SAN domains versus the root CN itself
        totalDomainsSANDescribed = []

        updatedDomains = list(updatedDomains)
        updatedDomains.sort(key=lambda x: sortByDomain(x[0]))

        # Generate informative output during the final action reporting phase
        for ud in updatedDomains:
            if len(ud) > 1:
                place = [ud[0]]
                place.extend([f"{u} (SAN)" for u in ud[1:]])
                place = ", ".join(place)
                place = f"({place})"
            else:
                place = ud[0]
            totalDomainsSANDescribed.append(place)

        updatedFormatted = ", ".join(totalDomainsSANDescribed)
        log(
            f"Executing [{actions['actionName']}] for {updatedFormatted}",
            "action",
            update=True,
        )

        # Do we have upload cert overrides?
        if "uploadCerts" in actions:
            for upload in actions["uploadCerts"]:
                cmd = upload.replace("CERTS", replaceCert)
                if IS_DRY_RUN:
                    log(f"[DRY-RUN] Would run: {cmd}", "action", update=True)
                else:
                    run(cmd, shell=True)

        # Do we have upload key overrides?
        if "uploadKeys" in actions:
            for upload in actions["uploadKeys"]:
                cmd = upload.replace("KEYS", replaceKey)
                if IS_DRY_RUN:
                    log(f"[DRY-RUN] Would run: {cmd}", "action", update=True)
                else:
                    run(cmd, shell=True)

        # Now with certs/keys replaced, run full service update:
        if "update" in actions:
            for action in actions["update"]:
                action = action.replace("DOMAINS_CN", replaceDomainsCN)
                action = action.replace("DOMAINS_ALL", replaceDomainsALL)
                if IS_DRY_RUN:
                    log(f"[DRY-RUN] Would run: {action}", "action", update=True)
                else:
                    run(action, shell=True)

    # 'combinedProcessingResult' is a map of:
    # actionNames -> set of domains for action
    # We use a set because with SAN domains, each SAN name has the full
    # domain set for the entire cert, but we only care about each
    # unique grouping.
    combinedProcessingResult = collections.defaultdict(set)

    # deduplicate actions across all domains so we only do one update
    # action across all updated certs this round.
    # print(updatedCerts)

    # Do we have 'every' actions for post-processing?
    hasGlobalEveryActionGroup = "every" in domainActionNames

    for updatedDomain, domainsOnCert in updatedCerts.items():
        # Step 1: Lookup domain in map of DOMAIN->Actions
        # Step 2: Get Action Name from map
        # Step 3: Append domain to list in map of ActionName->[Domains]
        # Step 4: Run each action on each aggregated domain list

        # For SAN domains, we need to trigger SAN overrides too, but provide
        # the key+cert starting with sniDomains[0] which probably isn't
        # the SAN name itself...
        # So, we need to map SAN actions back to actual cert names, which we
        # accomplish by just using the entire domain list per cert and using
        # the [0]th entry as the CN and the rest are alt names.

        # print(updatedDomain, domainActions, domainActionNames)
        # If this domain has an explicit override:
        if updatedDomain in domainActions:
            actions = domainActions[updatedDomain]
            actionName = actions["actionName"]
            combinedProcessingResult[actionName].add(domainsOnCert)
        else:  # else, no override, so use default action!
            combinedProcessingResult["default"].add(domainsOnCert)

        if hasGlobalEveryActionGroup:
            combinedProcessingResult["every"].add(domainsOnCert)

    # Now run deduplicated domain actions for uploads and service updates:
    if combinedProcessingResult:
        log("Copying keys and certs then reloading services...", "action", update=True)

    # print(combinedProcessingResult)
    for sectionName, sectionDomains in combinedProcessingResult.items():
        runUploadsAndUpdates(sectionDomains, domainActionNames[sectionName])
        log("", update=True)  # line break


def showCertificateStatus(configuredDomains, configBase):
    """Display status of all configured certificates using CertificateInfo dataclass."""
    print("\n" + "=" * 80)
    print("CERTIFICATE STATUS REPORT")
    if HAS_CRYPTOGRAPHY:
        print("(Using native cryptography library)")
    else:
        print(
            "(Using openssl subprocess - install 'cryptography' for better performance)"
        )
    print("=" * 80)
    print(f"{'Domain':<40} {'Expires':<20} {'Days Left':<12} {'Status'}")
    print("-" * 80)

    for configuredDomain in configuredDomains:
        # Handle SAN domains
        if isinstance(configuredDomain, list):
            domain_display = configuredDomain[0]
            if len(configuredDomain) > 1:
                domain_display += f" (+{len(configuredDomain) - 1} SANs)"
            domain_for_file = "_".join(configuredDomain)
        else:
            domain_display = configuredDomain
            domain_for_file = configuredDomain

        for keyType in ["rsa", "ec"]:
            tag = RSA_TAG if keyType == "rsa" else CURVE_TAG
            cert_path = f"{configBase}/{getSubdir('cert')}/{domain_for_file}-cert-combined.{tag}.pem"

            if IS_TEST:
                cert_path = cert_path.replace(".pem", ".test.pem")

            # Use the new unified get_certificate_info function
            cert_info = get_certificate_info(cert_path)

            if not cert_info.exists:
                status = "⚠️  MISSING"
                expires_str = "N/A"
                days_left = "N/A"
            elif cert_info.parse_error:
                status = f"⚠️  PARSE ERROR"
                expires_str = "Unknown"
                days_left = "?"
            elif cert_info.not_after:
                days = cert_info.days_until_expiry
                expires_str = cert_info.not_after.strftime("%Y-%m-%d")
                days_left = str(days) if days is not None else "?"

                if cert_info.is_expired:
                    status = "❌ EXPIRED"
                elif days is not None and days < 7:
                    status = "🔴 CRITICAL"
                elif days is not None and days < 30:
                    status = "🟡 RENEW SOON"
                else:
                    status = "✅ OK"
            else:
                status = "⚠️  UNKNOWN"
                expires_str = "Unknown"
                days_left = "?"

            domain_with_type = f"{domain_display} ({keyType.upper()})"
            print(f"{domain_with_type:<40} {expires_str:<20} {days_left:<12} {status}")

    print("=" * 80 + "\n")


def validateConfig(config: SectionProxy, configBase: str) -> bool:
    """Validate configuration values and provide helpful error messages."""
    errors = []
    warnings = []

    # Check required config values
    required_keys = ["challengeDropDir", "accountKey"]
    for key in required_keys:
        if key not in config or not config[key]:
            errors.append(f"Missing required config: '{key}'")

    # Validate challengeDropDir exists
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
                f"EC curve '{curve}' may not be widely supported. Recommended: {valid_curves}"
            )

    # Validate reauthorizeDays
    if "reauthorizeDays" in config:
        try:
            days = float(config["reauthorizeDays"])
            if days < 1:
                warnings.append(
                    f"reauthorizeDays={days} is very aggressive. Consider higher value."
                )
            elif days > 89:
                warnings.append(
                    f"reauthorizeDays={days} exceeds LE cert lifetime (90 days)."
                )
        except ValueError:
            errors.append(f"Invalid reauthorizeDays value: {config['reauthorizeDays']}")

    # Validate generateNewCertsAfterDays
    if "generateNewCertsAfterDays" in config:
        try:
            days = float(config["generateNewCertsAfterDays"])
            if days > 0 and days < 3.5:
                warnings.append(
                    f"generateNewCertsAfterDays={days} may hit rate limits. Minimum 3.5 days recommended."
                )
        except ValueError:
            errors.append(
                f"Invalid generateNewCertsAfterDays value: {config['generateNewCertsAfterDays']}"
            )

    # Check domains file exists
    domains_file = f"{configBase}/domains"
    if not os.path.isfile(domains_file):
        errors.append(f"Domains file not found: {domains_file}")

    # Check actions.conf exists
    actions_file = f"{configBase}/actions.conf"
    if not os.path.isfile(actions_file):
        errors.append(f"Actions config not found: {actions_file}")

    # Report warnings
    for warning in warnings:
        logger.warning(f"Config warning: {warning}")

    # Report errors and exit if any
    if errors:
        for error in errors:
            logger.error(f"Config error: {error}")
        logger.error("Configuration validation failed. Please fix the errors above.")
        sys.exit(1)

    return True


def loadDomains() -> list[str | list[str]]:
    """Load domain configuration from the domains file."""
    # Format of 'domains' file is one or more domains per line.
    # Each line becomes ONE certificate. If more than one domain
    # is present, an SAN certificate will be generated.
    # If the secondary domains on a line don't have a '.', they will
    # be prepended to the first domain on the line.
    # e.g. "mydomain.com www" will generate a certificate with
    # domains: mydomain.com and www.mydomain.com
    configuredDomains = []
    with open(f"{configBase}/domains") as doms:
        for line in doms:
            # Skip commented out or blank lines
            if line.startswith("#") or line.startswith("\n"):
                continue

            # If multiple names are on one line, they all become
            # one SAN certificate
            domainsOnLine = line.split()
            firstDomain = domainsOnLine[0]

            # All rate limits detailed at:
            # https://letsencrypt.org/docs/rate-limits/
            if len(domainsOnLine) > 100:
                print(
                    f"Error! The domain limit is 100 per certificate, but you "
                    "configured {len(domainsOnLine)} domains:\n{domainsOnLine}"
                )
                sys.exit(1)

            # If only one domain, present as a string, _not_ a list,
            # so the rest of our code knows not to populate SAN fields
            if len(domainsOnLine) == 1:
                domainsOnLine = firstDomain
            else:
                # else, format domains where required
                for i, domain in enumerate(domainsOnLine):
                    # you can use subdomains as shorthand by just giving their
                    # name and we take care of appending the first
                    # domain on the line to your subdomain
                    if "." not in domain:
                        domainsOnLine[i] = f"{domain}.{firstDomain}"

            configuredDomains.append(domainsOnLine)

    return configuredDomains


if __name__ == "__main__":
    # Rate limits described at:
    # Testing / Staging: https://letsencrypt.org/docs/staging-environment/
    #        Production: https://letsencrypt.org/docs/rate-limits/
    parser = argparse.ArgumentParser(description="Matt's Let's Encrypt Automation")

    # production-xor-staging/testing
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--prod",
        dest="isTest",
        action="store_false",
        help="Use LE production endpoint. "
        "Production rate limit is 5 duplicate certs per domain per week.",
    )

    group.add_argument(
        "--test",
        dest="isTest",
        action="store_true",
        help="""Use LE staging endpoint.
        Keys and certs will have 'test' in filenames.
        Don't waste your production rate limits during testing.
        Staging rate limit is 30,000 cert requests per week and
        30,000 duplicate cert issuance per week (per domain).""",
    )

    parser.add_argument(
        "--cron",
        dest="isCron",
        action="store_true",
        help="Only produce output when changes happen.",
    )

    parser.add_argument(
        "--parallel",
        dest="concurrency",
        default=1,
        type=int,
        help="Number of certificates to process in parallel",
    )

    parser.add_argument(
        "--config",
        dest="config",
        default="conf/lematt.conf",
        help="Path to your lematt.conf - "
        "config files 'domains' and 'actions.conf' "
        "must be in the same directory as lematt.conf",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose output (show all debug messages)",
    )

    parser.add_argument(
        "--dry-run",
        dest="dryRun",
        action="store_true",
        help="Show what would be done without making any changes",
    )

    parser.add_argument(
        "--status",
        dest="showStatus",
        action="store_true",
        help="Show certificate status and expiration dates, then exit",
    )

    parser.add_argument(
        "--domain",
        dest="singleDomain",
        default=None,
        help="Process only a specific domain (useful for testing)",
    )

    parser.add_argument(
        "--force-renew",
        dest="forceRenew",
        action="store_true",
        help="Force renewal regardless of expiration date",
    )

    args = parser.parse_args()

    IS_CRON = args.isCron
    IS_TEST = args.isTest
    IS_DRY_RUN = args.dryRun
    FORCE_RENEW = args.forceRenew

    # Set up logging based on arguments
    setup_logging(is_cron=IS_CRON, verbose=args.verbose)

    concurrency = args.concurrency

    configBase = os.path.dirname(os.path.realpath(args.config))

    conf = configparser.ConfigParser()
    conf["DEFAULT"] = {
        "reauthorizeDays": 15,
        "keyBitsRSA": "2048",
        "alwaysGenerateNewKeys": "no",
        "generateNewCertsAfterDays": 0,
        "curve": "prime256v1",
    }

    if not conf.read(args.config):
        logger.error(f"Requested config path not found: {args.config}")
        sys.exit(1)

    config = conf["config"]

    # Validate configuration before proceeding
    validateConfig(config, configBase)

    # We treat these as globals throughout the code, so they must
    # be initialized here outside of any functions:
    reauthDays = float(config["reauthorizeDays"])
    REAUTHORIZE_DAYS_IN_ADVANCE = timedelta(days=reauthDays)
    CHALLENGE_DIR = config["challengeDropDir"]
    ACCOUNT_KEY = config["accountKey"]
    KEYBITS_RSA = config["keyBitsRSA"]
    CURVE = config["curve"]
    ALWAYS_NEW_KEYS = config.getboolean("alwaysGenerateNewKeys")
    GENERATE_CERTS_DAYS = float(config["generateNewCertsAfterDays"])

    if GENERATE_CERTS_DAYS:  # <-- if !0
        # Instead of days-before-expire, use days-since-issue math.
        # Maximum rate should be 3.5 days-since-issue because:
        # Fun Fact: LE gives 90 day certs, but you get 5 duplicates per week.
        # Since we are issuing both RSA and EC certs, each issue eats
        # 2 rate limits out of 5 in every 7 day sliding window.
        # Remaining under rate limit of 5 per week means we can
        # run a complete issue cycle twice a week, giving us a
        # period for issuing of 7 days / 2 runs = 3.5 days/run
        # Therefore, our 90 day certs should be renewed with:
        # 90 days - 3.5 days = 86.5 days remaining,
        # which python lets us express as math by:
        # timedelta(days=90) - timedelta(days=3.5)
        # (actually it's the same as timedelta(days=86.5), but the
        #  mathy way looks cleaner and can be adjusted easier)
        REAUTHORIZE_DAYS_IN_ADVANCE = timedelta(days=90) - timedelta(
            days=GENERATE_CERTS_DAYS
        )

    # Use old configparser .get() syntax because defaults are based on values
    RSA_TAG = config.get("rsaTag", f"rsa{KEYBITS_RSA}")
    CURVE_TAG = config.get("curveTag", f"{CURVE}")

    # Endpoints taken from:
    # https://letsencrypt.org/docs/acme-protocol-updates/
    STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"

    # See for updates:
    # https://letsencrypt.org/certificates/#intermediate-certificates
    # Updates:
    #  2021-03-27: x3 expires
    #  2019-07-08: LE will provide certificates from their own root
    CROSSCHAIN_BASE = "https://letsencrypt.org/certs/"
    CROSSCHAIN_NAME_RSA = "lets-encrypt-x3-cross-signed.pem.txt"

    # TODO: turn this into a map of CHAIN = {'rsa': CHAIN_RSA, 'ec': CHAIN_EC}
    # LE plans a full ECDSA cert chain in Q3 2018
    CHAIN_RSA = f"{configBase}/{CROSSCHAIN_NAME_RSA}".replace(".txt", "")

    # LE actually returns a chained cert, so we don't have to manually apply
    # the cross chain ourself, but the cross chain is useful for configuring
    # stapling.

    testing = ""
    if IS_TEST:
        testing = "[TEST MODE — DO NOT USE TEST CERTS IN PRODUCTION] "

    configuredDomains = loadDomains()

    # Filter to single domain if requested
    if args.singleDomain:
        filtered = []
        for d in configuredDomains:
            if isinstance(d, list):
                if args.singleDomain in d or args.singleDomain == d[0]:
                    filtered.append(d)
            elif d == args.singleDomain:
                filtered.append(d)
        if not filtered:
            logger.error(f"Domain '{args.singleDomain}' not found in configuration")
            sys.exit(1)
        configuredDomains = filtered
        logger.info(f"Processing single domain: {args.singleDomain}")

    # Handle --status command
    if args.showStatus:
        showCertificateStatus(configuredDomains, configBase)
        sys.exit(0)

    if not IS_CRON:
        print(f"{testing}Welcome to LE Matt!")
        if IS_DRY_RUN:
            print("[DRY-RUN MODE - No changes will be made]")
        print("Using domain list:")
        for domain in configuredDomains:
            print(f"\t{domain}")

    if not os.path.isfile(ACCOUNT_KEY):
        logger.error(f"Account key doesn't exist: {ACCOUNT_KEY}")
        logger.error("Create your LE account key with: openssl genrsa 4096 > key.pem")
        sys.exit(1)

    # Fetch intermediate cert so user can copy it elsewhere if needed
    if not os.path.isfile(CHAIN_RSA):
        run(
            f"wget -O{CHAIN_RSA} {CROSSCHAIN_BASE}{CROSSCHAIN_NAME_RSA}",
            output=False,
        )

    # Create directories to store results (if they don't already exist)
    for name in ["key", "cert", "csr"]:
        gendir(getSubdir(name))

    # Parse actions.conf to load cert update actions (defaults and overrides)
    domainActions, domainActionNames = loadDomainActions()

    # Now process domains by:
    #   - requesting new certs from LE when cert doesn't exist or expires soon
    #     - generating rsa and ec keys if a key doesn't already exist
    #     - generating CSRs for each {key,domains} pair when CSRs don't exist
    #     - run per-domain prepare actions when configured
    #   - adding updated domains to results for post-update action triggering

    # We now do massively parallel certificate updating where each Certificate
    # for each domain gets processed with '--parallel' concurrency

    # LE has per-second rate limits and we don't recover from those errors
    # gracefully at the moment, so try to slow overzealous users down somewhat:
    # ==================
    # "The “new-reg”, “new-authz” and “new-cert” endpoints have an
    # Overall Requests limit of 20 per second.
    # The “/directory” endpoint and the “/acme” directory have an
    # Overall Requests limit of 40 requests per second."
    # ==================
    if concurrency > 10:
        concurrency = 10

    with multiprocessing.Pool(processes=concurrency) as pool:
        updatedCerts = pool.starmap(
            generateKeysAndCertsAndRequestSignedCerts,
            itertools.product(configuredDomains, [domainActions], ["rsa", "ec"]),
        )

    # sanity check from starmap
    assert isinstance(updatedCerts, list)
    assert len(updatedCerts) and isinstance(updatedCerts[0], dict)

    # pool.starmap() returns a list of dicts, but our final
    # result expects one dict with all results,
    # so merge the nested dicts into one big dict.
    updatedCertsSingleDict = {}
    for u in updatedCerts:
        updatedCertsSingleDict.update(u)

    # sanity check
    assert isinstance(updatedCertsSingleDict, dict)

    # Now deduplicate updated certs to action mappings then
    # copy keys, certs, and run configured update actions for updated certs
    updateKeysAndCertsAndServices(
        domainActions, domainActionNames, updatedCertsSingleDict
    )
