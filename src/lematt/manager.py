"""Certificate management for lematt.

This module provides the CertificateManager class that encapsulates
all certificate generation, renewal, and management operations.
"""

import contextlib
import datetime
import os
import pathlib
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

from loguru import logger

from lematt.config import (
    ActionConfig,
    CertificateResult,
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
    RenewalSummary,
)
from lematt.crypto import HAS_CRYPTOGRAPHY, get_certificate_info

if TYPE_CHECKING:
    from collections.abc import Sequence


class CertificateRequestError(Exception):
    """Raised when certificate request fails after all retries."""


@dataclass
class PrepareActionRunner:
    """Handles prepare actions that must run before certificate requests.

    Prepare actions start async processes (like temporary web servers)
    that must be kept alive during the ACME challenge and killed afterward.
    """

    config: LemattConfig
    _processes: list[subprocess.Popen] = field(default_factory=list, repr=False)
    _domain_lock: object = field(default=None, repr=False)  # multiprocessing.Lock
    _locked_domain: str | None = field(default=None, repr=False)

    def prepare_domain(
        self, domain: str, domain_actions: DomainActions
    ) -> list[subprocess.Popen]:
        """Run prepare actions for a domain before cert request.

        CRITICAL: This method acquires a domain-level lock to ensure only ONE
        prepare action runs per domain at a time. This prevents port conflicts
        when processing multiple key types (RSA + EC) in parallel.

        Args:
            domain: The domain to prepare.
            domain_actions: DomainActions container with action configs.

        Returns:
            List of running Popen processes that must be killed after cert request.
        """
        # Acquire domain lock to serialize prepare actions per domain
        # This prevents "port already in use" errors when running parallel renewals
        from lematt.executor import _get_domain_lock

        try:
            self._domain_lock = _get_domain_lock(domain)
            self._locked_domain = domain
            logger.debug(f"[PREPARE] Acquiring lock for domain: {domain}")
            self._domain_lock.acquire()  # type: ignore[union-attr]
            logger.info(f"[PREPARE] Lock acquired for domain: {domain}")
        except (RuntimeError, AttributeError):
            # Lock manager not initialized (sequential mode)
            self._domain_lock = None
            self._locked_domain = None
            logger.debug(
                f"[PREPARE] No lock needed for domain: {domain} (sequential mode)"
            )

        processes: list[subprocess.Popen] = []

        # Get actions for this domain (or default)
        actions = domain_actions.get_for_domain(domain)
        every_actions = domain_actions.every

        def run_prepare(action_config: ActionConfig | None) -> None:
            if action_config is None or not action_config.prepare_commands:
                return
            for cmd in action_config.prepare_commands:
                cmd = cmd.replace("DOMAIN", domain)
                if self.config.is_dry_run:
                    logger.info(f"[DRY-RUN] Would run prepare: {cmd}")
                else:
                    logger.info(f"[PREPARE] Starting: {cmd}")
                    try:
                        # Use start_new_session to create process group for proper cleanup
                        proc = subprocess.Popen(cmd, shell=True, start_new_session=True)
                        processes.append(proc)
                    except OSError as e:
                        logger.error(f"[PREPARE] Failed to start: {cmd} - {e}")

        run_prepare(actions)
        run_prepare(every_actions)

        self._processes.extend(processes)
        return processes

    def cleanup(self, processes: list[subprocess.Popen] | None = None) -> None:
        """Kill prepare processes after certificate request completes.

        Args:
            processes: Specific processes to kill. If None, kills all tracked processes.
        """
        import os
        import signal

        procs = processes if processes is not None else self._processes

        if not procs:
            return

        logger.debug(f"[PREPARE] Cleaning up {len(procs)} prepare process(es)")
        killed_count = 0
        for proc in procs:
            try:
                # Kill entire process group (handles shell=True and child processes)
                if proc.poll() is None:  # Process still running
                    try:
                        # Send SIGTERM to process group
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        # Wait for graceful termination
                        try:
                            proc.wait(timeout=2)
                            killed_count += 1
                            logger.debug(
                                f"[PREPARE] Terminated process group for PID {proc.pid}"
                            )
                        except subprocess.TimeoutExpired:
                            # Force kill the process group
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                            proc.wait()
                            killed_count += 1
                            logger.debug(
                                f"[PREPARE] Force killed process group for PID {proc.pid}"
                            )
                    except (OSError, ProcessLookupError):
                        # Process group doesn't exist, try killing just the process
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                            killed_count += 1
                            logger.debug(f"[PREPARE] Terminated process PID {proc.pid}")
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                            killed_count += 1
                            logger.debug(
                                f"[PREPARE] Force killed process PID {proc.pid}"
                            )
            except (OSError, ProcessLookupError):
                pass  # Process may have already exited

        if killed_count > 0:
            logger.info(f"[PREPARE] Cleaned up {killed_count} prepare process(es)")

        # Release domain lock if we acquired it
        if self._domain_lock is not None:
            try:
                self._domain_lock.release()  # type: ignore[union-attr,attr-defined]
                logger.info(
                    f"[PREPARE] Released lock for domain: {self._locked_domain}"
                )
                self._domain_lock = None
                self._locked_domain = None
            except Exception as e:
                logger.warning(f"[PREPARE] Error releasing domain lock: {e}")

        # Reset terminal if any prepare commands were run
        with contextlib.suppress(subprocess.CalledProcessError, OSError):
            subprocess.run(["stty", "sane"], check=False, capture_output=True)

        if processes is None:
            self._processes = []


@dataclass
class CertificateManager:
    """Manages certificate generation, renewal, and deployment.

    This class encapsulates all certificate operations and eliminates
    global state by accepting configuration through __init__.
    """

    config: LemattConfig
    _acme_module: object | None = field(default=None, repr=False)

    @property
    def acme(self) -> object:
        """Lazily load the ACME module."""
        if self._acme_module is None:
            from . import acme_tiny

            self._acme_module = acme_tiny
        return self._acme_module

    def log(self, message: str, mode: str = "", update: bool = False) -> None:
        """Log a message with optional mode prefix.

        Args:
            message: The message to log.
            mode: Optional category/mode prefix.
            update: If True, always log even in cron mode.
        """
        if not message:
            return

        prefix = "[TEST] " if self.config.is_test else "> "
        mode_str = f"[{mode}] " if mode else ""
        full_message = f"{prefix}{mode_str}{message}"

        if mode in ("ERROR", "FAIL"):
            logger.error(full_message)
        elif mode in ("WARN", "WARNING"):
            logger.warning(full_message)
        elif update:
            logger.info(full_message)
        else:
            logger.debug(full_message)

    def ensure_directories(self) -> None:
        """Create required directory hierarchy."""
        for name in ["key", "cert", "csr"]:
            subdir = self.config.get_subdir(name)
            adir = pathlib.Path(f"{self.config.config_base}/{subdir}")
            adir.mkdir(parents=True, exist_ok=True)

    def get_customized_name(
        self,
        subdir: str,
        name: str,
        subtype: str,
        key_type: KeyType,
        ext: str = "pem",
    ) -> str:
        """Generate a customized filename for keys, certs, or CSRs."""
        tag = self.config.rsa_tag if key_type == KeyType.RSA else self.config.curve_tag
        test_suffix = ".test" if self.config.is_test else ""
        return (
            f"{self.config.config_base}/"
            f"{self.config.get_subdir(subdir)}/"
            f"{name}-{subtype}.{tag}{test_suffix}.{ext}"
        )

    def cert_needs_renewal(
        self,
        cert_path: str,
        utcnow: datetime.datetime,
    ) -> bool:
        """Check if a certificate needs renewal based on expiration date."""
        if not os.path.isfile(cert_path):
            return True

        cert_info = get_certificate_info(cert_path)
        if not cert_info.exists or cert_info.parse_error:
            return True

        if cert_info.not_after is None:
            return True

        remaining = cert_info.not_after - utcnow
        if remaining < timedelta(days=0):
            return True  # Already expired

        return remaining < self.config.reauthorize_timedelta

    def request_certificate(
        self,
        csr_path: str,
        output_path: str,
        max_retries: int = 3,
        domain_context: str = "",
    ) -> bool:
        """Request a signed certificate from Let's Encrypt.

        Args:
            csr_path: Path to the CSR file.
            output_path: Path to write the signed certificate.
            max_retries: Maximum number of retry attempts.
            domain_context: Domain context for logging (e.g., "example.com[rsa]").

        Returns:
            True if successful, False otherwise.
        """
        directory = self.config.acme_directory_url
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                signed_cert = self.acme.get_crt(
                    self.config.account_key,
                    csr_path,
                    self.config.challenge_dir,
                    directory_url=directory,
                    domain_context=domain_context,
                )
                with open(output_path, "w") as f:
                    f.write(signed_cert)
                return True
            except Exception as e:
                last_error = e
                wait_time = 2**attempt
                if attempt < max_retries - 1:
                    self.log(
                        f"Certificate request failed (attempt {attempt + 1}/{max_retries}): {e}",
                        "RETRY",
                    )
                    self.log(f"Retrying in {wait_time} seconds...", "RETRY")
                    time.sleep(wait_time)
                else:
                    self.log(
                        f"Certificate request failed after {max_retries} attempts: {e}",
                        "ERROR",
                        update=True,
                    )

        self.log(f"FAILED FOR CSR: {csr_path}", "ERROR", update=True)
        self.log(f"Last error: {last_error}", "ERROR", update=True)
        return False

    def generate_key(
        self,
        output_path: str,
        key_type: KeyType,
    ) -> bool:
        """Generate a private key.

        Args:
            output_path: Path to write the key.
            key_type: Type of key to generate (RSA or EC).

        Returns:
            True if successful, False otherwise.
        """
        try:
            if key_type == KeyType.EC:
                self.log(f"Generating EC {self.config.ec_curve} key...", str(key_type))
                cmd = ["openssl", "ecparam", "-genkey", "-name", self.config.ec_curve]
            else:
                self.log(
                    f"Generating RSA {self.config.rsa_key_bits} key...", str(key_type)
                )
                cmd = ["openssl", "genrsa", str(self.config.rsa_key_bits)]

            result = subprocess.run(cmd, capture_output=True, check=True)

            # Write with secure permissions
            with os.fdopen(
                os.open(output_path, os.O_WRONLY | os.O_CREAT, 0o600), "wb"
            ) as f:
                f.write(result.stdout)

            return True
        except subprocess.CalledProcessError as e:
            self.log(f"Key generation failed: {e}", "ERROR", update=True)
            return False

    def generate_csr(
        self,
        private_key_path: str,
        domains: list[str],
        output_path: str,
        ocsp_must_staple: bool = False,
    ) -> bool:
        """Generate a Certificate Signing Request.

        Args:
            private_key_path: Path to the private key.
            domains: List of domains for the certificate.
            output_path: Path to write the CSR.
            ocsp_must_staple: Whether to include OCSP Must-Staple extension.

        Returns:
            True if successful, False otherwise.
        """
        self.log("Generating CSR...", "CSR")

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
            cmd = (
                f"openssl req -new -sha256 -key {private_key_path} "
                f"-subj /CN={primary_domain} {cmd_san} -config -"
            )
            result = subprocess.run(
                cmd.split(),
                input=stdin_config.encode(),
                capture_output=True,
                check=True,
            )
            with open(output_path, "wb") as f:
                f.write(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            self.log(f"CSR generation failed: {e}", "ERROR", update=True)
            return False

    def create_atomic_symlink(
        self,
        target: str,
        link_path: str,
        key_type: KeyType,
    ) -> bool:
        """Create a symlink atomically to avoid race conditions.

        Args:
            target: The target file (just the filename, not full path).
            link_path: The full path for the symlink.
            key_type: Key type for logging.

        Returns:
            True if successful, False otherwise.
        """
        self.log(f"Linking {target} to {link_path}", str(key_type), update=True)
        temp_link = tempfile.mktemp(dir=os.path.dirname(link_path))
        try:
            os.symlink(target, temp_link)
            os.replace(temp_link, link_path)
            return True
        except OSError as e:
            self.log(f"Warning: Could not create symlink {link_path}: {e}", "WARN")
            with contextlib.suppress(OSError):
                os.unlink(temp_link)
            return False

    def process_domain_all_keys(
        self,
        domain_config: DomainConfig,
        domain_actions: DomainActions,
        key_types: list[KeyType] | None = None,
    ) -> list[CertificateResult]:
        """Process a domain with ALL key types, running prepare ONCE.

        This prevents "port already in use" errors by running prepare scripts
        once and keeping them alive for the entire domain processing.

        Args:
            domain_config: The domain configuration.
            domain_actions: DomainActions container with action configs.
            key_types: List of key types to process (defaults to [RSA, EC]).

        Returns:
            List of CertificateResult for each key type processed.
        """
        if key_types is None:
            key_types = [KeyType.RSA, KeyType.EC]

        results: list[CertificateResult] = []

        # Run prepare actions ONCE before processing any key types
        prepare_runner = PrepareActionRunner(self.config)
        prepared_processes: list[subprocess.Popen] = []

        try:
            # Prepare all domains on this certificate
            for domain in domain_config.all_domains:
                procs = prepare_runner.prepare_domain(domain, domain_actions)
                prepared_processes.extend(procs)

            # Process ALL key types with prepare processes still running
            for key_type in key_types:
                result = self.process_domain(
                    domain_config,
                    key_type,
                    domain_actions,
                    skip_prepare=True,
                    prepare_processes=prepared_processes,
                )
                results.append(result)

        finally:
            # Cleanup prepare processes after ALL key types are done
            prepare_runner.cleanup(prepared_processes)

        return results

    def process_domain(
        self,
        domain_config: DomainConfig,
        key_type: KeyType,
        domain_actions: DomainActions,
        skip_prepare: bool = False,
        prepare_processes: list[subprocess.Popen] | None = None,
    ) -> CertificateResult:
        """Process a single domain for certificate renewal.

        Args:
            domain_config: The domain configuration.
            skip_prepare: If True, skip running prepare actions (caller manages them).
            prepare_processes: Existing prepare processes to reuse (if skip_prepare=True).
            key_type: Type of key (RSA or EC).
            domain_actions: DomainActions container with action configs.

        Returns:
            CertificateResult with the operation outcome.
        """
        utcnow = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)

        # Build file paths
        filename_base = domain_config.filename_base
        private_key = self.get_customized_name("key", filename_base, "key", key_type)
        cert = self.get_customized_name(
            "cert", filename_base, "cert-combined", key_type
        )
        csr = self.get_customized_name("csr", filename_base, "csr", key_type, "csr")

        self.log(f"Checking certificate for {domain_config}...", str(key_type))

        # Check if renewal is needed
        needs_renewal = self.cert_needs_renewal(cert, utcnow)
        if self.config.force_renew:
            self.log("Force renewal requested", str(key_type), update=True)
            needs_renewal = True

        if not needs_renewal:
            self.log("Not renewing!", str(key_type))
            return CertificateResult(
                domain_config=domain_config,
                key_type=key_type,
                success=True,
                renewed=False,
                cert_path=cert,
                key_path=private_key,
            )

        self.log(f"Renewing {domain_config}!", str(key_type), update=True)

        # Dry-run mode
        if self.config.is_dry_run:
            self.log(
                f"[DRY-RUN] Would generate key: {private_key}",
                str(key_type),
                update=True,
            )
            self.log(f"[DRY-RUN] Would generate CSR: {csr}", str(key_type), update=True)
            self.log(
                f"[DRY-RUN] Would request certificate: {cert}",
                str(key_type),
                update=True,
            )
            return CertificateResult(
                domain_config=domain_config,
                key_type=key_type,
                success=True,
                renewed=True,
                cert_path=cert,
                key_path=private_key,
            )

        # Generate key if needed (nested if is intentional - only generate then check result)
        if self.config.always_generate_new_keys or not os.path.isfile(private_key):  # noqa: SIM102
            if not self.generate_key(private_key, key_type):
                return CertificateResult(
                    domain_config=domain_config,
                    key_type=key_type,
                    success=False,
                    renewed=True,
                    error_message="Key generation failed",
                )

        # Create key symlinks for SAN domains
        for domain in domain_config.san_domains:
            single_domain_key = self.get_customized_name("key", domain, "key", key_type)
            self.create_atomic_symlink(
                os.path.basename(private_key),
                single_domain_key,
                key_type,
            )

        # Generate CSR if needed
        if self.config.always_generate_new_keys or not os.path.isfile(csr):
            # Check OCSP requirements
            ocsp_required = self._check_ocsp_requirement(domain_config, domain_actions)
            if not self.generate_csr(
                private_key,
                domain_config.all_domains,
                csr,
                ocsp_required,
            ):
                return CertificateResult(
                    domain_config=domain_config,
                    key_type=key_type,
                    success=False,
                    renewed=True,
                    error_message="CSR generation failed",
                )

        # Run prepare actions before certificate request (unless skipped)
        # (e.g., start temporary web server, open firewall ports)
        if skip_prepare:
            # Caller manages prepare processes - just use them
            cert_success = self.request_certificate(
                csr, cert, domain_context=f"{domain_config.primary_domain}[{key_type}]"
            )
        else:
            # This cert manages its own prepare/cleanup cycle
            prepare_runner = PrepareActionRunner(self.config)
            prepared_processes: list[subprocess.Popen] = []

            try:
                # Prepare all domains on this certificate
                for domain in domain_config.all_domains:
                    procs = prepare_runner.prepare_domain(domain, domain_actions)
                    prepared_processes.extend(procs)

                # Request certificate (prepare processes kept alive during ACME challenge)
                domain_context = f"{domain_config.primary_domain}[{key_type}]"
                cert_success = self.request_certificate(
                    csr, cert, domain_context=domain_context
                )
            finally:
                # Always cleanup prepare processes, regardless of cert success
                prepare_runner.cleanup(prepared_processes)

        if not cert_success:
            self.log(
                f"Skipping symlinks for {domain_config} due to cert failure",
                str(key_type),
                update=True,
            )
            return CertificateResult(
                domain_config=domain_config,
                key_type=key_type,
                success=False,
                renewed=True,
                error_message="Certificate request failed",
            )

        # Create cert symlinks for SAN domains
        for domain in domain_config.san_domains:
            single_domain_cert = self.get_customized_name(
                "cert", domain, "cert-combined", key_type
            )
            self.create_atomic_symlink(
                os.path.basename(cert),
                single_domain_cert,
                key_type,
            )

        self.log("")  # Visual break
        return CertificateResult(
            domain_config=domain_config,
            key_type=key_type,
            success=True,
            renewed=True,
            cert_path=cert,
            key_path=private_key,
        )

    def _check_ocsp_requirement(
        self,
        domain_config: DomainConfig,
        domain_actions: DomainActions,
    ) -> bool:
        """Check if OCSP stapling is required for a domain.

        Args:
            domain_config: The domain configuration.
            domain_actions: DomainActions container with action configs.

        Returns:
            True if OCSP stapling is required.
        """
        # Check domain-level OCSP setting first (from domains file)
        if domain_config.ocsp_staple_required:
            return True

        # Fall back to action-level OCSP setting
        first_ocsp = domain_actions.get_ocsp_required(domain_config.primary_domain)
        for domain in domain_config.san_domains:
            if domain_actions.get_ocsp_required(domain) != first_ocsp:
                raise ValueError(
                    f"All SAN domains must have same OCSP config: {domain_config.all_domains}"
                )
        return first_ocsp

    def get_status_data(self, domains: Sequence[DomainConfig]) -> list[dict]:
        """Get certificate status as structured data.

        Args:
            domains: List of domain configurations.

        Returns:
            List of status dictionaries for each certificate.
        """
        results: list[dict] = []

        for domain_config in domains:
            for key_type in [KeyType.RSA, KeyType.EC]:
                cert_path = self.config.get_cert_path(domain_config, key_type)
                cert_info = get_certificate_info(cert_path)

                entry: dict = {
                    "domain": domain_config.primary_domain,
                    "san_domains": domain_config.san_domains,
                    "key_type": key_type.name.lower(),
                    "cert_path": cert_path,
                    "exists": cert_info.exists,
                }

                if not cert_info.exists:
                    entry["status"] = "missing"
                    entry["expires"] = None
                    entry["days_until_expiry"] = None
                elif cert_info.parse_error:
                    entry["status"] = "parse_error"
                    entry["parse_error"] = cert_info.parse_error
                    entry["expires"] = None
                    entry["days_until_expiry"] = None
                elif cert_info.not_after:
                    days = cert_info.days_until_expiry
                    entry["expires"] = cert_info.not_after.isoformat()
                    entry["days_until_expiry"] = days

                    if cert_info.is_expired:
                        entry["status"] = "expired"
                    elif days is not None and days < 7:
                        entry["status"] = "critical"
                    elif days is not None and days < 30:
                        entry["status"] = "renew_soon"
                    else:
                        entry["status"] = "ok"
                else:
                    entry["status"] = "unknown"
                    entry["expires"] = None
                    entry["days_until_expiry"] = None

                results.append(entry)

        return results

    def show_status(
        self, domains: Sequence[DomainConfig], json_output: bool = False
    ) -> dict | None:
        """Display status of all configured certificates.

        Args:
            domains: List of domain configurations.
            json_output: If True, return data dict instead of printing.

        Returns:
            Status data dict if json_output is True, otherwise None.
        """
        status_data = self.get_status_data(domains)

        if json_output:
            return {
                "certificates": status_data,
                "summary": {
                    "total": len(status_data),
                    "ok": sum(1 for s in status_data if s["status"] == "ok"),
                    "renew_soon": sum(
                        1 for s in status_data if s["status"] == "renew_soon"
                    ),
                    "critical": sum(
                        1 for s in status_data if s["status"] == "critical"
                    ),
                    "expired": sum(1 for s in status_data if s["status"] == "expired"),
                    "missing": sum(1 for s in status_data if s["status"] == "missing"),
                },
                "using_native_crypto": HAS_CRYPTOGRAPHY,
            }

        # Human-readable output
        logger.info("=" * 80)
        logger.info("CERTIFICATE STATUS REPORT")
        if HAS_CRYPTOGRAPHY:
            logger.info("(Using native cryptography library)")
        else:
            logger.info(
                "(Using openssl subprocess - install 'cryptography' for better performance)"
            )
        logger.info("=" * 80)
        logger.info(f"{'Domain':<40} {'Expires':<20} {'Days Left':<12} {'Status'}")
        logger.info("-" * 80)

        status_icons = {
            "ok": "✅ OK",
            "renew_soon": "🟡 RENEW SOON",
            "critical": "🔴 CRITICAL",
            "expired": "❌ EXPIRED",
            "missing": "⚠️  MISSING",
            "parse_error": "⚠️  PARSE ERROR",
            "unknown": "⚠️  UNKNOWN",
        }

        for entry in status_data:
            domain_with_type = f"{entry['domain']} ({entry['key_type'].upper()})"
            expires_str = entry["expires"][:10] if entry["expires"] else "N/A"
            days_left = (
                str(entry["days_until_expiry"])
                if entry["days_until_expiry"] is not None
                else "N/A"
            )
            status = status_icons.get(entry["status"], "❓ UNKNOWN")
            logger.info(
                f"{domain_with_type:<40} {expires_str:<20} {days_left:<12} {status}"
            )

        logger.info("=" * 80)
        return None

    def process_all_domains(
        self,
        domains: Sequence[DomainConfig],
        domain_actions: DomainActions,
    ) -> RenewalSummary:
        """Process all domains for certificate renewal.

        Args:
            domains: List of domain configurations.
            domain_actions: Dictionary of domain-specific actions.

        Returns:
            RenewalSummary with all operation outcomes.
        """
        summary = RenewalSummary()

        for domain_config in domains:
            for key_type in [KeyType.RSA, KeyType.EC]:
                result = self.process_domain(domain_config, key_type, domain_actions)
                summary.add_result(result)

        return summary
