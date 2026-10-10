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
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from loguru import logger

from lematt.acme import AcmeError, issue_certificate
from lematt.config import (
    ActionConfig,
    CertificateInfo,
    CertificateResult,
    DomainActions,
    DomainConfig,
    KeyType,
    LemattConfig,
)
from lematt.crypto import (
    create_csr,
    generate_private_key,
    get_certificate_info,
    write_file_atomically,
)
from lematt.log import EVENT
from lematt.renewal import RenewalDecision, backoff_until, decide
from lematt.session import AcmeSession
from lematt.state import AttemptState, CertState, IssuedState, StateStore, utcnow

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class RenewalPlan:
    """A certificate, what lematt remembers about it, and the decision."""

    key_type: KeyType
    info: CertificateInfo
    state: CertState
    decision: RenewalDecision


@dataclass(frozen=True)
class RequestFailure:
    """Why a certificate request failed (and how long the CA asked to wait)."""

    message: str
    retry_after: float | None = None


# Upper bound on waiting before retrying a transient ACME failure
MAX_RETRY_WAIT = 60.0


@dataclass
class PrepareActionRunner:
    """Handles prepare actions that must run before certificate requests.

    Prepare actions start async processes (like temporary web servers)
    that must be kept alive during the ACME challenge and killed afterward.
    """

    config: LemattConfig
    _processes: list[subprocess.Popen] = field(default_factory=list, repr=False)
    _held_locks: list[tuple[str, Any]] = field(default_factory=list, repr=False)

    def lock_domains(self, domains: Iterable[str]) -> None:
        """Wait for other parallel workers preparing any of these names.

        Prevents two workers from running the same name's prepare actions
        (e.g. a challenge forwarder bound to one port) at the same time.
        Locks are taken in sorted order so workers sharing names can't
        deadlock. No-op outside parallel workers.
        """
        from lematt.executor import _get_domain_lock

        for domain in sorted(set(domains)):
            try:
                lock = _get_domain_lock(domain)
            except RuntimeError:
                return  # sequential run: nothing to coordinate with
            logger.debug(f"[PREPARE] Acquiring lock for domain: {domain}")
            lock.acquire()
            self._held_locks.append((domain, lock))

    def release_locks(self) -> None:
        while self._held_locks:
            domain, lock = self._held_locks.pop()
            try:
                lock.release()
                logger.debug(f"[PREPARE] Released lock for domain: {domain}")
            except Exception as e:
                logger.warning(f"[PREPARE] Error releasing lock for {domain}: {e}")

    def prepare_domain(
        self, domain: str, domain_actions: DomainActions
    ) -> list[subprocess.Popen]:
        """Start the prepare actions for a domain before its cert request.

        Args:
            domain: The domain to prepare (replaces DOMAIN in commands).
            domain_actions: DomainActions container with action configs.

        Returns:
            Running processes that must be killed after the cert request.
        """
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
        """Kill prepare processes and release domain locks.

        Args:
            processes: Specific processes to kill. If None, kills all tracked processes.
        """
        import os
        import signal

        procs = processes if processes is not None else self._processes

        if not procs:
            self.release_locks()
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
                    except OSError, ProcessLookupError:
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
            except OSError, ProcessLookupError:
                pass  # Process may have already exited

        if killed_count > 0:
            logger.info(f"[PREPARE] Cleaned up {killed_count} prepare process(es)")

        self.release_locks()

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
            logger.log(EVENT, full_message)
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

    @property
    def store(self) -> StateStore:
        """Persistent state for this mode (read-only during dry runs)."""
        return StateStore(
            pathlib.Path(self.config.state_dir), read_only=self.config.is_dry_run
        )

    def load_state(
        self, domain_config: DomainConfig, key_type: KeyType, info: CertificateInfo
    ) -> CertState:
        """Saved state for a certificate, reconciled with the file on disk.

        A certificate lematt didn't issue (or issued before it kept state)
        is adopted so status and monitoring can describe it.
        """
        cert_id = self.config.cert_id(domain_config, key_type)
        state = self.store.load_cert(cert_id) or CertState(cert_id)
        state.names = domain_config.all_domains
        state.key_type = str(key_type)
        if (
            info.serial_hex
            and info.not_before
            and info.not_after
            and (state.issued is None or state.issued.serial != info.serial_hex)
        ):
            state.issued = IssuedState(
                serial=info.serial_hex,
                ari_id=info.ari_id,
                not_before=info.not_before,
                not_after=info.not_after,
            )
            state.renewal_info = None
        return state

    def plan(
        self,
        domain_config: DomainConfig,
        key_type: KeyType,
        now: datetime.datetime | None = None,
    ) -> RenewalPlan:
        """Load a certificate and its state and decide whether to renew it."""
        now = now or utcnow()
        info = get_certificate_info(self.config.get_cert_path(domain_config, key_type))
        state = self.load_state(domain_config, key_type, info)
        decision = decide(
            info,
            state,
            now,
            self.config.renewal_settings,
            force=self.config.force_renew,
        )
        return RenewalPlan(key_type, info, state, decision)

    def new_session(self) -> AcmeSession:
        """An ACME session for this mode's directory and account."""
        return AcmeSession(
            directory_url=self.config.acme_directory_url,
            account_key_path=self.config.account_key,
            challenge_dir=self.config.challenge_dir,
            store=self.store,
        )

    def request_certificate(
        self,
        csr_path: str,
        output_path: str,
        max_retries: int = 3,
        domain_context: str = "",
        *,
        session: AcmeSession | None = None,
    ) -> RequestFailure | None:
        """Request a signed certificate from the ACME server.

        Only transient failures (network errors, 5xx) are retried, waiting
        for the server's Retry-After when given. Anything else (validation
        failures, rate limits, bad requests) fails immediately: retrying
        can't help and would spend Let's Encrypt's failed-validation limit.
        A saved account the CA no longer knows is replaced once.

        Args:
            csr_path: Path to the CSR file.
            output_path: Path to write the signed certificate chain.
            max_retries: Maximum attempts for transient failures.
            domain_context: Domain context for logging (e.g., "example.com[rsa]").
            session: ACME session to reuse (a new one by default).

        Returns:
            None on success, otherwise what went wrong.
        """
        session = session or self.new_session()
        csr_pem = pathlib.Path(csr_path).read_bytes()
        account_replaced = False
        for attempt in range(1, max_retries + 1):
            try:
                session.ensure_account()
                issued = issue_certificate(
                    directory_url=self.config.acme_directory_url,
                    account_key_path=self.config.account_key,
                    csr_pem=csr_pem,
                    challenge_dir=self.config.challenge_dir,
                    context=domain_context,
                    transport=session.transport,
                    solver=session.solver(),
                )
                write_file_atomically(output_path, issued.pem.encode())
                return None
            except AcmeError as e:
                if e.problem == "accountDoesNotExist" and not account_replaced:
                    session.forget_account()
                    account_replaced = True
                    continue
                if not e.retryable or attempt == max_retries:
                    self.log(f"Certificate request failed: {e}", "ERROR", update=True)
                    return RequestFailure(str(e), e.retry_after)
                wait = min(e.retry_after or 2**attempt, MAX_RETRY_WAIT)
                self.log(
                    f"Certificate request failed (attempt {attempt}/{max_retries}): "
                    f"{e}; retrying in {wait:.0f}s",
                    "RETRY",
                )
                time.sleep(wait)
            except (OSError, ValueError) as e:
                self.log(f"Certificate request failed: {e}", "ERROR", update=True)
                return RequestFailure(str(e))
        return RequestFailure("certificate request failed")

    def record_success(self, plan: RenewalPlan, cert_path: str) -> None:
        """Remember a newly issued certificate and reset failure backoff."""
        now = utcnow()
        state, previous = plan.state, plan.state.issued
        info = get_certificate_info(cert_path)
        if info.serial_hex and info.not_before and info.not_after:
            state.issued = IssuedState(
                serial=info.serial_hex,
                ari_id=info.ari_id,
                not_before=info.not_before,
                not_after=info.not_after,
                issued_at=now,
            )
        else:
            logger.warning(f"Issued certificate {cert_path} could not be read back")
            state.issued = None
        state.renewal_info = None
        state.attempts = AttemptState(last_attempt=now, last_success=now)
        self.store.save_cert(state)
        self.store.record(
            "issued",
            state.cert_id,
            serial=info.serial_hex,
            not_after=info.not_after,
            replaced=previous.serial if previous else None,
            reason=plan.decision.reason,
        )

    def record_failure(self, plan: RenewalPlan, failure: RequestFailure) -> None:
        """Remember a failed renewal and schedule the next allowed attempt."""
        now = utcnow()
        attempts = plan.state.attempts
        attempts.last_attempt = attempts.last_failure = now
        attempts.last_error = failure.message
        attempts.consecutive_failures += 1
        attempts.next_attempt_after = backoff_until(
            attempts.consecutive_failures, now, failure.retry_after
        )
        self.store.save_cert(plan.state)
        self.store.record(
            "renewal_failed",
            plan.state.cert_id,
            error=failure.message,
            consecutive_failures=attempts.consecutive_failures,
            next_attempt_after=attempts.next_attempt_after,
        )

    def generate_key(
        self,
        output_path: str,
        key_type: KeyType,
    ) -> bool:
        """Generate a private key (written atomically with 0600 permissions).

        Args:
            output_path: Path to write the key.
            key_type: Type of key to generate (RSA or EC).

        Returns:
            True if successful, False otherwise.
        """
        if key_type == KeyType.EC:
            self.log(f"Generating EC {self.config.ec_curve} key...", str(key_type))
        else:
            self.log(f"Generating RSA {self.config.rsa_key_bits} key...", str(key_type))
        try:
            pem = generate_private_key(
                key_type,
                rsa_bits=self.config.rsa_key_bits,
                ec_curve=self.config.ec_curve,
            )
            write_file_atomically(output_path, pem, mode=0o600)
            return True
        except (ValueError, OSError) as e:
            self.log(f"Key generation failed: {e}", "ERROR", update=True)
            return False

    def generate_csr(
        self,
        private_key_path: str,
        domains: list[str],
        output_path: str,
    ) -> bool:
        """Generate a Certificate Signing Request.

        Args:
            private_key_path: Path to the private key.
            domains: List of domains for the certificate.
            output_path: Path to write the CSR.

        Returns:
            True if successful, False otherwise.
        """
        self.log("Generating CSR...", "CSR")
        try:
            write_file_atomically(output_path, create_csr(private_key_path, domains))
            return True
        except (ValueError, OSError) as e:
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
        """Renew whichever of a domain's certificates are due.

        Prepare actions (e.g. remote challenge forwarders) start only if
        some key type is due, run once, and stay alive for every key type.

        Args:
            domain_config: The domain configuration.
            domain_actions: DomainActions container with action configs.
            key_types: Key types to process (defaults to [RSA, EC]).

        Returns:
            One CertificateResult per key type.
        """
        now = utcnow()
        plans = [self.plan(domain_config, kt, now) for kt in key_types or list(KeyType)]
        for plan in plans:
            for note in plan.decision.notes:
                self.log(note, "WARN")
            if not plan.decision.renew:
                self.store.save_cert(plan.state)  # adopted/refreshed state

        if not any(plan.decision.renew for plan in plans):
            return [
                self.process_domain(domain_config, p.key_type, plan=p) for p in plans
            ]

        session = self.new_session()
        prepare_runner = PrepareActionRunner(self.config)
        prepared_processes: list[subprocess.Popen] = []
        try:
            prepare_runner.lock_domains(domain_config.all_domains)
            for domain in domain_config.all_domains:
                procs = prepare_runner.prepare_domain(domain, domain_actions)
                prepared_processes.extend(procs)

            return [
                self.process_domain(domain_config, p.key_type, plan=p, session=session)
                for p in plans
            ]
        finally:
            prepare_runner.cleanup(prepared_processes)

    def process_domain(
        self,
        domain_config: DomainConfig,
        key_type: KeyType,
        *,
        plan: RenewalPlan | None = None,
        session: AcmeSession | None = None,
    ) -> CertificateResult:
        """Renew one certificate if its plan says so.

        Prepare actions are the caller's responsibility; see
        process_domain_all_keys().

        Args:
            domain_config: The domain configuration.
            key_type: Type of key (RSA or EC).
            plan: The renewal decision (computed now if not given).
            session: ACME session shared with the domain's other key types.

        Returns:
            CertificateResult with the operation outcome.
        """
        plan = plan or self.plan(domain_config, key_type)
        decision = plan.decision
        private_key = self.config.get_key_path(domain_config, key_type)
        cert = self.config.get_cert_path(domain_config, key_type)
        csr = self.config.get_csr_path(domain_config, key_type)

        def result(
            success: bool, renewed: bool, error: str | None = None
        ) -> CertificateResult:
            return CertificateResult(
                domain_config=domain_config,
                key_type=key_type,
                success=success,
                renewed=renewed,
                cert_path=cert if success else None,
                key_path=private_key if success else None,
                error_message=error,
            )

        if not decision.renew:
            self.log(f"Not renewing {domain_config}: {decision.reason}", str(key_type))
            return result(success=True, renewed=False)

        self.log(
            f"Renewing {domain_config}: {decision.reason}", str(key_type), update=True
        )

        if self.config.is_dry_run:
            for action, path in (
                ("generate key", private_key),
                ("generate CSR", csr),
                ("request certificate", cert),
            ):
                self.log(
                    f"[DRY-RUN] Would {action}: {path}", str(key_type), update=True
                )
            return result(success=True, renewed=True)

        needs_key = self.config.always_generate_new_keys or not os.path.isfile(
            private_key
        )
        if needs_key and not self.generate_key(private_key, key_type):
            return result(success=False, renewed=True, error="Key generation failed")

        for domain in domain_config.san_domains:
            self.create_atomic_symlink(
                os.path.basename(private_key),
                self.get_customized_name("key", domain, "key", key_type),
                key_type,
            )

        needs_csr = self.config.always_generate_new_keys or not os.path.isfile(csr)
        if needs_csr and not self.generate_csr(
            private_key, domain_config.all_domains, csr
        ):
            return result(success=False, renewed=True, error="CSR generation failed")

        failure = self.request_certificate(
            csr,
            cert,
            domain_context=f"{domain_config.primary_domain}[{key_type}]",
            session=session,
        )
        if failure is not None:
            self.record_failure(plan, failure)
            self.log(
                f"Next attempt after {plan.state.attempts.next_attempt_after} UTC",
                str(key_type),
                update=True,
            )
            return result(
                success=False, renewed=True, error="Certificate request failed"
            )

        for domain in domain_config.san_domains:
            self.create_atomic_symlink(
                os.path.basename(cert),
                self.get_customized_name("cert", domain, "cert-combined", key_type),
                key_type,
            )
        self.record_success(plan, cert)
        return result(success=True, renewed=True)

    def get_status_data(self, domains: Sequence[DomainConfig]) -> list[dict]:
        """Certificate status, including the renewal decision, as plain data.

        ``status`` is one of: ok, renew_soon (renewal is due or backing
        off), critical (less than a tenth of the lifetime left), expired,
        missing, parse_error, unknown.
        """
        now = utcnow()
        results: list[dict] = []
        for domain_config in domains:
            for key_type in KeyType:
                plan = self.plan(domain_config, key_type, now)
                info, decision = plan.info, plan.decision
                entry: dict = {
                    "domain": domain_config.primary_domain,
                    "san_domains": domain_config.san_domains,
                    "key_type": key_type.name.lower(),
                    "cert_path": info.path,
                    "exists": info.exists,
                    "expires": info.not_after.isoformat() if info.not_after else None,
                    "days_until_expiry": info.days_until_expiry,
                    "status": self._status(info, decision, now),
                    "renewal": self._renewal_status(plan),
                }
                if info.parse_error:
                    entry["parse_error"] = info.parse_error
                results.append(entry)
        return results

    @staticmethod
    def _status(
        info: CertificateInfo, decision: RenewalDecision, now: datetime.datetime
    ) -> str:
        if not info.exists:
            return "missing"
        if info.parse_error:
            return "parse_error"
        if info.not_after is None or info.lifetime is None:
            return "unknown"
        if info.not_after <= now:
            return "expired"
        if info.not_after - now < info.lifetime / 10:
            return "critical"
        if decision.renew or decision.blocked_until:
            return "renew_soon"
        return "ok"

    @staticmethod
    def _renewal_status(plan: RenewalPlan) -> dict:
        def iso(moment: datetime.datetime | None) -> str | None:
            return moment.isoformat() if moment else None

        decision, state = plan.decision, plan.state
        attempts = state.attempts
        ari = state.renewal_info
        current_ari = (
            ari is not None
            and state.issued is not None
            and (ari.serial == state.issued.serial)
        )
        return {
            "renew_now": decision.renew,
            "due_at": iso(decision.due_at),
            "basis": decision.basis,
            "reason": decision.reason,
            "blocked_until": iso(decision.blocked_until),
            "ari_window": {
                "start": iso(ari.window_start),
                "end": iso(ari.window_end),
                "explanation_url": ari.explanation_url,
            }
            if ari is not None and current_ari
            else None,
            "last_success": iso(attempts.last_success),
            "last_failure": iso(attempts.last_failure),
            "last_error": attempts.last_error,
            "consecutive_failures": attempts.consecutive_failures,
        }

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
            }

        # Human-readable output
        logger.info("=" * 100)
        logger.info("CERTIFICATE STATUS REPORT")
        logger.info("=" * 100)
        logger.info(
            f"{'Domain':<40} {'Expires':<12} {'Days Left':<10} {'Renews':<17} {'Status'}"
        )
        logger.info("-" * 100)

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
            renewal = entry["renewal"]
            if renewal["renew_now"]:
                renews = "now"
            elif renewal["blocked_until"]:
                renews = f"retry {renewal['blocked_until'][:10]}"
            elif renewal["due_at"]:
                renews = f"{renewal['due_at'][:10]} ({renewal['basis'][:5]})"
            else:
                renews = "N/A"
            logger.info(
                f"{domain_with_type:<40} {expires_str:<12} {days_left:<10} {renews:<17} {status}"
            )

        logger.info("=" * 100)
        return None
