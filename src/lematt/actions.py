"""Action execution for lematt.

This module provides the ActionRunner class that handles pre/post
certificate actions like prepare commands, uploads, and service reloads.
"""

import collections
import configparser
import contextlib
import itertools
import json
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from loguru import logger

from lematt.config import ActionConfig, CertificateResult, DomainActions, LemattConfig

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class ActionRunner:
    """Handles execution of pre/post certificate actions.

    This class encapsulates all action-related operations including
    loading action configuration, preparing domains, and running
    upload and update commands.
    """

    config: LemattConfig
    actions: DomainActions = field(default_factory=DomainActions)
    _prepare_processes: list[subprocess.Popen] = field(default_factory=list, repr=False)

    # Legacy properties for backward compatibility during transition
    @property
    def domain_actions(self) -> DomainActions:
        """Get domain actions (for backward compatibility)."""
        return self.actions

    def log(self, message: str, mode: str = "", update: bool = False) -> None:
        """Log a message with optional mode prefix."""
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

    def load_actions(self) -> None:
        """Load actions from actions.conf file."""
        updaters = configparser.ConfigParser()
        updaters.read(f"{self.config.config_base}/actions.conf")

        def extract_commands(
            section_config: configparser.SectionProxy, key: str
        ) -> list[str]:
            """Extract command list from section config."""
            if key in section_config:
                return json.loads(section_config[key])
            return []

        # Get default OCSP setting
        default_ocsp = False
        if "default" in updaters and "ocspStapleRequired" in updaters["default"]:
            default_ocsp = updaters["default"].getboolean("ocspStapleRequired")

        # Validate sections
        for section in ["default", "every"]:
            if section in updaters:
                section_config = updaters[section]
                if "domains" in section_config:
                    raise ValueError(
                        f"'domains' entry not allowed in section [{section}]"
                    )
                if section == "every" and "ocspStapleRequired" in section_config:
                    raise ValueError(
                        f"'ocspStapleRequired' not allowed in section [{section}]"
                    )

        # Set default OCSP for all sections
        updaters["DEFAULT"] = {"ocspStapleRequired": str(default_ocsp)}

        # Process all sections
        for section in updaters.sections():
            section_config = updaters[section]

            # Build ActionConfig for this section
            action_config = ActionConfig(
                name=section,
                prepare_commands=extract_commands(section_config, "prepare"),
                upload_certs_commands=extract_commands(section_config, "uploadCerts"),
                upload_keys_commands=extract_commands(section_config, "uploadKeys"),
                update_commands=extract_commands(section_config, "update"),
                ocsp_staple_required=section_config.getboolean("ocspStapleRequired"),
            )

            if section == "default":
                self.actions.default = action_config
            elif section == "every":
                self.actions.every = action_config
            else:
                # Get domains for this action section
                domains = section_config["domains"].split()
                action_config.domains = domains
                for domain in domains:
                    self.actions.domain_configs[domain] = action_config

    def get_actions_for_domain(self, domain: str) -> ActionConfig:
        """Get the action configuration for a domain.

        Args:
            domain: The domain name.

        Returns:
            ActionConfig for the domain.
        """
        return self.actions.get_for_domain(domain)

    def prepare_domain(self, domain: str) -> list[subprocess.Popen]:
        """Run prepare actions for a domain.

        Args:
            domain: The domain to prepare.

        Returns:
            List of running Popen processes.
        """
        action_config = self.get_actions_for_domain(domain)
        every_config = self.actions.every

        processes: list[subprocess.Popen] = []

        def run_prepare(config: ActionConfig | None) -> list[subprocess.Popen]:
            if config is None or not config.prepare_commands:
                return []
            procs = []
            for cmd in config.prepare_commands:
                cmd = cmd.replace("DOMAIN", domain)
                self.log(f"Running: {cmd}", "CMD-ASYNC", update=True)
                procs.append(subprocess.Popen(cmd.split()))
            return procs

        processes.extend(run_prepare(action_config))
        processes.extend(run_prepare(every_config))

        return processes

    def prepare_domains(self, domains: Sequence[str]) -> list[subprocess.Popen]:
        """Run prepare actions for multiple domains.

        Args:
            domains: List of domain names.

        Returns:
            List of running Popen processes.
        """
        processes: list[subprocess.Popen] = []
        for domain in domains:
            processes.extend(self.prepare_domain(domain))
        self._prepare_processes = processes
        return processes

    def cleanup_prepare(self, processes: list[subprocess.Popen] | None = None) -> None:
        """Clean up prepare processes.

        Args:
            processes: List of processes to kill. Uses stored processes if None.
        """
        import os
        import signal

        procs = processes if processes is not None else self._prepare_processes

        if not procs:
            return

        logger.debug(f"[PREPARE] Cleaning up {len(procs)} prepare process(es)")
        killed_count = 0
        for proc in procs:
            try:
                # Kill entire process group to ensure child processes are also killed
                if proc.poll() is None:  # Process still running
                    try:
                        # Try killing process group first (for shell=True spawned processes)
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        try:
                            proc.wait(timeout=2)
                            killed_count += 1
                            logger.debug(
                                f"[PREPARE] Terminated process group for PID {proc.pid}"
                            )
                        except subprocess.TimeoutExpired:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                            proc.wait()
                            killed_count += 1
                            logger.debug(
                                f"[PREPARE] Force killed process group for PID {proc.pid}"
                            )
                    except (OSError, ProcessLookupError):
                        # No process group, kill just the process
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
                pass  # Process already exited

        if killed_count > 0:
            logger.info(f"[PREPARE] Cleaned up {killed_count} prepare process(es)")

        # Reset terminal if needed
        with contextlib.suppress(subprocess.CalledProcessError, OSError):
            subprocess.run(["stty", "sane"], check=False, capture_output=True)

        if processes is None:
            self._prepare_processes = []

    def run_command(
        self,
        command: str,
        shell: bool = True,
        action_type: str = "CMD",
    ) -> subprocess.CompletedProcess | None:
        """Run a command with logging and execution confirmation.

        Args:
            command: The command to run.
            shell: Whether to run in shell mode.
            action_type: Type of action for logging (uploadCerts, uploadKeys, update).

        Returns:
            CompletedProcess result or None on failure.
        """
        self.log(f"[{action_type}] Running: {command}", "action", update=True)

        if self.config.is_dry_run:
            self.log(f"[DRY-RUN] Would run: {command}", "action", update=True)
            return None

        try:
            result = subprocess.run(
                command,
                shell=shell,
                check=True,
                capture_output=True,
                text=True,
            )
            self.log(f"[{action_type}] SUCCESS: {command}", "action", update=True)
            return result
        except subprocess.CalledProcessError as e:
            self.log(
                f"[{action_type}] FAILED: {command} - Exit code {e.returncode}",
                "ERROR",
                update=True,
            )
            if e.stderr:
                self.log(
                    f"[{action_type}] stderr: {e.stderr[:500]}", "ERROR", update=True
                )
            return None
        except OSError as e:
            self.log(f"[{action_type}] OS ERROR: {command} - {e}", "ERROR", update=True)
            return None

    def process_updated_certs(
        self,
        results: Sequence[CertificateResult],
    ) -> None:
        """Process all successfully updated certificates.

        Runs upload and update actions for all domains that were renewed.

        Args:
            results: List of certificate results from renewal operations.
        """
        # Build mapping of domains to their action names
        updated_certs: dict[str, tuple[str, ...]] = {}

        for result in results:
            if not result.renewed or not result.success:
                continue

            domains = result.domain_config.all_domains
            domain_tuple = tuple(domains)

            for domain in domains:
                updated_certs[domain] = domain_tuple

        if not updated_certs:
            return

        # Group updates by action name for deduplication
        combined_results: dict[str, set[tuple[str, ...]]] = collections.defaultdict(set)
        has_every = self.actions.every is not None

        for domain, domain_tuple in updated_certs.items():
            action_config = self.actions.get_for_domain(domain)
            combined_results[action_config.name].add(domain_tuple)

            if has_every:
                combined_results["every"].add(domain_tuple)

        if combined_results:
            self.log(
                "Copying keys and certs then reloading services...",
                "action",
                update=True,
            )

        # Run actions for each group
        action_configs = self.actions.all_action_names()
        for section_name, domain_tuples in combined_results.items():
            if section_name in action_configs:
                self._run_uploads_and_updates(
                    domain_tuples, action_configs[section_name]
                )
            self.log("")

    def _run_uploads_and_updates(
        self,
        domain_tuples: set[tuple[str, ...]],
        action_config: ActionConfig,
    ) -> None:
        """Run upload and update actions for a set of domains.

        Args:
            domain_tuples: Set of domain tuples (each tuple is domains on one cert).
            action_config: ActionConfig with commands to run.
        """
        # Build replacement patterns
        # Use shlex.quote for domain names, but preserve glob pattern
        replace_cert = " ".join(
            shlex.quote(
                f"{self.config.config_base}/{self.config.get_subdir('cert')}/{domain}"
            )
            + "*"
            for domains in domain_tuples
            for domain in domains
        )
        replace_key = " ".join(
            shlex.quote(
                f"{self.config.config_base}/{self.config.get_subdir('key')}/{domain}"
            )
            + "*"
            for domains in domain_tuples
            for domain in domains
        )

        # Get first domain (CN) from each tuple
        first_domains = [domains[0] for domains in domain_tuples]
        replace_domains_cn = " ".join(shlex.quote(d) for d in first_domains)
        replace_domains_all = " ".join(
            shlex.quote(d) for d in set(itertools.chain(*domain_tuples))
        )

        # Build descriptive output
        sorted_tuples = sorted(domain_tuples, key=lambda x: self._sort_by_domain(x[0]))
        descriptions = []
        for domains in sorted_tuples:
            if len(domains) > 1:
                parts = [domains[0], *(f"{d} (SAN)" for d in domains[1:])]
                descriptions.append(f"({', '.join(parts)})")
            else:
                descriptions.append(domains[0])

        self.log(
            f"Executing [{action_config.name}] for {', '.join(descriptions)}",
            "action",
            update=True,
        )

        # Run upload certs
        for upload in action_config.upload_certs_commands:
            cmd = upload.replace("CERTS", replace_cert)
            self.run_command(cmd, action_type="uploadCerts")

        # Run upload keys
        for upload in action_config.upload_keys_commands:
            cmd = upload.replace("KEYS", replace_key)
            self.run_command(cmd, action_type="uploadKeys")

        # Run update commands (service reloads, etc.)
        for action in action_config.update_commands:
            action = action.replace("DOMAINS_CN", replace_domains_cn)
            action = action.replace("DOMAINS_ALL", replace_domains_all)
            self.run_command(action, action_type="update")

    @staticmethod
    def _sort_by_domain(domain: str) -> tuple[str, ...]:
        """Sort domain by reversed parts (ignoring TLD).

        Args:
            domain: Domain name to sort.

        Returns:
            Tuple of domain parts for sorting.
        """
        parts = domain.split(".")
        parts.reverse()
        return tuple(parts[1:])

    def to_action_config(self, domain: str) -> ActionConfig:
        """Get ActionConfig for a domain.

        Args:
            domain: Domain to get configuration for.

        Returns:
            ActionConfig instance.
        """
        return self.get_actions_for_domain(domain)
