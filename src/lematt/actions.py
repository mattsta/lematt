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
from typing import TYPE_CHECKING

from loguru import logger

from lematt.config import ActionConfig, CertificateResult, LemattConfig

if TYPE_CHECKING:
    from collections.abc import Sequence


class ActionRunner:
    """Handles execution of pre/post certificate actions.

    This class encapsulates all action-related operations including
    loading action configuration, preparing domains, and running
    upload and update commands.
    """

    def __init__(self, config: LemattConfig) -> None:
        """Initialize the action runner.

        Args:
            config: The lematt configuration object.
        """
        self.config = config
        self.domain_actions: dict[str, dict] = {}
        self.domain_action_names: dict[str, dict] = {}
        self._prepare_processes: list[subprocess.Popen] = []

    def log(self, message: str, mode: str = "", update: bool = False) -> None:
        """Log a message with optional mode prefix."""
        if not message:
            if not self.config.is_cron:
                print("")
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

        def extract_and_populate(
            section_name: str,
            override: configparser.SectionProxy,
            actions: dict,
        ) -> None:
            if section_name in override:
                commands = json.loads(override[section_name])
                actions[section_name] = commands

        # Get default OCSP setting
        default_ocsp = False
        if "ocspStapleRequired" in updaters["default"]:
            default_ocsp = updaters["default"].getboolean("ocspStapleRequired")

        # Validate sections
        for section in ["default", "every"]:
            if section in updaters:
                section_config = updaters[section]
                if "domains" in section_config:
                    raise ValueError(f"'domains' entry not allowed in section [{section}]")
                if section == "every" and "ocspStapleRequired" in section_config:
                    raise ValueError(f"'ocspStapleRequired' not allowed in section [{section}]")

        # Set default OCSP for all sections
        updaters["DEFAULT"] = {"ocspStapleRequired": str(default_ocsp)}

        # Process all sections
        for section in updaters.sections():
            section_config = updaters[section]
            actions: dict = {"actionName": section}
            self.domain_action_names[section] = actions

            if section not in ("default", "every"):
                domains = section_config["domains"].split()
            else:
                domains = []

            # Extract action commands
            extract_and_populate("prepare", section_config, actions)
            extract_and_populate("update", section_config, actions)
            extract_and_populate("uploadCerts", section_config, actions)
            extract_and_populate("uploadKeys", section_config, actions)

            actions["ocspStapleRequired"] = section_config.getboolean("ocspStapleRequired")

            if section in ("default", "every"):
                self.domain_actions[section] = actions
            else:
                for domain in domains:
                    self.domain_actions[domain] = actions

    def get_actions_for_domain(self, domain: str) -> dict:
        """Get the action configuration for a domain.

        Args:
            domain: The domain name.

        Returns:
            Action configuration dictionary.
        """
        return self.domain_actions.get(domain, self.domain_actions.get("default", {}))

    def prepare_domain(self, domain: str) -> list[subprocess.Popen]:
        """Run prepare actions for a domain.

        Args:
            domain: The domain to prepare.

        Returns:
            List of running Popen processes.
        """
        actions = self.get_actions_for_domain(domain)
        every_actions = self.domain_actions.get("every", {})

        processes: list[subprocess.Popen] = []

        def run_prepare(acts: dict) -> list[subprocess.Popen]:
            if "prepare" not in acts:
                return []
            procs = []
            for cmd in acts["prepare"]:
                cmd = cmd.replace("DOMAIN", domain)
                self.log(f"Running: {cmd}", "CMD-ASYNC", update=True)
                procs.append(subprocess.Popen(cmd.split()))
            return procs

        processes.extend(run_prepare(actions))
        processes.extend(run_prepare(every_actions))

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
        procs = processes if processes is not None else self._prepare_processes

        if not procs:
            return

        for proc in procs:
            proc.kill()

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
                self.log(f"[{action_type}] stderr: {e.stderr[:500]}", "ERROR", update=True)
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
        has_every = "every" in self.domain_action_names

        for domain, domain_tuple in updated_certs.items():
            if domain in self.domain_actions:
                action_name = self.domain_actions[domain]["actionName"]
                combined_results[action_name].add(domain_tuple)
            else:
                combined_results["default"].add(domain_tuple)

            if has_every:
                combined_results["every"].add(domain_tuple)

        if combined_results:
            self.log("Copying keys and certs then reloading services...", "action", update=True)

        # Run actions for each group
        for section_name, domain_tuples in combined_results.items():
            self._run_uploads_and_updates(domain_tuples, self.domain_action_names[section_name])
            self.log("")

    def _run_uploads_and_updates(
        self,
        domain_tuples: set[tuple[str, ...]],
        actions: dict,
    ) -> None:
        """Run upload and update actions for a set of domains.

        Args:
            domain_tuples: Set of domain tuples (each tuple is domains on one cert).
            actions: Action configuration dictionary.
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
            f"Executing [{actions['actionName']}] for {', '.join(descriptions)}",
            "action",
            update=True,
        )

        # Run upload certs
        if "uploadCerts" in actions:
            for upload in actions["uploadCerts"]:
                cmd = upload.replace("CERTS", replace_cert)
                self.run_command(cmd, action_type="uploadCerts")

        # Run upload keys
        if "uploadKeys" in actions:
            for upload in actions["uploadKeys"]:
                cmd = upload.replace("KEYS", replace_key)
                self.run_command(cmd, action_type="uploadKeys")

        # Run update commands (service reloads, etc.)
        if "update" in actions:
            for action in actions["update"]:
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
        """Convert internal action dict to ActionConfig dataclass.

        Args:
            domain: Domain to get configuration for.

        Returns:
            ActionConfig instance.
        """
        actions = self.get_actions_for_domain(domain)
        return ActionConfig(
            name=actions.get("actionName", "default"),
            prepare_commands=actions.get("prepare", []),
            upload_certs_commands=actions.get("uploadCerts", []),
            upload_keys_commands=actions.get("uploadKeys", []),
            update_commands=actions.get("update", []),
            ocsp_staple_required=actions.get("ocspStapleRequired", False),
        )
