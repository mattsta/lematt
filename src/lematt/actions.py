"""Action execution for lematt.

This module provides the ActionRunner class that handles pre/post
certificate actions like prepare commands, uploads, and service reloads.
"""

import collections
import itertools
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from loguru import logger

from lematt.config import (
    ActionConfig,
    CertificateResult,
    DomainActions,
    LemattConfig,
)
from lematt.config_loader import load_actions_ini
from lematt.log import EVENT

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class ActionRunner:
    """Handles execution of pre/post certificate actions.

    This class encapsulates all action-related operations including
    loading action configuration and running upload and update commands.
    """

    config: LemattConfig
    actions: DomainActions = field(default_factory=DomainActions)

    def log(self, message: str, mode: str = "", update: bool = False) -> None:
        """Log a message with optional mode prefix."""
        if not message:
            return

        prefix = "> "  # the log format adds [TEST] in test mode
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

    def load_actions(self) -> None:
        """Load actions from actions.conf in the configuration directory."""
        self.actions = load_actions_ini(self.config.config_base / "actions.conf")

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
        # Certificates in a stable order, so expansions don't vary between runs
        sorted_tuples = sorted(
            domain_tuples, key=lambda names: (self._sort_by_domain(names[0]), names)
        )
        names = list(dict.fromkeys(itertools.chain.from_iterable(sorted_tuples)))

        # CERTS/KEYS: one quoted glob per name (matching every key type and
        # the SAN symlinks), with the trailing * left unquoted
        cert_dir, key_dir = self.config.mode_dir("cert"), self.config.mode_dir("key")
        replace_cert = " ".join(
            shlex.quote(str(cert_dir / name)) + "*" for name in names
        )
        replace_key = " ".join(shlex.quote(str(key_dir / name)) + "*" for name in names)

        # DOMAINS_CN: each certificate's primary name; DOMAINS_ALL: every name
        replace_domains_cn = " ".join(shlex.quote(d[0]) for d in sorted_tuples)
        replace_domains_all = " ".join(shlex.quote(d) for d in names)

        # Build descriptive output
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
