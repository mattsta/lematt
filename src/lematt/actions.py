"""Action execution for lematt.

This module provides the ActionRunner class that handles pre/post
certificate actions like prepare commands, uploads, and service reloads.
"""

import collections
import configparser
import itertools
import json
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
    warn_obsolete_config_keys,
)
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
            logger.log(EVENT, full_message)
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

        # Validate sections
        for section in ["default", "every"]:
            if section in updaters and "domains" in updaters[section]:
                raise ValueError(f"'domains' entry not allowed in section [{section}]")

        # Process all sections
        for section in updaters.sections():
            section_config = updaters[section]
            warn_obsolete_config_keys(section_config, f"actions.conf [{section}]")

            # Build ActionConfig for this section
            action_config = ActionConfig(
                name=section,
                prepare_commands=extract_commands(section_config, "prepare"),
                upload_certs_commands=extract_commands(section_config, "uploadCerts"),
                upload_keys_commands=extract_commands(section_config, "uploadKeys"),
                update_commands=extract_commands(section_config, "update"),
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
