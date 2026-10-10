"""Systemd service and timer units for scheduled renewals.

``--print-systemd-units`` prints the units (for configuration management to
install), and ``--install-systemd`` writes and enables them directly.

The service deliberately isn't sandboxed (no ProtectSystem/ProtectHome/
NoNewPrivileges): deployment actions run arbitrary commands, such as ssh/rsync
with keys in a home directory, uploads to any path, and `sudo` reloads, which
a sandbox would silently break. Add hardening with a drop-in if your actions
allow it.
"""

import contextlib
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class SystemdConfig:
    """Configuration for systemd unit generation."""

    service_name: str = "lematt-renew"
    description: str = "Lematt Certificate Renewal"

    # Let's Encrypt recommends checking (ARI) at least twice a day, at a
    # randomized time rather than on the hour
    calendar: str = "*-*-* 00,12:00:00"
    randomized_delay_sec: int = 3600
    persistent: bool = True  # Run a missed timer on boot

    user: str = "root"
    config_file: Path = Path("/etc/lematt/lematt.conf")
    use_test_mode: bool = False
    python: str = field(default_factory=lambda: sys.executable)
    extra_args: list[str] = field(default_factory=list)

    # A hung prepare/deploy command must not block every later run
    timeout_start_sec: str = "3h"

    @property
    def command(self) -> str:
        mode = "--test" if self.use_test_mode else "--prod"
        args = [
            self.python,
            "-m",
            "lematt",
            "--config",
            str(self.config_file),
            mode,
            "--cron",
        ]
        return " ".join([*args, *self.extra_args])


def generate_service_unit(config: SystemdConfig) -> str:
    """The systemd service unit (a oneshot renewal run)."""
    lines = [
        "[Unit]",
        f"Description={config.description}",
        "After=network-online.target",
        "Wants=network-online.target",
        "Documentation=https://github.com/mattsta/lematt",
        "",
        "[Service]",
        "Type=oneshot",
        f"User={config.user}",
        f"WorkingDirectory={config.config_file.parent}",
        f"ExecStart={config.command}",
        f"TimeoutStartSec={config.timeout_start_sec}",
        # Exit 75: another run still holds the lock; not a failure
        "SuccessExitStatus=75",
        "PrivateTmp=true",
        f"SyslogIdentifier={config.service_name}",
    ]
    return "\n".join(lines) + "\n"


def generate_timer_unit(config: SystemdConfig) -> str:
    """The systemd timer unit scheduling the service."""
    lines = [
        "[Unit]",
        f"Description={config.description} Timer",
        "Documentation=https://github.com/mattsta/lematt",
        "",
        "[Timer]",
        f"OnCalendar={config.calendar}",
        f"RandomizedDelaySec={config.randomized_delay_sec}",
        f"Persistent={str(config.persistent).lower()}",
        "",
        "[Install]",
        "WantedBy=timers.target",
    ]
    return "\n".join(lines) + "\n"


@dataclass
class SystemdInstaller:
    """Writes, enables and inspects the systemd units."""

    config: SystemdConfig
    systemd_dir: Path = field(default_factory=lambda: Path("/etc/systemd/system"))
    dry_run: bool = False

    @property
    def service_path(self) -> Path:
        return self.systemd_dir / f"{self.config.service_name}.service"

    @property
    def timer_path(self) -> Path:
        return self.systemd_dir / f"{self.config.service_name}.timer"

    def generate_units(self) -> dict[Path, str]:
        return {
            self.service_path: generate_service_unit(self.config),
            self.timer_path: generate_timer_unit(self.config),
        }

    def _systemctl(
        self, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["systemctl", *args], check=check, capture_output=True, text=True
        )

    def install(self) -> bool:
        """Write the units, reload systemd, and enable and start the timer."""
        for path, content in self.generate_units().items():
            if self.dry_run:
                logger.info(f"[DRY RUN] Would write {path}:\n{content}")
                continue
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            except PermissionError:
                logger.error(f"Permission denied writing {path} - run as root")
                return False
            logger.info(f"Wrote: {path}")

        if self.dry_run:
            logger.info("[DRY RUN] Would reload systemd and enable the timer")
            return True
        try:
            self._systemctl("daemon-reload")
            self._systemctl("enable", "--now", f"{self.config.service_name}.timer")
        except (OSError, subprocess.CalledProcessError) as e:
            logger.error(f"systemctl failed: {e}")
            return False
        logger.info(f"Enabled and started {self.config.service_name}.timer")
        return True

    def uninstall(self) -> bool:
        """Disable the timer and remove the units."""
        if self.dry_run:
            logger.info("[DRY RUN] Would disable the timer and remove the units")
            return True
        try:
            self._systemctl(
                "disable", "--now", f"{self.config.service_name}.timer", check=False
            )
        except OSError as e:
            logger.warning(f"systemctl failed: {e}")
        for path in (self.service_path, self.timer_path):
            try:
                path.unlink(missing_ok=True)
            except PermissionError:
                logger.error(f"Permission denied removing {path}")
                return False
            logger.info(f"Removed: {path}")
        with contextlib.suppress(OSError):
            self._systemctl("daemon-reload", check=False)
        return True

    def status(self) -> dict[str, object]:
        """Installed/active/enabled state and trigger times of the timer."""
        timer = f"{self.config.service_name}.timer"
        result: dict[str, object] = {
            "service_installed": self.service_path.exists(),
            "timer_installed": self.timer_path.exists(),
            "timer_active": False,
            "timer_enabled": False,
            "next_trigger": None,
            "last_trigger": None,
        }
        if not self.timer_path.exists():
            return result
        try:
            result["timer_active"] = (
                self._systemctl("is-active", timer, check=False).returncode == 0
            )
            result["timer_enabled"] = (
                self._systemctl("is-enabled", timer, check=False).returncode == 0
            )
            for key, prop in (
                ("next_trigger", "NextElapseUSecRealtime"),
                ("last_trigger", "LastTriggerUSec"),
            ):
                shown = self._systemctl(
                    "show", timer, f"--property={prop}", check=False
                )
                value = shown.stdout.strip().partition("=")[2]
                result[key] = value or None
        except OSError as e:
            logger.warning(f"systemctl failed: {e}")
        return result


# Schedules (all meet Let's Encrypt's "check at least twice a day" guidance
# except "conservative", which suits only 90-day certificates)
PRESETS: dict[str, SystemdConfig] = {
    "default": SystemdConfig(),
    "aggressive": SystemdConfig(
        calendar="*-*-* 00,06,12,18:00:00",
        randomized_delay_sec=1800,
        description="Lematt Certificate Renewal (4x daily)",
    ),
    "conservative": SystemdConfig(
        calendar="*-*-* 03:00:00",
        randomized_delay_sec=7200,
        description="Lematt Certificate Renewal (daily)",
    ),
}
