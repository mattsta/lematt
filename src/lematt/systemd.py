"""Systemd timer and service generation for automated certificate renewals.

This module provides automatic generation and installation of systemd units
for scheduled certificate renewal with proper alerting and monitoring.
"""

import contextlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class SystemdConfig:
    """Configuration for systemd unit generation."""

    # Unit naming
    service_name: str = "lematt-renew"
    description: str = "Lematt Certificate Renewal Service"

    # Timer configuration
    calendar: str = "*-*-* 00,12:00:00"  # Twice daily (Let's Encrypt recommended)
    randomized_delay_sec: int = 3600  # 1 hour random delay to spread load
    persistent: bool = True  # Run missed timers on boot

    # Service configuration
    user: str = "root"  # Must be root for cert operations
    working_directory: str = "/etc/lematt"
    config_file: str = "/etc/lematt/lematt.toml"

    # Execution settings
    use_test_mode: bool = False
    extra_args: list[str] = field(default_factory=list)

    # Notification settings
    notify_on_failure: bool = True
    notify_on_success: bool = False
    notify_command: str = ""  # Custom notification command

    # Resource limits
    memory_max: str = "512M"
    cpu_quota: str = "50%"

    # Security hardening
    private_tmp: bool = True
    protect_system: str = "strict"
    protect_home: bool = True
    no_new_privileges: bool = True


def generate_service_unit(config: SystemdConfig) -> str:
    """Generate the systemd service unit file content."""
    # Build the lematt command
    lematt_cmd = f"/usr/bin/env python3 -m lematt --config {config.config_file}"
    if config.use_test_mode:
        lematt_cmd += " --test"
    if config.extra_args:
        lematt_cmd += " " + " ".join(config.extra_args)

    # Build ExecStartPost for notifications if configured
    exec_post_lines = []
    if config.notify_on_success and config.notify_command:
        exec_post_lines.append(
            f"ExecStartPost=-{config.notify_command} success"
        )

    # Build the unit file
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
        f"WorkingDirectory={config.working_directory}",
        f"ExecStart={lematt_cmd}",
    ]

    # Add notification on success
    lines.extend(exec_post_lines)

    # Add failure notification
    if config.notify_on_failure and config.notify_command:
        lines.append(f"ExecStopPost=-/bin/sh -c 'if [ \"$SERVICE_RESULT\" != \"success\" ]; then {config.notify_command} failure; fi'")

    # Resource limits
    lines.extend([
        "",
        "# Resource limits",
        f"MemoryMax={config.memory_max}",
        f"CPUQuota={config.cpu_quota}",
    ])

    # Security hardening
    lines.extend([
        "",
        "# Security hardening",
        f"PrivateTmp={str(config.private_tmp).lower()}",
        f"ProtectSystem={config.protect_system}",
        f"ProtectHome={str(config.protect_home).lower()}",
        f"NoNewPrivileges={str(config.no_new_privileges).lower()}",
        "ReadWritePaths=/etc/lematt",
        "ReadWritePaths=/var/www/.well-known/acme-challenge",
    ])

    # Environment for structured logging
    lines.extend([
        "",
        "# Logging",
        "StandardOutput=journal",
        "StandardError=journal",
        f"SyslogIdentifier={config.service_name}",
    ])

    lines.extend([
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ])

    return "\n".join(lines) + "\n"


def generate_timer_unit(config: SystemdConfig) -> str:
    """Generate the systemd timer unit file content."""
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


def generate_notification_script() -> str:
    """Generate a notification helper script."""
    return '''#!/bin/bash
# Lematt notification helper script
# Usage: lematt-notify.sh <success|failure> [message]

STATUS="${1:-unknown}"
MESSAGE="${2:-Certificate renewal $STATUS}"
HOSTNAME=$(hostname -f)
TIMESTAMP=$(date -Iseconds)

# Load notification config if present
CONFIG_FILE="/etc/lematt/notify.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Email notification
send_email() {
    if [[ -n "$NOTIFY_EMAIL" ]]; then
        echo -e "Host: $HOSTNAME\\nTime: $TIMESTAMP\\nStatus: $STATUS\\n\\n$MESSAGE" | \
            mail -s "[$STATUS] Lematt Certificate Renewal - $HOSTNAME" "$NOTIFY_EMAIL"
    fi
}

# Webhook notification (Slack, Discord, etc.)
send_webhook() {
    if [[ -n "$NOTIFY_WEBHOOK" ]]; then
        local color="good"
        [[ "$STATUS" == "failure" ]] && color="danger"

        local payload
        payload=$(cat <<EOF
{
    "attachments": [{
        "color": "$color",
        "title": "Certificate Renewal: $STATUS",
        "text": "$MESSAGE",
        "fields": [
            {"title": "Host", "value": "$HOSTNAME", "short": true},
            {"title": "Time", "value": "$TIMESTAMP", "short": true}
        ]
    }]
}
EOF
)
        curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$NOTIFY_WEBHOOK"
    fi
}

# PagerDuty notification
send_pagerduty() {
    if [[ -n "$PAGERDUTY_KEY" ]] && [[ "$STATUS" == "failure" ]]; then
        local payload
        payload=$(cat <<EOF
{
    "routing_key": "$PAGERDUTY_KEY",
    "event_action": "trigger",
    "dedup_key": "lematt-$HOSTNAME",
    "payload": {
        "summary": "Certificate renewal failure on $HOSTNAME",
        "source": "$HOSTNAME",
        "severity": "critical",
        "custom_details": {
            "message": "$MESSAGE",
            "timestamp": "$TIMESTAMP"
        }
    }
}
EOF
)
        curl -s -X POST -H "Content-Type: application/json" \
            -d "$payload" "https://events.pagerduty.com/v2/enqueue"
    fi
}

# Ntfy notification (self-hosted push notifications)
send_ntfy() {
    if [[ -n "$NTFY_TOPIC" ]]; then
        local priority="default"
        [[ "$STATUS" == "failure" ]] && priority="high"

        curl -s -X POST "${NTFY_SERVER:-https://ntfy.sh}/$NTFY_TOPIC" \
            -H "Title: Lematt: $STATUS" \
            -H "Priority: $priority" \
            -H "Tags: ${STATUS},certificate" \
            -d "$MESSAGE - $HOSTNAME"
    fi
}

# Run custom command
run_custom() {
    if [[ -n "$NOTIFY_CUSTOM_CMD" ]]; then
        $NOTIFY_CUSTOM_CMD "$STATUS" "$MESSAGE" "$HOSTNAME" "$TIMESTAMP"
    fi
}

# Execute all configured notifications
send_email
send_webhook
send_pagerduty
send_ntfy
run_custom

# Log to journald
logger -t lematt-notify "Certificate renewal $STATUS: $MESSAGE"
'''


def generate_notify_config() -> str:
    """Generate an example notification configuration file."""
    return '''# Lematt notification configuration
# Uncomment and configure the notification methods you want to use

# Email notification (requires mail command configured)
# NOTIFY_EMAIL="admin@example.com"

# Webhook notification (Slack, Discord, etc.)
# NOTIFY_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"

# PagerDuty integration (only triggers on failures)
# PAGERDUTY_KEY="your-pagerduty-integration-key"

# Ntfy push notifications (https://ntfy.sh)
# NTFY_TOPIC="my-cert-alerts"
# NTFY_SERVER="https://ntfy.sh"  # Optional, defaults to ntfy.sh

# Custom command (receives: status message hostname timestamp)
# NOTIFY_CUSTOM_CMD="/usr/local/bin/my-notify-script.sh"
'''


@dataclass
class SystemdInstaller:
    """Handles installation and management of systemd units."""

    config: SystemdConfig
    systemd_dir: Path = field(default_factory=lambda: Path("/etc/systemd/system"))
    bin_dir: Path = field(default_factory=lambda: Path("/usr/local/bin"))
    dry_run: bool = False

    @property
    def service_path(self) -> Path:
        return self.systemd_dir / f"{self.config.service_name}.service"

    @property
    def timer_path(self) -> Path:
        return self.systemd_dir / f"{self.config.service_name}.timer"

    @property
    def notify_script_path(self) -> Path:
        return self.bin_dir / "lematt-notify.sh"

    @property
    def notify_config_path(self) -> Path:
        return Path("/etc/lematt/notify.conf")

    def generate_units(self) -> dict[str, str]:
        """Generate all unit files and scripts."""
        return {
            str(self.service_path): generate_service_unit(self.config),
            str(self.timer_path): generate_timer_unit(self.config),
            str(self.notify_script_path): generate_notification_script(),
            str(self.notify_config_path): generate_notify_config(),
        }

    def install(self) -> bool:
        """Install systemd units and enable the timer."""
        units = self.generate_units()

        # Write all files
        for path_str, content in units.items():
            path = Path(path_str)
            if self.dry_run:
                logger.info(f"[DRY RUN] Would write: {path}")
                continue

            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                logger.info(f"Wrote: {path}")

                # Make notification script executable
                if path_str.endswith(".sh"):
                    path.chmod(0o755)
            except PermissionError:
                logger.error(f"Permission denied writing {path} - run as root")
                return False

        if self.dry_run:
            logger.info("[DRY RUN] Would reload systemd and enable timer")
            return True

        # Reload systemd
        try:
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            logger.info("Reloaded systemd daemon")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload systemd: {e}")
            return False

        # Enable and start timer
        try:
            subprocess.run(
                ["systemctl", "enable", f"{self.config.service_name}.timer"],
                check=True,
            )
            subprocess.run(
                ["systemctl", "start", f"{self.config.service_name}.timer"],
                check=True,
            )
            logger.info(f"Enabled and started {self.config.service_name}.timer")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable timer: {e}")
            return False

        return True

    def uninstall(self) -> bool:
        """Uninstall systemd units and disable the timer."""
        if self.dry_run:
            logger.info("[DRY RUN] Would stop and disable timer, remove units")
            return True

        # Stop and disable timer
        try:
            subprocess.run(
                ["systemctl", "stop", f"{self.config.service_name}.timer"],
                check=False,  # Don't fail if not running
            )
            subprocess.run(
                ["systemctl", "disable", f"{self.config.service_name}.timer"],
                check=False,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to stop/disable timer: {e}")

        # Remove files
        for path in [self.service_path, self.timer_path]:
            try:
                if path.exists():
                    path.unlink()
                    logger.info(f"Removed: {path}")
            except PermissionError:
                logger.error(f"Permission denied removing {path}")
                return False

        # Reload systemd
        with contextlib.suppress(subprocess.CalledProcessError):
            subprocess.run(["systemctl", "daemon-reload"], check=True)

        return True

    def status(self) -> dict[str, object]:
        """Get status of the systemd units."""
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

        # Check timer status
        try:
            proc = subprocess.run(
                ["systemctl", "is-active", f"{self.config.service_name}.timer"],
                capture_output=True,
                text=True,
            )
            result["timer_active"] = proc.returncode == 0

            proc = subprocess.run(
                ["systemctl", "is-enabled", f"{self.config.service_name}.timer"],
                capture_output=True,
                text=True,
            )
            result["timer_enabled"] = proc.returncode == 0

            # Get next trigger time
            proc = subprocess.run(
                ["systemctl", "show", f"{self.config.service_name}.timer",
                 "--property=NextElapseUSecRealtime"],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                line = proc.stdout.strip()
                if "=" in line:
                    result["next_trigger"] = line.split("=", 1)[1] or None

            # Get last trigger time
            proc = subprocess.run(
                ["systemctl", "show", f"{self.config.service_name}.timer",
                 "--property=LastTriggerUSec"],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                line = proc.stdout.strip()
                if "=" in line:
                    result["last_trigger"] = line.split("=", 1)[1] or None

        except subprocess.CalledProcessError:
            pass

        return result


# Preset configurations for common use cases
PRESETS: dict[str, SystemdConfig] = {
    "default": SystemdConfig(),
    "aggressive": SystemdConfig(
        calendar="*-*-* 00,06,12,18:00:00",  # 4 times daily
        randomized_delay_sec=1800,  # 30 minutes
        description="Lematt Certificate Renewal (Aggressive)",
    ),
    "conservative": SystemdConfig(
        calendar="*-*-* 03:00:00",  # Once daily at 3 AM
        randomized_delay_sec=7200,  # 2 hours
        description="Lematt Certificate Renewal (Conservative)",
    ),
    "weekly": SystemdConfig(
        calendar="Mon *-*-* 03:00:00",  # Weekly on Monday
        randomized_delay_sec=3600,
        description="Lematt Certificate Renewal (Weekly)",
    ),
}
