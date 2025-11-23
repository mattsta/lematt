"""Notification and alerting system for certificate operations.

This module provides a unified interface for sending alerts through
multiple channels: email, webhooks, PagerDuty, ntfy, and custom commands.
"""

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from typing import Protocol
from urllib.error import URLError
from urllib.request import Request, urlopen

from loguru import logger


@dataclass
class NotificationEvent:
    """Represents a notification event."""

    event_type: str  # success, failure, warning, info
    title: str
    message: str
    hostname: str = field(default_factory=lambda: _get_hostname())
    timestamp: datetime = field(default_factory=datetime.now)
    details: dict[str, object] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        """Map event type to severity level."""
        return {
            "failure": "critical",
            "warning": "warning",
            "success": "info",
            "info": "info",
        }.get(self.event_type, "info")

    @property
    def is_failure(self) -> bool:
        return self.event_type == "failure"

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_type": self.event_type,
            "title": self.title,
            "message": self.message,
            "hostname": self.hostname,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "details": self.details,
        }


def _get_hostname() -> str:
    """Get the system hostname."""
    import socket

    try:
        return socket.getfqdn()
    except Exception:
        return "unknown"


class NotificationBackend(ABC):
    """Abstract base class for notification backends."""

    @abstractmethod
    def send(self, event: NotificationEvent) -> bool:
        """Send a notification. Returns True on success."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the backend name."""
        ...


@dataclass
class EmailBackend(NotificationBackend):
    """Email notification backend using sendmail or SMTP."""

    to_address: str
    from_address: str = "lematt@localhost"
    smtp_host: str = "localhost"
    smtp_port: int = 25
    use_sendmail: bool = True

    @property
    def name(self) -> str:
        return "email"

    def send(self, event: NotificationEvent) -> bool:
        """Send email notification."""
        subject = f"[{event.event_type.upper()}] {event.title}"
        body = self._format_body(event)

        if self.use_sendmail:
            return self._send_via_sendmail(subject, body)
        return self._send_via_smtp(subject, body)

    def _format_body(self, event: NotificationEvent) -> str:
        """Format the email body."""
        lines = [
            "Lematt Certificate Alert",
            f"{'=' * 40}",
            "",
            f"Status: {event.event_type.upper()}",
            f"Host: {event.hostname}",
            f"Time: {event.timestamp.isoformat()}",
            "",
            "Message:",
            f"{event.message}",
        ]

        if event.details:
            lines.extend([
                "",
                "Details:",
            ])
            for key, value in event.details.items():
                lines.append(f"  {key}: {value}")

        return "\n".join(lines)

    def _send_via_sendmail(self, subject: str, body: str) -> bool:
        """Send using sendmail command."""
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = self.from_address
            msg["To"] = self.to_address
            msg.set_content(body)

            proc = subprocess.run(
                ["/usr/sbin/sendmail", "-t"],
                input=msg.as_string(),
                text=True,
                capture_output=True,
            )
            if proc.returncode != 0:
                logger.warning(f"sendmail failed: {proc.stderr}")
                return False
            return True
        except Exception as e:
            logger.warning(f"Email send failed: {e}")
            return False

    def _send_via_smtp(self, subject: str, body: str) -> bool:
        """Send using SMTP."""
        import smtplib

        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = self.from_address
            msg["To"] = self.to_address
            msg.set_content(body)

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as smtp:
                smtp.send_message(msg)
            return True
        except Exception as e:
            logger.warning(f"SMTP send failed: {e}")
            return False


@dataclass
class WebhookBackend(NotificationBackend):
    """Generic webhook notification backend (Slack, Discord, etc.)."""

    url: str
    format: str = "slack"  # slack, discord, generic

    @property
    def name(self) -> str:
        return f"webhook-{self.format}"

    def send(self, event: NotificationEvent) -> bool:
        """Send webhook notification."""
        payload = self._format_payload(event)

        try:
            req = Request(
                self.url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=30) as response:
                return response.status < 400
        except URLError as e:
            logger.warning(f"Webhook send failed: {e}")
            return False

    def _format_payload(self, event: NotificationEvent) -> dict[str, object]:
        """Format the webhook payload based on target format."""
        if self.format == "slack":
            return self._slack_payload(event)
        elif self.format == "discord":
            return self._discord_payload(event)
        return self._generic_payload(event)

    def _slack_payload(self, event: NotificationEvent) -> dict[str, object]:
        """Format for Slack webhooks."""
        color = {"failure": "danger", "warning": "warning", "success": "good"}.get(
            event.event_type, "#439FE0"
        )

        fields = [
            {"title": "Host", "value": event.hostname, "short": True},
            {"title": "Time", "value": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "short": True},
        ]

        for key, value in event.details.items():
            fields.append({"title": key, "value": str(value), "short": True})

        return {
            "attachments": [
                {
                    "color": color,
                    "title": event.title,
                    "text": event.message,
                    "fields": fields,
                    "footer": "Lematt Certificate Manager",
                }
            ]
        }

    def _discord_payload(self, event: NotificationEvent) -> dict[str, object]:
        """Format for Discord webhooks."""
        color = {"failure": 0xFF0000, "warning": 0xFFFF00, "success": 0x00FF00}.get(
            event.event_type, 0x0099FF
        )

        fields = [
            {"name": "Host", "value": event.hostname, "inline": True},
            {"name": "Time", "value": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "inline": True},
        ]

        for key, value in event.details.items():
            fields.append({"name": key, "value": str(value), "inline": True})

        return {
            "embeds": [
                {
                    "title": event.title,
                    "description": event.message,
                    "color": color,
                    "fields": fields,
                    "footer": {"text": "Lematt Certificate Manager"},
                }
            ]
        }

    def _generic_payload(self, event: NotificationEvent) -> dict[str, object]:
        """Generic JSON payload."""
        return event.to_dict()


@dataclass
class PagerDutyBackend(NotificationBackend):
    """PagerDuty Events API v2 backend."""

    routing_key: str
    only_on_failure: bool = True

    @property
    def name(self) -> str:
        return "pagerduty"

    def send(self, event: NotificationEvent) -> bool:
        """Send PagerDuty alert."""
        if self.only_on_failure and not event.is_failure:
            logger.debug("Skipping PagerDuty for non-failure event")
            return True

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"lematt-{event.hostname}",
            "payload": {
                "summary": f"{event.title}: {event.message}",
                "source": event.hostname,
                "severity": event.severity,
                "timestamp": event.timestamp.isoformat(),
                "custom_details": event.details,
            },
        }

        try:
            req = Request(
                "https://events.pagerduty.com/v2/enqueue",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=30) as response:
                return response.status < 400
        except URLError as e:
            logger.warning(f"PagerDuty send failed: {e}")
            return False


@dataclass
class NtfyBackend(NotificationBackend):
    """Ntfy push notification backend (https://ntfy.sh)."""

    topic: str
    server: str = "https://ntfy.sh"
    token: str | None = None

    @property
    def name(self) -> str:
        return "ntfy"

    def send(self, event: NotificationEvent) -> bool:
        """Send ntfy push notification."""
        priority = {"failure": "urgent", "warning": "high", "success": "default"}.get(
            event.event_type, "default"
        )
        tags = f"{event.event_type},certificate"

        headers: dict[str, str] = {
            "Title": event.title,
            "Priority": priority,
            "Tags": tags,
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = f"{self.server.rstrip('/')}/{self.topic}"
        body = f"{event.message}\n\nHost: {event.hostname}"

        try:
            req = Request(url, data=body.encode("utf-8"), headers=headers, method="POST")
            with urlopen(req, timeout=30) as response:
                return response.status < 400
        except URLError as e:
            logger.warning(f"Ntfy send failed: {e}")
            return False


@dataclass
class CommandBackend(NotificationBackend):
    """Custom command execution backend."""

    command: str  # Command receives: event_type title message hostname timestamp

    @property
    def name(self) -> str:
        return "command"

    def send(self, event: NotificationEvent) -> bool:
        """Execute custom notification command."""
        try:
            proc = subprocess.run(
                [
                    self.command,
                    event.event_type,
                    event.title,
                    event.message,
                    event.hostname,
                    event.timestamp.isoformat(),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode != 0:
                logger.warning(f"Notification command failed: {proc.stderr}")
                return False
            return True
        except Exception as e:
            logger.warning(f"Notification command error: {e}")
            return False


@dataclass
class JournaldBackend(NotificationBackend):
    """Systemd journald logging backend."""

    identifier: str = "lematt"

    @property
    def name(self) -> str:
        return "journald"

    def send(self, event: NotificationEvent) -> bool:
        """Log to journald via logger command."""
        priority = {
            "failure": "err",
            "warning": "warning",
            "success": "info",
            "info": "info",
        }.get(event.event_type, "info")

        message = f"{event.title}: {event.message}"

        try:
            subprocess.run(
                ["logger", "-t", self.identifier, "-p", f"user.{priority}", message],
                check=True,
            )
            return True
        except Exception as e:
            logger.warning(f"Journald logging failed: {e}")
            return False


class NotificationSender(Protocol):
    """Protocol for notification sending."""

    def send(self, event: NotificationEvent) -> bool: ...


@dataclass
class NotificationManager:
    """Manages multiple notification backends."""

    backends: list[NotificationBackend] = field(default_factory=list)
    notify_on_success: bool = False
    notify_on_warning: bool = True
    notify_on_failure: bool = True

    def add_backend(self, backend: NotificationBackend) -> None:
        """Add a notification backend."""
        self.backends.append(backend)
        logger.debug(f"Added notification backend: {backend.name}")

    def should_notify(self, event: NotificationEvent) -> bool:
        """Check if we should send notifications for this event type."""
        if event.event_type == "success":
            return self.notify_on_success
        elif event.event_type == "warning":
            return self.notify_on_warning
        elif event.event_type == "failure":
            return self.notify_on_failure
        return True

    def notify(self, event: NotificationEvent) -> dict[str, bool]:
        """Send notification to all backends. Returns success status per backend."""
        if not self.should_notify(event):
            logger.debug(f"Skipping notification for event type: {event.event_type}")
            return {}

        results: dict[str, bool] = {}
        for backend in self.backends:
            try:
                success = backend.send(event)
                results[backend.name] = success
                if success:
                    logger.debug(f"Notification sent via {backend.name}")
                else:
                    logger.warning(f"Notification failed via {backend.name}")
            except Exception as e:
                logger.error(f"Notification error in {backend.name}: {e}")
                results[backend.name] = False

        return results

    def notify_renewal_success(
        self,
        domains: list[str],
        renewed_count: int,
        skipped_count: int,
    ) -> dict[str, bool]:
        """Send notification for successful renewal run."""
        event = NotificationEvent(
            event_type="success",
            title="Certificate Renewal Complete",
            message=f"Renewed {renewed_count} certificates, {skipped_count} already valid",
            details={
                "renewed": renewed_count,
                "skipped": skipped_count,
                "total_domains": len(domains),
            },
        )
        return self.notify(event)

    def notify_renewal_failure(
        self,
        failed_domains: list[str],
        error_messages: list[str],
    ) -> dict[str, bool]:
        """Send notification for failed renewals."""
        event = NotificationEvent(
            event_type="failure",
            title="Certificate Renewal Failed",
            message=f"Failed to renew {len(failed_domains)} certificates",
            details={
                "failed_domains": ", ".join(failed_domains[:10]),  # Limit for readability
                "errors": "; ".join(error_messages[:5]),
                "failed_count": len(failed_domains),
            },
        )
        return self.notify(event)

    def notify_expiry_warning(
        self,
        domain: str,
        days_remaining: int,
    ) -> dict[str, bool]:
        """Send notification for upcoming certificate expiry."""
        event = NotificationEvent(
            event_type="warning",
            title="Certificate Expiring Soon",
            message=f"Certificate for {domain} expires in {days_remaining} days",
            details={
                "domain": domain,
                "days_remaining": days_remaining,
            },
        )
        return self.notify(event)


@dataclass
class NotificationConfig:
    """Configuration for notification system loaded from config file."""

    email_to: str | None = None
    email_from: str = "lematt@localhost"
    email_smtp_host: str = "localhost"
    email_smtp_port: int = 25
    email_use_sendmail: bool = True

    webhook_url: str | None = None
    webhook_format: str = "slack"

    pagerduty_key: str | None = None
    pagerduty_only_failure: bool = True

    ntfy_topic: str | None = None
    ntfy_server: str = "https://ntfy.sh"
    ntfy_token: str | None = None

    custom_command: str | None = None

    journald_enabled: bool = True
    journald_identifier: str = "lematt"

    notify_on_success: bool = False
    notify_on_warning: bool = True
    notify_on_failure: bool = True

    def create_manager(self) -> NotificationManager:
        """Create a NotificationManager from this configuration."""
        manager = NotificationManager(
            notify_on_success=self.notify_on_success,
            notify_on_warning=self.notify_on_warning,
            notify_on_failure=self.notify_on_failure,
        )

        if self.email_to:
            manager.add_backend(EmailBackend(
                to_address=self.email_to,
                from_address=self.email_from,
                smtp_host=self.email_smtp_host,
                smtp_port=self.email_smtp_port,
                use_sendmail=self.email_use_sendmail,
            ))

        if self.webhook_url:
            manager.add_backend(WebhookBackend(
                url=self.webhook_url,
                format=self.webhook_format,
            ))

        if self.pagerduty_key:
            manager.add_backend(PagerDutyBackend(
                routing_key=self.pagerduty_key,
                only_on_failure=self.pagerduty_only_failure,
            ))

        if self.ntfy_topic:
            manager.add_backend(NtfyBackend(
                topic=self.ntfy_topic,
                server=self.ntfy_server,
                token=self.ntfy_token,
            ))

        if self.custom_command:
            manager.add_backend(CommandBackend(command=self.custom_command))

        if self.journald_enabled:
            manager.add_backend(JournaldBackend(identifier=self.journald_identifier))

        return manager
