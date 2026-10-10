"""Health check and monitoring system for certificate management.

This module provides comprehensive health checking capabilities including:
- Certificate expiry monitoring
- Pre-emptive warnings for approaching expirations
- Validation of certificate chains
- Status reporting for monitoring systems
"""

import datetime
import json
import socket
import ssl
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import cast

from loguru import logger

from .config import DomainConfig, KeyType, LemattConfig
from .crypto import get_certificate_info
from .manager import CertificateManager, RenewalPlan
from .notifications import NotificationEvent, NotificationManager


def _iso(moment: datetime.datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _utcnow() -> datetime.datetime:
    """Current time as naive UTC, matching parsed certificate dates."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


class HealthStatus(Enum):
    """Health check status levels."""

    HEALTHY = auto()
    WARNING = auto()
    CRITICAL = auto()
    UNKNOWN = auto()

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class CertificateHealth:
    """Health status for a single certificate."""

    domain: str
    key_type: str
    status: HealthStatus
    message: str
    cert_path: str | None = None
    days_until_expiry: int | None = None
    not_after: datetime.datetime | None = None
    issuer: str | None = None
    details: dict[str, object] = field(default_factory=dict)
    renewal_due_at: datetime.datetime | None = None
    renewal_basis: str | None = None
    last_success: datetime.datetime | None = None
    consecutive_failures: int = 0
    last_error: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON output."""
        return {
            "domain": self.domain,
            "key_type": self.key_type,
            "status": str(self.status),
            "message": self.message,
            "cert_path": self.cert_path,
            "days_until_expiry": self.days_until_expiry,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "issuer": self.issuer,
            "details": self.details,
            "renewal": {
                "due_at": _iso(self.renewal_due_at),
                "basis": self.renewal_basis,
                "last_success": _iso(self.last_success),
                "consecutive_failures": self.consecutive_failures,
                "last_error": self.last_error,
            },
        }


@dataclass
class SystemHealth:
    """Overall system health status."""

    status: HealthStatus
    certificates: list[CertificateHealth]
    checked_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    summary: str = ""

    @property
    def healthy_count(self) -> int:
        return sum(1 for c in self.certificates if c.status == HealthStatus.HEALTHY)

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.certificates if c.status == HealthStatus.WARNING)

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.certificates if c.status == HealthStatus.CRITICAL)

    @property
    def unknown_count(self) -> int:
        return sum(1 for c in self.certificates if c.status == HealthStatus.UNKNOWN)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for JSON output."""
        return {
            "status": str(self.status),
            "summary": self.summary,
            "checked_at": self.checked_at.isoformat(),
            "counts": {
                "healthy": self.healthy_count,
                "warning": self.warning_count,
                "critical": self.critical_count,
                "unknown": self.unknown_count,
                "total": len(self.certificates),
            },
            "certificates": [c.to_dict() for c in self.certificates],
        }


@dataclass
class HealthChecker:
    """Performs health checks on certificates."""

    config: LemattConfig
    # Fixed day thresholds; when both are None, status is relative to each
    # certificate's lifetime and renewal state instead
    warning_days: int | None = None
    critical_days: int | None = None
    notification_manager: NotificationManager | None = None

    def check_certificate_file(
        self,
        cert_path: Path,
        domain: str,
        key_type: str,
        plan: RenewalPlan | None = None,
    ) -> CertificateHealth:
        """Check health of a certificate file.

        With a renewal ``plan`` (and no explicit day thresholds), the result
        reflects lematt's renewal state: a renewal that is overdue (failing)
        is a warning long before the certificate is close to expiry.
        """
        info = get_certificate_info(cert_path)
        if not info.exists:
            return CertificateHealth(
                domain=domain,
                key_type=key_type,
                status=HealthStatus.CRITICAL,
                message="Certificate file not found",
                cert_path=str(cert_path),
            )
        if info.parse_error or info.not_after is None:
            return CertificateHealth(
                domain=domain,
                key_type=key_type,
                status=HealthStatus.UNKNOWN,
                message=f"Failed to parse certificate: {info.parse_error}",
                cert_path=str(cert_path),
            )

        now = _utcnow()
        days_until_expiry = (info.not_after - now).days
        if self._explicit_thresholds or plan is None or info.lifetime is None:
            status, message = self._classify(days_until_expiry, "Certificate")
        else:
            status, message = self._classify_by_lifetime(
                info.not_after - now, info.lifetime, plan, now
            )

        health = CertificateHealth(
            domain=domain,
            key_type=key_type,
            status=status,
            message=message,
            cert_path=str(cert_path),
            days_until_expiry=days_until_expiry,
            not_after=info.not_after,
            issuer=info.issuer_dn,
        )
        if plan is not None:
            attempts = plan.state.attempts
            health.renewal_due_at = plan.decision.due_at
            health.renewal_basis = plan.decision.basis
            health.last_success = attempts.last_success
            health.consecutive_failures = attempts.consecutive_failures
            health.last_error = attempts.last_error
        return health

    @property
    def _explicit_thresholds(self) -> bool:
        return self.warning_days is not None or self.critical_days is not None

    def _classify(
        self, days_until_expiry: int, subject: str
    ) -> tuple[HealthStatus, str]:
        """Map days until expiry to a status using fixed day thresholds."""
        warning = self.warning_days if self.warning_days is not None else 14
        critical = self.critical_days if self.critical_days is not None else 7
        if days_until_expiry < 0:
            return (
                HealthStatus.CRITICAL,
                f"{subject} EXPIRED {abs(days_until_expiry)} days ago",
            )
        if days_until_expiry < critical:
            return (
                HealthStatus.CRITICAL,
                f"{subject} expires in {days_until_expiry} days (CRITICAL)",
            )
        if days_until_expiry < warning:
            return (
                HealthStatus.WARNING,
                f"{subject} expires in {days_until_expiry} days",
            )
        return HealthStatus.HEALTHY, f"{subject} valid for {days_until_expiry} days"

    @staticmethod
    def _classify_by_lifetime(
        remaining: datetime.timedelta,
        lifetime: datetime.timedelta,
        plan: RenewalPlan,
        now: datetime.datetime,
    ) -> tuple[HealthStatus, str]:
        """Status relative to the certificate's lifetime and renewal state.

        Critical: expired, or less than a tenth of the lifetime left.
        Warning: renewal is overdue (past its due time plus a grace period of
        a day, or a tenth of the lifetime for short-lived certificates).
        """
        days = remaining.days
        attempts = plan.state.attempts
        failing = (
            f" ({attempts.consecutive_failures} failed attempt(s): {attempts.last_error})"
            if attempts.consecutive_failures
            else ""
        )
        if remaining <= datetime.timedelta(0):
            return (
                HealthStatus.CRITICAL,
                f"Certificate EXPIRED {abs(days)} days ago{failing}",
            )
        if remaining < lifetime / 10:
            return (
                HealthStatus.CRITICAL,
                f"Certificate expires in {days} days (CRITICAL){failing}",
            )
        due = plan.decision.due_at
        grace = min(datetime.timedelta(days=1), lifetime / 10)
        if due is not None and now > due + grace:
            return (
                HealthStatus.WARNING,
                f"Renewal overdue since {due:%Y-%m-%d %H:%M} UTC; expires in "
                f"{days} days{failing}",
            )
        when = f"; renews {due:%Y-%m-%d} ({plan.decision.basis})" if due else ""
        return HealthStatus.HEALTHY, f"Certificate valid for {days} days{when}"

    @staticmethod
    def _classify_served(
        remaining: datetime.timedelta, lifetime: datetime.timedelta
    ) -> tuple[HealthStatus, str]:
        """Status of a certificate a server presents, relative to its lifetime.

        A served certificate with less than a quarter of its lifetime left
        should already have been replaced (lematt renews at about a third),
        so the renewed certificate probably wasn't deployed.
        """
        days = remaining.days
        if remaining <= datetime.timedelta(0):
            return (
                HealthStatus.CRITICAL,
                f"Live certificate EXPIRED {abs(days)} days ago",
            )
        if remaining < lifetime / 10:
            return (
                HealthStatus.CRITICAL,
                f"Live certificate expires in {days} days (CRITICAL)",
            )
        if remaining < lifetime / 4:
            return (
                HealthStatus.WARNING,
                f"Live certificate expires in {days} days and should have been "
                "replaced by now (was the renewed certificate deployed?)",
            )
        return HealthStatus.HEALTHY, f"Live certificate valid for {days} days"

    def check_live_certificate(
        self,
        domain: str,
        port: int = 443,
        timeout: float = 10.0,
    ) -> CertificateHealth:
        """Check the live certificate served by a domain."""
        try:
            context = ssl.create_default_context()
            with (
                socket.create_connection((domain, port), timeout=timeout) as sock,
                context.wrap_socket(sock, server_hostname=domain) as ssock,
            ):
                cert = ssock.getpeercert()

            if not cert:
                return CertificateHealth(
                    domain=domain,
                    key_type="live",
                    status=HealthStatus.CRITICAL,
                    message="No certificate returned by server",
                )

            # Parse expiry
            not_after_str = str(cert.get("notAfter", ""))
            try:
                not_after = datetime.datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                )
            except ValueError:
                return CertificateHealth(
                    domain=domain,
                    key_type="live",
                    status=HealthStatus.UNKNOWN,
                    message=f"Could not parse expiry date: {not_after_str}",
                )

            # Get issuer
            issuer_parts = cast(
                "tuple[tuple[tuple[str, str], ...], ...]", cert.get("issuer", ())
            )
            issuer = None
            for part in issuer_parts:
                for key, value in part:
                    if key == "organizationName":
                        issuer = value
                        break

            now = _utcnow()
            days_until_expiry = (not_after - now).days
            not_before = _peer_time(cert.get("notBefore"))
            if self._explicit_thresholds or not_before is None:
                status, message = self._classify(days_until_expiry, "Live certificate")
            else:
                status, message = self._classify_served(
                    not_after - now, not_after - not_before
                )

            return CertificateHealth(
                domain=domain,
                key_type="live",
                status=status,
                message=message,
                days_until_expiry=days_until_expiry,
                not_after=not_after,
                issuer=issuer,
                details={"port": port},
            )

        except ssl.SSLCertVerificationError as e:
            return CertificateHealth(
                domain=domain,
                key_type="live",
                status=HealthStatus.CRITICAL,
                message=f"Certificate verification failed: {e}",
            )
        except TimeoutError:
            return CertificateHealth(
                domain=domain,
                key_type="live",
                status=HealthStatus.UNKNOWN,
                message="Connection timed out",
            )
        except Exception as e:
            return CertificateHealth(
                domain=domain,
                key_type="live",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking live certificate: {e}",
            )

    def check_all_certificates(
        self,
        domains: list[DomainConfig],
        key_types: list[str] | None = None,
    ) -> SystemHealth:
        """Check all configured certificates."""
        if key_types is None:
            key_types = ["rsa", "ec"]

        certificates: list[CertificateHealth] = []
        manager = CertificateManager(self.config)
        now = _utcnow()
        worst_status = HealthStatus.HEALTHY

        for domain_config in domains:
            for key_type in key_types:
                kt = KeyType.from_string(key_type)
                health = self.check_certificate_file(
                    Path(self.config.get_cert_path(domain_config, kt)),
                    domain_config.primary_domain,
                    key_type,
                    plan=manager.plan(domain_config, kt, now),
                )
                certificates.append(health)

                # Track worst status
                if health.status == HealthStatus.CRITICAL:
                    worst_status = HealthStatus.CRITICAL
                elif (
                    health.status == HealthStatus.WARNING
                    and worst_status != HealthStatus.CRITICAL
                ):
                    worst_status = HealthStatus.WARNING
                elif (
                    health.status == HealthStatus.UNKNOWN
                    and worst_status == HealthStatus.HEALTHY
                ):
                    worst_status = HealthStatus.UNKNOWN

        # Generate summary
        summary_parts = []
        healthy = sum(1 for c in certificates if c.status == HealthStatus.HEALTHY)
        warning = sum(1 for c in certificates if c.status == HealthStatus.WARNING)
        critical = sum(1 for c in certificates if c.status == HealthStatus.CRITICAL)
        unknown = sum(1 for c in certificates if c.status == HealthStatus.UNKNOWN)

        if critical > 0:
            summary_parts.append(f"{critical} critical")
        if warning > 0:
            summary_parts.append(f"{warning} warning")
        if unknown > 0:
            summary_parts.append(f"{unknown} unknown")
        summary_parts.append(f"{healthy} healthy")

        summary = f"Certificates: {', '.join(summary_parts)}"

        system_health = SystemHealth(
            status=worst_status,
            certificates=certificates,
            summary=summary,
        )

        # Send notifications for issues
        if self.notification_manager:
            self._send_health_notifications(certificates)

        return system_health

    def _send_health_notifications(self, certificates: list[CertificateHealth]) -> None:
        """Send notifications for unhealthy certificates."""
        if not self.notification_manager:
            return

        for cert in certificates:
            if cert.status == HealthStatus.CRITICAL:
                if cert.days_until_expiry is not None and cert.days_until_expiry < 0:
                    # Expired
                    event = NotificationEvent(
                        event_type="failure",
                        title="Certificate Expired",
                        message=cert.message,
                        details={
                            "domain": cert.domain,
                            "key_type": cert.key_type,
                            "cert_path": cert.cert_path or "unknown",
                        },
                    )
                else:
                    # Expiring soon
                    event = NotificationEvent(
                        event_type="failure",
                        title="Certificate Expiring Soon",
                        message=cert.message,
                        details={
                            "domain": cert.domain,
                            "key_type": cert.key_type,
                            "days_remaining": cert.days_until_expiry,
                        },
                    )
                self.notification_manager.notify(event)

            elif cert.status == HealthStatus.WARNING:
                self.notification_manager.notify(
                    NotificationEvent(
                        event_type="warning",
                        title="Certificate Needs Attention",
                        message=f"{cert.domain} ({cert.key_type}): {cert.message}",
                        details={
                            "domain": cert.domain,
                            "key_type": cert.key_type,
                            "days_remaining": cert.days_until_expiry,
                        },
                    )
                )


@dataclass
class PrometheusMetrics:
    """Generate Prometheus-compatible metrics for monitoring."""

    health: SystemHealth

    def generate(self) -> str:
        """Generate Prometheus metrics output."""
        lines = [
            "# HELP lematt_certificate_expiry_days Days until certificate expires",
            "# TYPE lematt_certificate_expiry_days gauge",
        ]

        for cert in self.health.certificates:
            if cert.days_until_expiry is not None:
                labels = f'domain="{cert.domain}",key_type="{cert.key_type}"'
                lines.append(
                    f"lematt_certificate_expiry_days{{{labels}}} {cert.days_until_expiry}"
                )

        lines.extend(
            [
                "",
                "# HELP lematt_certificate_status Certificate health status (0=healthy, 1=warning, 2=critical, 3=unknown)",
                "# TYPE lematt_certificate_status gauge",
            ]
        )

        status_map = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.WARNING: 1,
            HealthStatus.CRITICAL: 2,
            HealthStatus.UNKNOWN: 3,
        }

        for cert in self.health.certificates:
            labels = f'domain="{cert.domain}",key_type="{cert.key_type}"'
            value = status_map.get(cert.status, 3)
            lines.append(f"lematt_certificate_status{{{labels}}} {value}")

        lines.extend(
            [
                "",
                "# HELP lematt_health_check_timestamp_seconds Unix timestamp of last health check",
                "# TYPE lematt_health_check_timestamp_seconds gauge",
                f"lematt_health_check_timestamp_seconds {self.health.checked_at.timestamp():.0f}",
                "",
                "# HELP lematt_certificates_total Total number of certificates by status",
                "# TYPE lematt_certificates_total gauge",
                f'lematt_certificates_total{{status="healthy"}} {self.health.healthy_count}',
                f'lematt_certificates_total{{status="warning"}} {self.health.warning_count}',
                f'lematt_certificates_total{{status="critical"}} {self.health.critical_count}',
                f'lematt_certificates_total{{status="unknown"}} {self.health.unknown_count}',
            ]
        )

        lines.extend(self._renewal_metrics())
        return "\n".join(lines) + "\n"

    def _renewal_metrics(self) -> list[str]:
        """Timestamp/counter gauges from lematt's renewal state."""

        def ts(moment: datetime.datetime | None) -> str | None:
            if moment is None:
                return None
            return f"{moment.replace(tzinfo=datetime.UTC).timestamp():.0f}"

        families = [
            (
                "lematt_certificate_expiry_timestamp_seconds",
                "Unix time the certificate expires",
                lambda c: ts(c.not_after),
            ),
            (
                "lematt_certificate_renewal_due_timestamp_seconds",
                "Unix time lematt plans to renew the certificate",
                lambda c: ts(c.renewal_due_at),
            ),
            (
                "lematt_certificate_last_renewal_timestamp_seconds",
                "Unix time of the last successful renewal",
                lambda c: ts(c.last_success),
            ),
            (
                "lematt_certificate_renewal_failures",
                "Consecutive failed renewal attempts",
                lambda c: str(c.consecutive_failures) if c.key_type != "live" else None,
            ),
        ]
        lines: list[str] = []
        for name, help_text, value_of in families:
            samples = [
                (f'domain="{c.domain}",key_type="{c.key_type}"', value)
                for c in self.health.certificates
                if (value := value_of(c)) is not None
            ]
            if samples:
                lines.extend(["", f"# HELP {name} {help_text}", f"# TYPE {name} gauge"])
                lines.extend(f"{name}{{{labels}}} {value}" for labels, value in samples)
        return lines


def write_health_status_file(
    health: SystemHealth,
    path: Path,
    format: str = "json",
) -> None:
    """Write health status to a file for external monitoring."""
    path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        content = json.dumps(health.to_dict(), indent=2)
    elif format == "prometheus":
        metrics = PrometheusMetrics(health)
        content = metrics.generate()
    else:
        raise ValueError(f"Unknown format: {format}")

    path.write_text(content)
    logger.debug(f"Wrote health status to {path}")


def create_healthcheck_script() -> str:
    """Generate a simple healthcheck script for external monitoring."""
    return """#!/bin/bash
# Lematt certificate health check script
# Returns exit code based on certificate health:
#   0 = all healthy
#   1 = warnings present
#   2 = critical issues

STATUS_FILE="/var/lib/lematt/health.json"

if [[ ! -f "$STATUS_FILE" ]]; then
    echo "UNKNOWN - Status file not found"
    exit 3
fi

STATUS=$(jq -r '.status' "$STATUS_FILE" 2>/dev/null)
SUMMARY=$(jq -r '.summary' "$STATUS_FILE" 2>/dev/null)

case "$STATUS" in
    healthy)
        echo "OK - $SUMMARY"
        exit 0
        ;;
    warning)
        echo "WARNING - $SUMMARY"
        exit 1
        ;;
    critical)
        echo "CRITICAL - $SUMMARY"
        exit 2
        ;;
    *)
        echo "UNKNOWN - $SUMMARY"
        exit 3
        ;;
esac
"""


def _peer_time(value: object) -> datetime.datetime | None:
    """Parse an ssl.getpeercert() timestamp ("Jan  1 00:00:00 2026 GMT")."""
    try:
        return datetime.datetime.strptime(str(value), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
