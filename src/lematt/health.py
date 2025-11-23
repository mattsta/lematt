"""Health check and monitoring system for certificate management.

This module provides comprehensive health checking capabilities including:
- Certificate expiry monitoring
- Pre-emptive warnings for approaching expirations
- Validation of certificate chains
- Status reporting for monitoring systems
"""

import contextlib
import datetime
import json
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

from loguru import logger

from .config import DomainConfig, LemattConfig  # noqa: TC001 - used at runtime
from .notifications import NotificationEvent, NotificationManager


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
    warning_days: int = 14  # Warn when cert expires in less than this
    critical_days: int = 7  # Critical when cert expires in less than this
    notification_manager: NotificationManager | None = None

    def check_certificate_file(
        self,
        cert_path: Path,
        domain: str,
        key_type: str,
    ) -> CertificateHealth:
        """Check health of a certificate file."""
        if not cert_path.exists():
            return CertificateHealth(
                domain=domain,
                key_type=key_type,
                status=HealthStatus.CRITICAL,
                message="Certificate file not found",
                cert_path=str(cert_path),
            )

        # Parse certificate using openssl
        try:
            result = subprocess.run(
                [
                    "openssl", "x509",
                    "-in", str(cert_path),
                    "-noout",
                    "-dates",
                    "-issuer",
                    "-subject",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return CertificateHealth(
                    domain=domain,
                    key_type=key_type,
                    status=HealthStatus.UNKNOWN,
                    message=f"Failed to parse certificate: {result.stderr}",
                    cert_path=str(cert_path),
                )

            # Parse output
            output = result.stdout
            not_after = None
            issuer = None

            for line in output.split("\n"):
                if line.startswith("notAfter="):
                    date_str = line.replace("notAfter=", "").strip()
                    # Parse OpenSSL date format: "Jan  1 00:00:00 2024 GMT"
                    try:
                        not_after = datetime.datetime.strptime(
                            date_str, "%b %d %H:%M:%S %Y %Z"
                        )
                    except ValueError:
                        # Try alternative format (double space for single digit day)
                        with contextlib.suppress(ValueError):
                            not_after = datetime.datetime.strptime(
                                date_str, "%b  %d %H:%M:%S %Y %Z"
                            )
                elif line.startswith("issuer="):
                    issuer = line.replace("issuer=", "").strip()

            if not not_after:
                return CertificateHealth(
                    domain=domain,
                    key_type=key_type,
                    status=HealthStatus.UNKNOWN,
                    message="Could not parse certificate expiry date",
                    cert_path=str(cert_path),
                )

            # Calculate days until expiry
            now = datetime.datetime.now()
            days_until_expiry = (not_after - now).days

            # Determine status
            if days_until_expiry < 0:
                status = HealthStatus.CRITICAL
                message = f"Certificate EXPIRED {abs(days_until_expiry)} days ago"
            elif days_until_expiry < self.critical_days:
                status = HealthStatus.CRITICAL
                message = f"Certificate expires in {days_until_expiry} days (CRITICAL)"
            elif days_until_expiry < self.warning_days:
                status = HealthStatus.WARNING
                message = f"Certificate expires in {days_until_expiry} days"
            else:
                status = HealthStatus.HEALTHY
                message = f"Certificate valid for {days_until_expiry} days"

            return CertificateHealth(
                domain=domain,
                key_type=key_type,
                status=status,
                message=message,
                cert_path=str(cert_path),
                days_until_expiry=days_until_expiry,
                not_after=not_after,
                issuer=issuer,
            )

        except subprocess.TimeoutExpired:
            return CertificateHealth(
                domain=domain,
                key_type=key_type,
                status=HealthStatus.UNKNOWN,
                message="Certificate check timed out",
                cert_path=str(cert_path),
            )
        except Exception as e:
            return CertificateHealth(
                domain=domain,
                key_type=key_type,
                status=HealthStatus.UNKNOWN,
                message=f"Error checking certificate: {e}",
                cert_path=str(cert_path),
            )

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
            not_after_str = cert.get("notAfter", "")
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
            issuer_parts = cert.get("issuer", ())
            issuer = None
            for part in issuer_parts:
                for key, value in part:
                    if key == "organizationName":
                        issuer = value
                        break

            # Calculate days
            now = datetime.datetime.now()
            days_until_expiry = (not_after - now).days

            # Determine status
            if days_until_expiry < 0:
                status = HealthStatus.CRITICAL
                message = f"Live certificate EXPIRED {abs(days_until_expiry)} days ago"
            elif days_until_expiry < self.critical_days:
                status = HealthStatus.CRITICAL
                message = f"Live certificate expires in {days_until_expiry} days (CRITICAL)"
            elif days_until_expiry < self.warning_days:
                status = HealthStatus.WARNING
                message = f"Live certificate expires in {days_until_expiry} days"
            else:
                status = HealthStatus.HEALTHY
                message = f"Live certificate valid for {days_until_expiry} days"

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
        worst_status = HealthStatus.HEALTHY

        for domain_config in domains:
            for key_type in key_types:
                # Construct cert path based on config
                from .config import KeyType
                kt = KeyType.from_string(key_type)
                cert_path = Path(self.config.get_cert_path(domain_config, kt))

                health = self.check_certificate_file(
                    cert_path,
                    domain_config.primary_domain,
                    key_type,
                )
                certificates.append(health)

                # Track worst status
                if health.status == HealthStatus.CRITICAL:
                    worst_status = HealthStatus.CRITICAL
                elif health.status == HealthStatus.WARNING and worst_status != HealthStatus.CRITICAL:
                    worst_status = HealthStatus.WARNING
                elif health.status == HealthStatus.UNKNOWN and worst_status == HealthStatus.HEALTHY:
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
                if cert.days_until_expiry is not None:
                    self.notification_manager.notify_expiry_warning(
                        cert.domain,
                        cert.days_until_expiry,
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
                lines.append(f"lematt_certificate_expiry_days{{{labels}}} {cert.days_until_expiry}")

        lines.extend([
            "",
            "# HELP lematt_certificate_status Certificate health status (0=healthy, 1=warning, 2=critical, 3=unknown)",
            "# TYPE lematt_certificate_status gauge",
        ])

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

        lines.extend([
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
        ])

        return "\n".join(lines) + "\n"


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
    return '''#!/bin/bash
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
'''
