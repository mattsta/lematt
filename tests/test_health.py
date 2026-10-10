"""Health checks: lifetime- and state-aware by default, fixed days on request."""

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from lematt.config import DomainConfig, KeyType, LemattConfig
from lematt.health import HealthChecker, HealthStatus, PrometheusMetrics
from lematt.state import AttemptState, CertState, StateStore

DOMAIN = DomainConfig("example.com")
NOW = datetime.datetime.now(datetime.UTC).replace(tzinfo=None, microsecond=0)


@pytest.fixture
def config(tmp_path):
    config = LemattConfig(config_base=str(tmp_path), challenge_dir="", account_key="")
    for sub in ("cert", "state"):
        (tmp_path / "prod" / sub).mkdir(parents=True)
    return config


def write_cert(config, key_type, *, lifetime_days: float, days_left: float) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    not_after = NOW + datetime.timedelta(days=days_left)
    not_before = not_after - datetime.timedelta(days=lifetime_days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    path = config.get_cert_path(DOMAIN, key_type)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))


def check(config, **thresholds):
    health = HealthChecker(config=config, **thresholds).check_all_certificates([DOMAIN])
    return {c.key_type: c for c in health.certificates}, health


def test_status_follows_lifetime_and_renewal_state(config):
    write_cert(config, KeyType.RSA, lifetime_days=45, days_left=40)  # fresh
    write_cert(config, KeyType.EC, lifetime_days=90, days_left=20)  # due at 30 left

    certs, health = check(config)

    assert certs["rsa"].status == HealthStatus.HEALTHY
    assert "renews" in certs["rsa"].message
    assert certs["ec"].status == HealthStatus.WARNING
    assert certs["ec"].message.startswith("Renewal overdue since")
    assert health.status == HealthStatus.WARNING


def test_overdue_warning_explains_failures(config):
    write_cert(config, KeyType.RSA, lifetime_days=90, days_left=20)
    write_cert(config, KeyType.EC, lifetime_days=90, days_left=5)
    StateStore(Path(config.state_dir)).save_cert(
        CertState(
            cert_id=config.cert_id(DOMAIN, KeyType.RSA),
            attempts=AttemptState(
                consecutive_failures=3, last_error="rateLimited: slow down"
            ),
        )
    )

    certs, health = check(config)

    assert "3 failed attempt(s): rateLimited: slow down" in certs["rsa"].message
    assert certs["rsa"].consecutive_failures == 3
    assert certs["ec"].status == HealthStatus.CRITICAL  # < 1/10 of 90 days left
    assert health.status == HealthStatus.CRITICAL


def test_short_lived_certificates_are_judged_by_their_own_lifetime(config):
    write_cert(config, KeyType.RSA, lifetime_days=160 / 24, days_left=5)  # 6-day cert
    write_cert(config, KeyType.EC, lifetime_days=160 / 24, days_left=0.5)

    certs, _ = check(config)

    assert certs["rsa"].status == HealthStatus.HEALTHY  # fixed 7-day rule: critical
    assert certs["ec"].status == HealthStatus.CRITICAL


def test_explicit_day_thresholds_keep_the_classic_behavior(config):
    write_cert(config, KeyType.RSA, lifetime_days=90, days_left=20)
    write_cert(config, KeyType.EC, lifetime_days=90, days_left=10)

    certs, _ = check(config, warning_days=14, critical_days=7)

    assert certs["rsa"].status == HealthStatus.HEALTHY
    assert certs["ec"].status == HealthStatus.WARNING


def test_prometheus_exposes_renewal_state(config):
    write_cert(config, KeyType.RSA, lifetime_days=90, days_left=60)
    write_cert(config, KeyType.EC, lifetime_days=90, days_left=60)

    _, health = check(config)
    metrics = PrometheusMetrics(health).generate()

    labels = 'domain="example.com",key_type="rsa"'
    due = NOW + datetime.timedelta(days=30)  # 1/3 of 90 days before expiry
    assert (
        f"lematt_certificate_renewal_due_timestamp_seconds{{{labels}}} "
        f"{due.replace(tzinfo=datetime.UTC).timestamp():.0f}"
    ) in metrics
    assert f"lematt_certificate_renewal_failures{{{labels}}} 0" in metrics
    assert "lematt_certificate_expiry_timestamp_seconds{" in metrics


@pytest.mark.parametrize(
    ("days_left", "status"),
    [
        (60, HealthStatus.HEALTHY),
        (20, HealthStatus.WARNING),
        (5, HealthStatus.CRITICAL),
    ],
)
def test_served_certificates_should_have_been_replaced(days_left, status):
    result, _ = HealthChecker._classify_served(
        datetime.timedelta(days=days_left), datetime.timedelta(days=90)
    )
    assert result == status


def test_report_schedule_uses_the_renewal_policy(config):
    from lematt.reports import ReportGenerator

    write_cert(config, KeyType.RSA, lifetime_days=45, days_left=40)
    write_cert(config, KeyType.EC, lifetime_days=45, days_left=40)
    config.domains = [DOMAIN]
    config.key_types = list(KeyType)
    _, health = check(config)

    schedule = ReportGenerator(config, health).build_renewal_schedule()

    due = NOW + datetime.timedelta(days=40 - 15)  # 1/3 of 45 days before expiry
    assert {item.renewal_date for item in schedule} == {due}
    assert {item.priority for item in schedule} == {"ok"}
