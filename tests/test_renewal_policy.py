"""Renewal decisions: ARI, lifetime fallback, operator overrides, backoff."""

import datetime

import pytest

from lematt.config import CertificateInfo
from lematt.renewal import RenewalSettings, backoff_until, decide
from lematt.state import AttemptState, CertState, RenewalInfoState

DAY = datetime.timedelta(days=1)
ISSUED = datetime.datetime(2026, 10, 1)


def cert(lifetime_days: float, serial: str = "0a") -> CertificateInfo:
    return CertificateInfo(
        exists=True,
        path="cert.pem",
        not_before=ISSUED,
        not_after=ISSUED + lifetime_days * DAY,
        serial_hex=serial,
    )


def with_ari(selected: datetime.datetime, serial: str = "0a") -> CertState:
    return CertState(
        cert_id="c",
        renewal_info=RenewalInfoState(
            serial=serial,
            window_start=selected - DAY,
            window_end=selected + DAY,
            selected_time=selected,
            fetched_at=ISSUED,
            next_check=ISSUED,
        ),
    )


@pytest.mark.parametrize(
    ("lifetime", "due_after_issue"),
    [
        (90, 60),  # 1/3 of 90 days left
        (64, 64 * 2 / 3),  # classic profile from 2027-02-10
        (45, 30),  # tlsserver / classic from 2028-02-16
        (160 / 24, 80 / 24),  # shortlived: half of 160 hours
    ],
)
def test_lifetime_fallback_follows_lets_encrypt_guidance(lifetime, due_after_issue):
    info = cert(lifetime)
    due = ISSUED + due_after_issue * DAY

    before = decide(info, None, due - datetime.timedelta(minutes=1))
    after = decide(info, None, due + datetime.timedelta(minutes=1))

    assert (before.renew, before.basis, before.due_at) == (False, "lifetime", due)
    assert (after.renew, after.basis) == (True, "lifetime")


def test_ari_window_takes_precedence_over_lifetime():
    selected = ISSUED + 50 * DAY  # earlier than the 60-day lifetime point
    state = with_ari(selected)

    decision = decide(cert(90), state, ISSUED + 55 * DAY)

    assert (decision.renew, decision.basis, decision.due_at) == (True, "ari", selected)


def test_ari_data_for_a_previous_certificate_is_ignored():
    state = with_ari(ISSUED + 5 * DAY, serial="old")

    decision = decide(cert(90, serial="new"), state, ISSUED + 10 * DAY)

    assert (decision.renew, decision.basis) == (False, "lifetime")


def test_operator_overrides_only_move_renewal_earlier():
    settings = RenewalSettings(reauthorize_days=45)  # 45 days left > 30
    decision = decide(cert(90), None, ISSUED + 50 * DAY, settings)
    assert (decision.renew, decision.basis) == (True, "reauthorizeDays")

    later = RenewalSettings(reauthorize_days=10)  # later than LE's 30 days left
    decision = decide(cert(90), None, ISSUED + 70 * DAY, later)
    assert (decision.renew, decision.basis) == (True, "lifetime")

    by_age = RenewalSettings(generate_new_certs_after_days=7)
    decision = decide(cert(90), None, ISSUED + 8 * DAY, by_age)
    assert (decision.renew, decision.basis) == (True, "generateNewCertsAfterDays")


def test_reauthorize_days_longer_than_lifetime_is_ignored_with_a_note():
    # The example config's reauthorizeDays: 60 against a 45-day certificate
    settings = RenewalSettings(reauthorize_days=60)

    decision = decide(cert(45), None, ISSUED + 1 * DAY, settings)

    assert (decision.renew, decision.basis) == (False, "lifetime")
    assert "would renew on every run" in decision.notes[0]


def test_backoff_blocks_due_renewals_until_it_expires():
    state = CertState(
        cert_id="c",
        attempts=AttemptState(
            consecutive_failures=2, next_attempt_after=ISSUED + 61 * DAY
        ),
    )

    blocked = decide(cert(90), state, ISSUED + 60.5 * DAY)
    allowed = decide(cert(90), state, ISSUED + 61.1 * DAY)

    assert (blocked.renew, blocked.blocked_until) == (False, ISSUED + 61 * DAY)
    assert "backing off after 2 failure(s)" in blocked.reason
    assert allowed.renew


def test_missing_unreadable_and_forced_renew_immediately():
    missing = CertificateInfo(exists=False, path="x")
    unreadable = CertificateInfo(exists=True, path="x", parse_error="bad PEM")

    assert decide(missing, None, ISSUED).basis == "missing"
    assert decide(unreadable, None, ISSUED).basis == "unreadable"
    forced = decide(cert(90), None, ISSUED, force=True)
    assert (forced.renew, forced.basis) == (True, "forced")


def test_expired_certificates_renew_unless_backing_off():
    expired_now = ISSUED + 91 * DAY
    assert decide(cert(90), None, expired_now).reason == "certificate expired"

    state = CertState(
        cert_id="c",
        attempts=AttemptState(
            consecutive_failures=5, next_attempt_after=expired_now + DAY
        ),
    )
    decision = decide(cert(90), state, expired_now)
    assert not decision.renew
    assert decision.reason.startswith("expired since")


@pytest.mark.parametrize(
    ("failures", "retry_after", "wait"),
    [
        (1, None, datetime.timedelta(minutes=1)),
        (2, None, datetime.timedelta(minutes=10)),
        (3, None, datetime.timedelta(minutes=100)),
        (9, None, DAY),
        (1, 7200, datetime.timedelta(hours=2)),  # rate limit Retry-After wins
    ],
)
def test_backoff_schedule(failures, retry_after, wait):
    assert backoff_until(failures, ISSUED, retry_after) == ISSUED + wait
