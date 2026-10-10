"""When to renew a certificate: one pure decision used everywhere.

Precedence:

1. No usable certificate (missing, unreadable): renew now.
2. ``--force-renew``: renew now.
3. The due time is the earliest of:
   - the CA's ARI window (RFC 9773), at the random moment lematt picked
     inside it, or, without ARI data for this certificate, Let's
     Encrypt's guidance: renew with 1/3 of the lifetime left (1/2 for
     certificates valid less than 10 days);
   - the operator's ``generateNewCertsAfterDays`` (renew at that age);
   - the operator's ``reauthorizeDays`` (renew with that many days left),
     unless it is at least the certificate's whole lifetime: that would
     renew on every run and burn through rate limits, so it is ignored
     with a note.
4. Past the due time, renew unless a previous failure's backoff is
   still in effect.

Renewal runs, ``--status``, health checks and reports all ask this module,
so they agree about what will happen and why.
"""

import datetime
from dataclasses import dataclass, field

from lematt.config import CertificateInfo
from lematt.state import CertState

DAY = datetime.timedelta(days=1)

# Let's Encrypt integration guide: renew with 1/3 of the lifetime left,
# or halfway through for certificates valid less than 10 days
SHORT_LIVED = datetime.timedelta(days=10)

# Waits after consecutive failures (1, 2, 3, 4+), per Let's Encrypt's
# integration guide: 1 minute, 10 minutes, 100 minutes, then daily
FAILURE_BACKOFF = (
    datetime.timedelta(minutes=1),
    datetime.timedelta(minutes=10),
    datetime.timedelta(minutes=100),
    datetime.timedelta(days=1),
)


@dataclass(frozen=True)
class RenewalSettings:
    """Operator overrides that can move renewal earlier."""

    reauthorize_days: float | None = None
    generate_new_certs_after_days: float = 0.0


@dataclass(frozen=True)
class RenewalDecision:
    """Whether to renew now, when it's due, and why.

    Attributes:
        basis: What set the due time: "missing", "unreadable", "forced",
            "ari", "lifetime", "reauthorizeDays" or
            "generateNewCertsAfterDays".
        blocked_until: Set when renewal is due but backing off after
            failures.
        notes: Configuration problems worth telling the operator about.
    """

    renew: bool
    basis: str
    reason: str
    due_at: datetime.datetime | None = None
    blocked_until: datetime.datetime | None = None
    notes: tuple[str, ...] = field(default=())


DEFAULT_SETTINGS = RenewalSettings()


def recommended_due(
    info: CertificateInfo, state: CertState | None
) -> tuple[datetime.datetime, str]:
    """The CA-recommended renewal time and its basis ("ari" or "lifetime")."""
    assert info.not_before is not None and info.not_after is not None
    ari = state.renewal_info if state else None
    if (
        ari is not None
        and info.serial_hex is not None
        and ari.serial == info.serial_hex
    ):
        return ari.selected_time, "ari"
    lifetime = info.not_after - info.not_before
    if lifetime < SHORT_LIVED:
        return info.not_before + lifetime / 2, "lifetime"
    return info.not_after - lifetime / 3, "lifetime"


def backoff_until(
    consecutive_failures: int,
    now: datetime.datetime,
    retry_after: float | None = None,
) -> datetime.datetime:
    """When the next attempt is allowed after ``consecutive_failures``.

    A server-provided Retry-After (e.g. a rate limit) extends the wait.
    """
    step = FAILURE_BACKOFF[min(max(consecutive_failures, 1), len(FAILURE_BACKOFF)) - 1]
    if retry_after is not None:
        step = max(step, datetime.timedelta(seconds=retry_after))
    return now + step


def _when(moment: datetime.datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def decide(
    info: CertificateInfo,
    state: CertState | None,
    now: datetime.datetime,
    settings: RenewalSettings = DEFAULT_SETTINGS,
    *,
    force: bool = False,
) -> RenewalDecision:
    """Decide whether ``info``'s certificate should be renewed at ``now``."""
    if not info.exists:
        return RenewalDecision(True, "missing", "no certificate yet")
    if info.parse_error or info.not_after is None or info.not_before is None:
        return RenewalDecision(
            True, "unreadable", f"certificate unreadable: {info.parse_error}"
        )
    if force:
        return RenewalDecision(True, "forced", "renewal forced (--force-renew)")

    due, basis = recommended_due(info, state)
    notes: list[str] = []
    lifetime = info.not_after - info.not_before

    if settings.generate_new_certs_after_days > 0:
        by_age = info.not_before + settings.generate_new_certs_after_days * DAY
        if by_age < due:
            due, basis = by_age, "generateNewCertsAfterDays"

    if settings.reauthorize_days is not None:
        days_left = settings.reauthorize_days * DAY
        if days_left >= lifetime:
            notes.append(
                f"reauthorizeDays={settings.reauthorize_days:g} is not shorter than "
                f"this certificate's {lifetime / DAY:.0f}-day lifetime, so it would "
                "renew on every run; ignoring it for this certificate"
            )
        elif info.not_after - days_left < due:
            due, basis = info.not_after - days_left, "reauthorizeDays"

    expired = info.not_after <= now
    if due > now and not expired:
        return RenewalDecision(
            False,
            basis,
            f"next renewal {_when(due)} ({basis})",
            due_at=due,
            notes=tuple(notes),
        )

    attempts = state.attempts if state else None
    if attempts and attempts.next_attempt_after and now < attempts.next_attempt_after:
        return RenewalDecision(
            False,
            basis,
            f"{'expired' if expired else 'due'} since "
            f"{_when(info.not_after if expired else due)}, but backing off after "
            f"{attempts.consecutive_failures} failure(s) until "
            f"{_when(attempts.next_attempt_after)}",
            due_at=due,
            blocked_until=attempts.next_attempt_after,
            notes=tuple(notes),
        )

    reason = "certificate expired" if expired else f"due since {_when(due)} ({basis})"
    return RenewalDecision(True, basis, reason, due_at=due, notes=tuple(notes))
