"""ACME Renewal Information (ARI, RFC 9773): the CA's suggested renewal window."""

import datetime
import random
from dataclasses import dataclass
from typing import Any

from lematt.acme.errors import AcmeError, AcmeProtocolError, parse_retry_after
from lematt.acme.transport import AcmeTransport

# RFC 9773 section 4.3: clients must bound how often they poll. Without a
# usable Retry-After, check again after six hours.
MIN_CHECK_INTERVAL = 60.0
MAX_CHECK_INTERVAL = 86_400.0
DEFAULT_CHECK_INTERVAL = 6 * 3600.0


@dataclass(frozen=True)
class RenewalInfo:
    """A suggested renewal window (naive UTC) and when to ask again."""

    window_start: datetime.datetime
    window_end: datetime.datetime
    check_after: float  # seconds until the next renewalInfo request
    explanation_url: str | None = None

    def select_time(self, rng: random.Random | None = None) -> datetime.datetime:
        """A uniformly random moment in the window (RFC 9773 section 4.2)."""
        span = (self.window_end - self.window_start).total_seconds()
        offset = (rng or random).uniform(0, span)
        return self.window_start + datetime.timedelta(seconds=offset)


def _timestamp(value: Any) -> datetime.datetime:
    moment = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.UTC)
    return moment.astimezone(datetime.UTC).replace(tzinfo=None)


def fetch_renewal_info(transport: AcmeTransport, cert_id: str) -> RenewalInfo:
    """GET the renewalInfo resource for an RFC 9773 certificate identifier.

    Raises:
        AcmeError: The CA doesn't support ARI, or the request failed.
        AcmeProtocolError: The response isn't a valid RenewalInfo object.
    """
    endpoint = transport.directory.renewal_info
    if not endpoint:
        raise AcmeError(
            "unsupported", "the CA does not offer renewal information (ARI)"
        )

    response = transport.get(f"{endpoint.rstrip('/')}/{cert_id}")
    try:
        data = response.json()
        window = data["suggestedWindow"]
        start, end = _timestamp(window["start"]), _timestamp(window["end"])
    except (ValueError, KeyError, TypeError) as e:
        raise AcmeProtocolError("", f"invalid renewalInfo for {cert_id}: {e}") from e
    if end <= start:
        raise AcmeProtocolError(
            "", f"renewalInfo window for {cert_id} ends before it starts"
        )

    check_after = parse_retry_after(response.headers.get("Retry-After"))
    if check_after is None:
        check_after = DEFAULT_CHECK_INTERVAL
    check_after = min(max(check_after, MIN_CHECK_INTERVAL), MAX_CHECK_INTERVAL)

    explanation = data.get("explanationURL")
    return RenewalInfo(
        window_start=start,
        window_end=end,
        check_after=check_after,
        explanation_url=str(explanation) if explanation else None,
    )
