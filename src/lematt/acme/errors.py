"""ACME problem documents (RFC 8555 section 6.7) as typed exceptions."""

import datetime
import email.utils
from collections.abc import Mapping
from typing import Any

PROBLEM_PREFIX = "urn:ietf:params:acme:error:"


def parse_retry_after(
    value: str | None, now: datetime.datetime | None = None
) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP-date)."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except TypeError, ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.UTC)
    now = now or datetime.datetime.now(datetime.UTC)
    return max(0.0, (when - now).total_seconds())


class AcmeError(Exception):
    """An ACME request failed.

    Attributes:
        problem: Problem type without the ACME URN prefix (e.g. "rateLimited").
        detail: Human-readable detail from the server.
        status: HTTP status code (None for client-side protocol errors).
        retry_after: Seconds the server asked us to wait, if it said.
        retryable: Whether retrying the same request later can succeed.
    """

    retryable = False

    def __init__(
        self,
        problem: str,
        detail: str,
        *,
        status: int | None = None,
        retry_after: float | None = None,
        document: Mapping[str, Any] | None = None,
    ) -> None:
        self.problem = problem
        self.detail = detail
        self.status = status
        self.retry_after = retry_after
        self.document = dict(document or {})
        super().__init__(self._describe())

    def _describe(self) -> str:
        text = f"{self.problem}: {self.detail}" if self.problem else self.detail
        for sub in self.document.get("subproblems", []):
            ident = sub.get("identifier", {}).get("value", "?")
            text += f"; {ident}: {sub.get('detail', '')}"
        if self.retry_after is not None:
            text += f" (retry after {self.retry_after:.0f}s)"
        return text


class BadNonceError(AcmeError):
    """The nonce was rejected; resending with a fresh nonce succeeds."""

    retryable = True


class RateLimitedError(AcmeError):
    """A Let's Encrypt rate limit was hit; wait ``retry_after`` seconds."""


class AlreadyReplacedError(AcmeError):
    """The order's ``replaces`` certificate was already replaced (RFC 9773)."""


class ServerError(AcmeError):
    """Temporary server-side failure (5xx / serverInternal)."""

    retryable = True


class AcmeProtocolError(AcmeError):
    """The server's response didn't follow the ACME protocol."""


class ChallengeError(AcmeError):
    """Domain validation failed, or the challenge couldn't be prepared."""


_BY_PROBLEM: dict[str, type[AcmeError]] = {
    "badNonce": BadNonceError,
    "rateLimited": RateLimitedError,
    "alreadyReplaced": AlreadyReplacedError,
    "serverInternal": ServerError,
}


def error_from_response(
    status: int, headers: Mapping[str, str], body: Any
) -> AcmeError:
    """Build the most specific AcmeError for an HTTP error response."""
    document = body if isinstance(body, dict) else {}
    problem = str(document.get("type", ""))
    problem = problem.removeprefix(PROBLEM_PREFIX)
    detail = str(document.get("detail") or body or f"HTTP {status}")
    retry_after = parse_retry_after(headers.get("Retry-After"))

    cls = _BY_PROBLEM.get(problem)
    if cls is None:
        cls = ServerError if status >= 500 else AcmeError
    return cls(
        problem, detail, status=status, retry_after=retry_after, document=document
    )
