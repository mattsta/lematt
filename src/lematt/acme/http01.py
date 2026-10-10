"""http-01 challenge handling via a shared webroot directory."""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from lematt.acme.errors import ChallengeError

# RFC 8555 section 8.3: tokens are base64url without padding
_TOKEN = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass
class Http01Solver:
    """Publishes key authorizations as files in ``challenge_dir``.

    ``challenge_dir`` must be served at
    ``http://<domain>/.well-known/acme-challenge/`` for every domain (directly
    or via redirects, e.g. a prepare action running contrib/leforward.py).
    Before asking the CA to validate, the solver fetches the file itself so
    misconfigurations fail fast without spending the CA's failed-validation
    rate limit.
    """

    challenge_dir: Path
    self_check: bool = True
    client: httpx.Client = field(
        # Like the CA: follow redirects (including to https) without judging
        # the target's certificate, which may be the expired one being renewed
        default_factory=lambda: httpx.Client(
            timeout=10.0, follow_redirects=True, verify=False
        )
    )
    # Prepare actions (e.g. a remote leforward.py over ssh) start
    # asynchronously and may not be listening yet when the challenge is
    # published, so connection failures are retried briefly. Wrong content is
    # a real misconfiguration and fails immediately.
    connect_retry_delays: tuple[float, ...] = (0.5, 1.0, 2.0, 4.0)
    sleep: Callable[[float], None] = time.sleep

    def path(self, token: str) -> Path:
        if not _TOKEN.match(token):
            raise ChallengeError(
                "malformed", f"refusing unsafe challenge token {token!r}"
            )
        return self.challenge_dir / token

    def present(self, domain: str, token: str, key_authorization: str) -> None:
        """Write the challenge file and (optionally) confirm it is reachable."""
        path = self.path(token)
        try:
            path.write_text(key_authorization)
        except OSError as e:
            raise ChallengeError(
                "io", f"cannot write challenge file {path}: {e}"
            ) from e

        if not self.self_check:
            return
        url = f"http://{domain}/.well-known/acme-challenge/{token}"
        response = self._fetch(url)
        if response.status_code != 200 or response.text.strip() != key_authorization:
            raise ChallengeError(
                "unauthorized",
                f"challenge at {url} returned HTTP {response.status_code} with "
                f"unexpected content (is challengeDropDir served there?)",
            )

    def _fetch(self, url: str) -> httpx.Response:
        """GET the challenge, retrying connection-level failures briefly."""
        for delay in (*self.connect_retry_delays, None):
            try:
                return self.client.get(url)
            except httpx.TransportError as e:
                if delay is None:
                    raise ChallengeError(
                        "connection", f"challenge not reachable at {url}: {e}"
                    ) from e
                self.sleep(delay)
            except httpx.HTTPError as e:
                raise ChallengeError(
                    "connection", f"challenge not reachable at {url}: {e}"
                ) from e
        raise AssertionError("unreachable")

    def cleanup(self, token: str) -> None:
        self.path(token).unlink(missing_ok=True)
