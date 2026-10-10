"""Signed ACME HTTP transport: nonces, JWS, and problem-document errors."""

import json
import re
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

import httpx

from lematt.acme.directory import Directory
from lematt.acme.errors import (
    AcmeError,
    BadNonceError,
    ServerError,
    error_from_response,
)
from lematt.acme.jws import AccountKey

# A rejected nonce is resent with the fresh one the error carries; give up
# if the server keeps rejecting them
MAX_BAD_NONCE_RETRIES = 5

_LINK = re.compile(r'<([^>]*)>\s*;\s*rel="?([^";]+)"?')


def _user_agent() -> str:
    try:
        version = metadata.version("lematt")
    except metadata.PackageNotFoundError:
        version = "dev"
    return f"lematt/{version} (+https://github.com/mattsta/lematt)"


def links(response: httpx.Response, rel: str) -> list[str]:
    """All Link header targets with the given relation (e.g. "alternate")."""
    found: list[str] = []
    for header in response.headers.get_list("link"):
        found.extend(url for url, r in _LINK.findall(header) if r == rel)
    return found


@dataclass
class AcmeTransport:
    """Sends ACME requests for one account key against one directory.

    Every response's ``Replay-Nonce`` is kept for the next request, so a
    run doesn't spend a newNonce round trip per request.
    """

    directory_url: str
    account_key: AccountKey
    client: httpx.Client = field(
        default_factory=lambda: httpx.Client(
            timeout=30.0, headers={"User-Agent": _user_agent()}
        )
    )
    kid: str | None = None
    _directory: Directory | None = field(default=None, repr=False)
    _nonces: list[str] = field(default_factory=list, repr=False)

    @property
    def directory(self) -> Directory:
        if self._directory is None:
            response = self._send("GET", self.directory_url)
            self._directory = Directory.from_json(response.json())
        return self._directory

    def get(self, url: str) -> httpx.Response:
        """Unauthenticated GET (directory, renewal info)."""
        return self._send("GET", url)

    def post(
        self,
        url: str,
        payload: dict[str, Any] | None,
        *,
        accept: str | None = None,
    ) -> httpx.Response:
        """Signed POST; ``payload=None`` sends a POST-as-GET."""
        for attempt in range(MAX_BAD_NONCE_RETRIES + 1):
            body = self.account_key.jws(
                url, payload, nonce=self._take_nonce(), kid=self.kid
            )
            headers = {"Content-Type": "application/jose+json"}
            if accept:
                headers["Accept"] = accept
            try:
                return self._send(
                    "POST", url, content=json.dumps(body), headers=headers
                )
            except BadNonceError:
                if attempt == MAX_BAD_NONCE_RETRIES:
                    raise
        raise AssertionError("unreachable")

    def _take_nonce(self) -> str:
        if self._nonces:
            return self._nonces.pop()
        self._send("HEAD", self.directory.new_nonce)
        if not self._nonces:
            raise AcmeError("", "newNonce response carried no Replay-Nonce header")
        return self._nonces.pop()

    def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self.client.request(method, url, **kwargs)
        except httpx.HTTPError as e:
            raise ServerError("connection", f"{method} {url} failed: {e}") from e
        if nonce := response.headers.get("Replay-Nonce"):
            self._nonces.append(nonce)
        if response.status_code >= 400:
            try:
                body: Any = response.json()
            except ValueError:
                body = response.text
            raise error_from_response(response.status_code, response.headers, body)
        return response
