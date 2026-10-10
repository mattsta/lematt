"""ACME certificate issuance (RFC 8555) against Let's Encrypt.

Flow: register (or look up) the account, create an order, satisfy each
pending authorization with http-01, finalize with the CSR, poll until the
certificate is issued, then download the chain.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from loguru import logger

from lematt.acme.errors import (
    AcmeError,
    AcmeProtocolError,
    ChallengeError,
    parse_retry_after,
)
from lematt.acme.http01 import Http01Solver
from lematt.acme.jws import AccountKey, b64url
from lematt.acme.transport import AcmeTransport, links

PEM_CHAIN = "application/pem-certificate-chain"

# Bounds for honoring Retry-After while polling orders and authorizations
MIN_POLL_DELAY = 1.0
MAX_POLL_DELAY = 60.0


class ChallengeSolver(Protocol):
    def present(self, domain: str, token: str, key_authorization: str) -> None: ...
    def cleanup(self, token: str) -> None: ...


@dataclass
class Order:
    """An ACME order resource."""

    url: str
    data: dict[str, Any]

    @property
    def status(self) -> str:
        return str(self.data.get("status", ""))

    @property
    def authorizations(self) -> list[str]:
        return list(self.data.get("authorizations", []))

    def require(self, key: str) -> str:
        value = self.data.get(key)
        if not isinstance(value, str):
            raise AcmeProtocolError("", f"order {self.url} has no '{key}' URL")
        return value


@dataclass(frozen=True)
class IssuedCertificate:
    """A downloaded certificate chain (leaf first) and where it came from."""

    pem: str
    order_url: str
    alternate_urls: tuple[str, ...] = ()


def csr_names(csr_pem: bytes) -> list[str]:
    """The DNS names a CSR requests (SANs, else the Subject CN)."""
    csr = x509.load_pem_x509_csr(csr_pem)
    try:
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    if not names:
        names = [
            str(a.value)
            for a in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ]
    if not names:
        raise ValueError("CSR requests no DNS names")
    return list(dict.fromkeys(names))


@dataclass
class AcmeClient:
    """Drives ACME orders over an :class:`AcmeTransport`."""

    transport: AcmeTransport
    context: str = ""
    poll_timeout: float = 300.0
    poll_interval: float = 2.0
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)

    def log(self, message: str) -> None:
        logger.info(f"[{self.context}] {message}" if self.context else message)

    def register_account(self) -> str:
        """Create the account (or find the existing one); return its URL."""
        response = self.transport.post(
            self.transport.directory.new_account, {"termsOfServiceAgreed": True}
        )
        url: str | None = response.headers.get("Location")
        if not url:
            raise AcmeProtocolError("", "newAccount response has no Location header")
        self.transport.kid = url
        self.log(
            "Account registered" if response.status_code == 201 else "Account found"
        )
        return url

    def new_order(
        self,
        names: list[str],
        *,
        profile: str | None = None,
        replaces: str | None = None,
    ) -> Order:
        """Create an order for ``names``.

        Args:
            profile: Certificate profile (must be advertised by the server).
            replaces: ARI certificate ID of the certificate being renewed.
        """
        directory = self.transport.directory
        payload: dict[str, Any] = {
            "identifiers": [{"type": "dns", "value": name} for name in names]
        }
        if profile:
            if profile not in directory.profiles:
                offered = ", ".join(sorted(directory.profiles)) or "none"
                raise AcmeError(
                    "invalidProfile",
                    f"profile '{profile}' is not offered by the CA (offered: {offered})",
                )
            payload["profile"] = profile
        if replaces and directory.renewal_info:
            payload["replaces"] = replaces

        response = self.transport.post(directory.new_order, payload)
        url: str | None = response.headers.get("Location")
        if not url:
            raise AcmeProtocolError("", "newOrder response has no Location header")
        self.log(f"Order created for {', '.join(names)}")
        return Order(url, response.json())

    def complete_authorizations(self, order: Order, solver: ChallengeSolver) -> None:
        """Satisfy every pending authorization of ``order`` with http-01."""
        for auth_url in order.authorizations:
            authz = self.transport.post(auth_url, None).json()
            domain = authz["identifier"]["value"]
            if authz["status"] == "valid":
                self.log(f"✓ {domain} already validated")
                continue
            if authz["status"] != "pending":
                raise ChallengeError(
                    "unauthorized", f"authorization for {domain} is {authz['status']}"
                )

            challenge = next(
                (c for c in authz.get("challenges", []) if c.get("type") == "http-01"),
                None,
            )
            if challenge is None:
                raise ChallengeError(
                    "unsupported", f"no http-01 challenge for {domain}"
                )

            token = challenge["token"]
            key_authorization = self.transport.account_key.key_authorization(token)
            self.log(f"Validating {domain}")
            try:
                solver.present(domain, token, key_authorization)
                self.transport.post(challenge["url"], {})
                authz = self._poll(auth_url, {"pending"})
            finally:
                solver.cleanup(token)

            if authz["status"] != "valid":
                raise self._authorization_error(domain, authz)
            self.log(f"✓ {domain} validated")

    @staticmethod
    def _authorization_error(domain: str, authz: dict[str, Any]) -> ChallengeError:
        for challenge in authz.get("challenges", []):
            if error := challenge.get("error"):
                problem = str(error.get("type", "")).rsplit(":", 1)[-1]
                return ChallengeError(
                    problem, f"{domain}: {error.get('detail', '')}", document=error
                )
        return ChallengeError(
            "unauthorized", f"{domain}: authorization {authz['status']}"
        )

    def finalize(self, order: Order, csr_pem: bytes) -> Order:
        """Submit the CSR and wait for the certificate to be issued."""
        csr_der = x509.load_pem_x509_csr(csr_pem).public_bytes(Encoding.DER)
        self.transport.post(order.require("finalize"), {"csr": b64url(csr_der)})
        self.log("Waiting for the certificate to be issued")
        data = self._poll(order.url, {"pending", "ready", "processing"})
        if data.get("status") != "valid":
            error = data.get("error") or {}
            raise AcmeError(
                str(error.get("type", "orderInvalid")).rsplit(":", 1)[-1],
                f"order {data.get('status')}: {error.get('detail', '')}",
                document=error,
            )
        return Order(order.url, data)

    def download_certificate(self, order: Order) -> IssuedCertificate:
        response = self.transport.post(
            order.require("certificate"), None, accept=PEM_CHAIN
        )
        return IssuedCertificate(
            pem=response.text,
            order_url=order.url,
            alternate_urls=tuple(links(response, "alternate")),
        )

    def _poll(self, url: str, pending: set[str]) -> dict[str, Any]:
        """POST-as-GET ``url`` until its status leaves ``pending``."""
        deadline = self.clock() + self.poll_timeout
        last_note = self.clock()
        while True:
            response = self.transport.post(url, None)
            data = response.json()
            if data.get("status") not in pending:
                return dict(data)
            now = self.clock()
            if now >= deadline:
                raise AcmeError(
                    "timeout",
                    f"{url} still {data.get('status')} after {self.poll_timeout:.0f}s",
                )
            if now - last_note >= 10:
                self.log(f"⏳ Still waiting ({data.get('status')})")
                last_note = now
            self.sleep(self._poll_delay(response, deadline - now))

    def _poll_delay(self, response: httpx.Response, remaining: float) -> float:
        delay = parse_retry_after(response.headers.get("Retry-After"))
        if delay is None:
            delay = self.poll_interval
        return min(max(delay, MIN_POLL_DELAY), MAX_POLL_DELAY, max(remaining, 0.0))


def issue_certificate(
    *,
    directory_url: str,
    account_key_path: str | Path,
    csr_pem: bytes,
    challenge_dir: str | Path,
    context: str = "",
    profile: str | None = None,
    replaces: str | None = None,
    transport: AcmeTransport | None = None,
    solver: ChallengeSolver | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> IssuedCertificate:
    """Obtain a certificate for a CSR via http-01 and return the PEM chain."""
    transport = transport or AcmeTransport(
        directory_url, AccountKey.from_file(account_key_path)
    )
    client = AcmeClient(transport, context=context, sleep=sleep)
    client.log("🔐 Requesting certificate from the ACME server")

    if transport.kid is None:
        client.register_account()
    order = client.new_order(csr_names(csr_pem), profile=profile, replaces=replaces)
    client.complete_authorizations(order, solver or Http01Solver(Path(challenge_dir)))
    order = client.finalize(order, csr_pem)
    issued = client.download_certificate(order)
    client.log("✅ Certificate issued")
    return issued
