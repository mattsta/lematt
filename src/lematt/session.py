"""A shared ACME session: one transport and one account per unit of work.

A domain's RSA and EC certificates (and its ARI checks) go through the same
session, so they share the directory, nonces and account. The account URL
is persisted in the state store, so later runs skip registration entirely.
"""

from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from lematt.acme import AccountKey, AcmeClient, AcmeTransport, Http01Solver
from lematt.state import AccountState, StateStore, utcnow


def make_transport(directory_url: str, account_key: AccountKey) -> AcmeTransport:
    """Create the HTTP transport for an ACME directory (replaceable in tests)."""
    return AcmeTransport(directory_url, account_key)


def make_solver(challenge_dir: str) -> Http01Solver:
    """Create the http-01 challenge solver (replaceable in tests)."""
    return Http01Solver(Path(challenge_dir))


@dataclass
class AcmeSession:
    """Lazily connects to the CA and resolves the account once."""

    directory_url: str
    account_key_path: str
    challenge_dir: str
    store: StateStore
    _transport: AcmeTransport | None = field(default=None, repr=False)

    @property
    def transport(self) -> AcmeTransport:
        if self._transport is None:
            key = AccountKey.from_file(self.account_key_path)
            self._transport = make_transport(self.directory_url, key)
        return self._transport

    def solver(self) -> Http01Solver:
        return make_solver(self.challenge_dir)

    def ensure_account(self) -> str:
        """The account URL: from this session, saved state, or registration."""
        transport = self.transport
        if transport.kid:
            return transport.kid
        thumbprint = transport.account_key.thumbprint
        saved = self.store.load_account(self.directory_url, thumbprint)
        if saved is not None:
            transport.kid = saved.account_url
            return saved.account_url

        url = AcmeClient(transport).register_account()
        self.store.save_account(
            AccountState(self.directory_url, thumbprint, url, registered_at=utcnow())
        )
        self.store.record("account_registered", account_url=url)
        return url

    def forget_account(self) -> None:
        """Drop a stored account the CA no longer recognizes."""
        logger.warning("The CA no longer recognizes the saved account; re-registering")
        self.transport.kid = None
        self.store.forget_account()
