"""Persistent lematt state: ACME account, per-certificate renewal state, history.

Layout (under ``<config dir>/<prod|test>/state/``)::

    account.json         ACME account URL for (directory, account key)
    certs/<cert>.json    one file per certificate (name set + key type)
    history.jsonl        append-only event log (rotated at 5 MB, between runs)
    run.lock             held for the duration of a renewal run

Every JSON file carries a ``schema`` version and is written atomically, so
a crash never leaves a truncated file. Unknown or corrupt files are
treated as absent (and logged) rather than failing a run.
"""

import datetime
import fcntl
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

from lematt.crypto import write_file_atomically

SCHEMA_VERSION = 1
HISTORY_MAX_BYTES = 5 * 1024 * 1024


def utcnow() -> datetime.datetime:
    """Current time as naive UTC (lematt's internal convention)."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)


def _iso(moment: datetime.datetime | None) -> str | None:
    return None if moment is None else moment.replace(microsecond=0).isoformat() + "Z"


def _parse(value: Any) -> datetime.datetime | None:
    if not value:
        return None
    parsed = datetime.datetime.fromisoformat(str(value).removesuffix("Z"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(datetime.UTC).replace(tzinfo=None)
    return parsed


@dataclass
class IssuedState:
    """The certificate currently on disk, as lematt last issued or saw it."""

    serial: str
    ari_id: str | None
    not_before: datetime.datetime
    not_after: datetime.datetime
    issued_at: datetime.datetime | None = None
    order_url: str | None = None
    profile: str | None = None
    revoked_at: datetime.datetime | None = None
    revocation_reason: str | None = None


@dataclass
class RenewalInfoState:
    """The CA's suggested renewal window (ARI) for the current certificate."""

    serial: str
    window_start: datetime.datetime
    window_end: datetime.datetime
    selected_time: datetime.datetime
    fetched_at: datetime.datetime
    next_check: datetime.datetime
    explanation_url: str | None = None


@dataclass
class AttemptState:
    """Outcome of renewal attempts, for backoff and monitoring."""

    last_attempt: datetime.datetime | None = None
    last_success: datetime.datetime | None = None
    last_failure: datetime.datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0
    next_attempt_after: datetime.datetime | None = None


@dataclass
class CertState:
    """Everything lematt remembers about one certificate."""

    cert_id: str
    names: list[str] = field(default_factory=list)
    key_type: str = ""
    issued: IssuedState | None = None
    renewal_info: RenewalInfoState | None = None
    attempts: AttemptState = field(default_factory=AttemptState)

    def to_json(self) -> dict[str, Any]:
        encoded: dict[str, Any] = _encode(asdict(self))
        encoded["schema"] = SCHEMA_VERSION
        return encoded

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> CertState:
        issued = data.get("issued")
        info = data.get("renewal_info")
        attempts = data.get("attempts") or {}
        return cls(
            cert_id=data["cert_id"],
            names=list(data.get("names", [])),
            key_type=data.get("key_type", ""),
            issued=IssuedState(**_decode(issued, IssuedState)) if issued else None,
            renewal_info=RenewalInfoState(**_decode(info, RenewalInfoState))
            if info
            else None,
            attempts=AttemptState(**_decode(attempts, AttemptState)),
        )


_DATETIME_FIELDS = {
    IssuedState: ("not_before", "not_after", "issued_at", "revoked_at"),
    RenewalInfoState: (
        "window_start",
        "window_end",
        "selected_time",
        "fetched_at",
        "next_check",
    ),
    AttemptState: (
        "last_attempt",
        "last_success",
        "last_failure",
        "next_attempt_after",
    ),
}


def _encode(value: Any) -> Any:
    if isinstance(value, datetime.datetime):
        return _iso(value)
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_encode(v) for v in value]
    return value


def _decode(data: dict[str, Any], cls: type) -> dict[str, Any]:
    known = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
    decoded = {k: v for k, v in data.items() if k in known}
    for name in _DATETIME_FIELDS[cls]:
        if name in decoded:
            decoded[name] = _parse(decoded[name])
    return decoded


@dataclass(frozen=True)
class AccountState:
    directory_url: str
    key_thumbprint: str
    account_url: str
    registered_at: datetime.datetime | None = None


class RunLockedError(RuntimeError):
    """Another lematt renewal run holds the lock."""


@dataclass
class StateStore:
    """Reads and writes lematt state under one directory.

    With ``read_only`` (dry runs) nothing is written: state is read as
    usual and updates are discarded.
    """

    root: Path
    read_only: bool = False

    @property
    def certs_dir(self) -> Path:
        return self.root / "certs"

    def _ensure_dirs(self) -> None:
        self.certs_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, path: Path, data: dict[str, Any]) -> None:
        if self.read_only:
            return
        self._ensure_dirs()
        content = json.dumps(data, indent=2, sort_keys=True) + "\n"
        write_file_atomically(path, content.encode(), mode=0o600)

    def _read_json(self, path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            logger.warning(f"Ignoring unreadable state file {path}: {e}")
            return None
        if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
            logger.warning(f"Ignoring state file {path} with unknown schema")
            return None
        return data

    # -- account ----------------------------------------------------------

    def load_account(
        self, directory_url: str, key_thumbprint: str
    ) -> AccountState | None:
        """The stored account for this directory and key, if any."""
        data = self._read_json(self.root / "account.json")
        if not data:
            return None
        if data.get("directory_url") != directory_url or (
            data.get("key_thumbprint") != key_thumbprint
        ):
            return None
        return AccountState(
            directory_url=directory_url,
            key_thumbprint=key_thumbprint,
            account_url=data["account_url"],
            registered_at=_parse(data.get("registered_at")),
        )

    def save_account(self, account: AccountState) -> None:
        data = _encode(asdict(account))
        data["schema"] = SCHEMA_VERSION
        self._write_json(self.root / "account.json", data)

    def forget_account(self) -> None:
        if not self.read_only:
            (self.root / "account.json").unlink(missing_ok=True)

    # -- certificates -----------------------------------------------------

    def cert_path(self, cert_id: str) -> Path:
        return self.certs_dir / f"{cert_id}.json"

    def load_cert(self, cert_id: str) -> CertState | None:
        data = self._read_json(self.cert_path(cert_id))
        if not data:
            return None
        try:
            return CertState.from_json(data)
        except (KeyError, TypeError, ValueError) as e:
            logger.warning(f"Ignoring malformed state for {cert_id}: {e}")
            return None

    def save_cert(self, state: CertState) -> None:
        self._write_json(self.cert_path(state.cert_id), state.to_json())

    # -- history ----------------------------------------------------------

    def record(self, event: str, cert_id: str | None = None, **details: Any) -> None:
        """Append an event to history.jsonl (one JSON object per line)."""
        if self.read_only:
            return
        self._ensure_dirs()
        entry = {"at": _iso(utcnow()), "event": event}
        if cert_id:
            entry["cert"] = cert_id
        entry.update(_encode(details))
        path = self.root / "history.jsonl"
        try:
            # One write() per line with O_APPEND, so concurrent workers'
            # lines don't interleave
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
            finally:
                os.close(fd)
        except OSError as e:
            logger.warning(f"Could not record {event} in history: {e}")

    def rotate_history(self) -> None:
        """Move history.jsonl to history.jsonl.1 once it exceeds 5 MB.

        Called once per run while holding the run lock (never from parallel
        workers), so rotations can't race.
        """
        path = self.root / "history.jsonl"
        if self.read_only or not path.exists():
            return
        if path.stat().st_size > HISTORY_MAX_BYTES:
            os.replace(path, path.with_suffix(".jsonl.1"))

    def history(self) -> list[dict[str, Any]]:
        """All recorded events (current file only), oldest first."""
        try:
            lines = (self.root / "history.jsonl").read_text().splitlines()
        except FileNotFoundError:
            return []
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        return events

    # -- run lock ---------------------------------------------------------

    @contextmanager
    def run_lock(self) -> Iterator[None]:
        """Hold the renewal-run lock; raise RunLockedError if it's taken."""
        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.root / "run.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as e:
                raise RunLockedError(
                    f"another lematt run holds {self.root / 'run.lock'}"
                ) from e
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode())
            yield
        finally:
            os.close(fd)
