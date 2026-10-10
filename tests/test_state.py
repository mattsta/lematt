"""Persistent state: round trips, robustness, history, and the run lock."""

import datetime
import json
import stat
import sys

import pytest

from lematt.cli import EXIT_RUN_LOCKED, main
from lematt.state import (
    AccountState,
    AttemptState,
    CertState,
    IssuedState,
    RenewalInfoState,
    RunLockedError,
    StateStore,
)

T0 = datetime.datetime(2026, 10, 10, 12, 0, 0)


def full_state() -> CertState:
    return CertState(
        cert_id="example.com_www.example.com.rsa2048",
        names=["example.com", "www.example.com"],
        key_type="rsa",
        issued=IssuedState(
            serial="0a1b",
            ari_id="aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE",
            not_before=T0,
            not_after=T0 + datetime.timedelta(days=90),
            issued_at=T0,
            order_url="https://acme.test/order/1",
        ),
        renewal_info=RenewalInfoState(
            serial="0a1b",
            window_start=T0 + datetime.timedelta(days=60),
            window_end=T0 + datetime.timedelta(days=62),
            selected_time=T0 + datetime.timedelta(days=61),
            fetched_at=T0,
            next_check=T0 + datetime.timedelta(hours=6),
            explanation_url="https://example.test/why",
        ),
        attempts=AttemptState(last_success=T0, consecutive_failures=0),
    )


def test_cert_state_round_trips(tmp_path):
    store = StateStore(tmp_path)
    state = full_state()

    store.save_cert(state)

    assert store.load_cert(state.cert_id) == state
    path = store.cert_path(state.cert_id)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text())
    assert data["schema"] == 1
    assert data["issued"]["not_after"] == "2027-01-08T12:00:00Z"


def test_missing_corrupt_or_foreign_state_is_treated_as_absent(tmp_path):
    store = StateStore(tmp_path)
    store.certs_dir.mkdir(parents=True)

    assert store.load_cert("none") is None
    store.cert_path("corrupt").write_text("{not json")
    assert store.load_cert("corrupt") is None
    store.cert_path("future").write_text(json.dumps({"schema": 99, "cert_id": "x"}))
    assert store.load_cert("future") is None


def test_unknown_fields_from_newer_versions_are_ignored(tmp_path):
    store = StateStore(tmp_path)
    data = full_state().to_json()
    data["attempts"]["added_later"] = True
    store.certs_dir.mkdir(parents=True)
    store.cert_path("x").write_text(json.dumps(data))

    assert store.load_cert("x") == full_state()


def test_read_only_store_never_writes(tmp_path):
    store = StateStore(tmp_path / "state", read_only=True)

    store.save_cert(full_state())
    store.save_account(
        AccountState("https://acme.test/directory", "tp", "https://acme.test/acct/1")
    )
    store.record("issued", "x")

    assert not (tmp_path / "state").exists()


def test_account_is_only_reused_for_the_same_directory_and_key(tmp_path):
    store = StateStore(tmp_path)
    store.save_account(AccountState("https://ca/dir", "thumb", "https://ca/acct/7", T0))

    assert (
        store.load_account("https://ca/dir", "thumb").account_url == "https://ca/acct/7"
    )
    assert store.load_account("https://ca/dir", "other-key") is None
    assert store.load_account("https://other-ca/dir", "thumb") is None


def test_history_appends_events_and_rotates_between_runs(tmp_path, monkeypatch):
    store = StateStore(tmp_path)
    store.record("issued", "a", serial="01", not_after=T0)
    store.record("renewal_failed", "b", error="boom")

    events = store.history()
    assert [(e["event"], e["cert"]) for e in events] == [
        ("issued", "a"),
        ("renewal_failed", "b"),
    ]
    assert events[0]["not_after"] == "2026-10-10T12:00:00Z"

    monkeypatch.setattr("lematt.state.HISTORY_MAX_BYTES", 10)
    store.record("issued", "c")  # appends never rotate (workers run in parallel)
    assert len(store.history()) == 3

    store.rotate_history()  # once per run, under the run lock
    store.record("issued", "d")
    assert [e["cert"] for e in store.history()] == ["d"]
    assert (tmp_path / "history.jsonl.1").exists()


def test_run_lock_is_exclusive(tmp_path):
    first, second = StateStore(tmp_path), StateStore(tmp_path)

    with first.run_lock(), pytest.raises(RunLockedError), second.run_lock():
        pass
    with second.run_lock():  # released after the first run
        pass


def test_overlapping_renewal_runs_exit_without_doing_anything(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "challenges").mkdir()
    (tmp_path / "account.key").write_text("placeholder")
    (tmp_path / "lematt.conf").write_text(
        f"[config]\nchallengeDropDir: {tmp_path / 'challenges'}\n"
        f"accountKey: {tmp_path / 'account.key'}\n"
    )
    (tmp_path / "domains").write_text("example.com\n")
    (tmp_path / "actions.conf").write_text("")
    monkeypatch.setattr(
        sys, "argv", ["lematt", "--test", "--config", str(tmp_path / "lematt.conf")]
    )

    with StateStore(tmp_path / "test" / "state").run_lock():
        assert main() == EXIT_RUN_LOCKED

    assert "another lematt run holds" in capsys.readouterr().err
    assert not (tmp_path / "test" / "cert").exists()  # nothing was processed
