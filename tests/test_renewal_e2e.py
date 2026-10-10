"""Full renewal runs through the CLI against the fake ACME CA."""

import json
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from fake_acme import DIRECTORY_URL, FakeAcmeServer, ari_id

import lematt.manager
from lematt.acme import AccountKey, AcmeTransport, Http01Solver, ServerError
from lematt.acme import issue_certificate as real_issue_certificate
from lematt.acme.errors import ChallengeError
from lematt.cli import main
from lematt.state import StateStore


@pytest.fixture
def setup(tmp_path, monkeypatch):
    challenges = tmp_path / "challenges"
    challenges.mkdir()
    account = tmp_path / "account.key"
    account.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    log = tmp_path / "actions.log"
    (tmp_path / "lematt.conf").write_text(
        f"[config]\nchallengeDropDir: {challenges}\naccountKey: {account}\n"
    )
    (tmp_path / "domains").write_text("example.com www\nmail.example.org\n")
    (tmp_path / "actions.conf").write_text(
        f'[default]\nuploadCerts: ["echo upload CERTS >> {log}"]\n'
        f'update: ["echo reload DOMAINS_CN >> {log}"]\n'
    )
    server = FakeAcmeServer(challenge_dir=challenges)

    def issue_via_fake(**kwargs):
        kwargs["directory_url"] = DIRECTORY_URL
        kwargs["transport"] = AcmeTransport(
            kwargs["directory_url"],
            AccountKey.from_file(kwargs["account_key_path"]),
            client=server.http_client(),
        )
        kwargs["solver"] = Http01Solver(challenges, client=server.http_client())
        return real_issue_certificate(**kwargs)

    monkeypatch.setattr(lematt.manager, "issue_certificate", issue_via_fake)
    return tmp_path, server, log


def run(monkeypatch, base, *args: str) -> int:
    monkeypatch.setattr(
        sys, "argv", ["lematt", "--test", "--config", str(base / "lematt.conf"), *args]
    )
    return main()


def test_renewal_issues_links_and_deploys(monkeypatch, setup, capsys):
    base, server, log = setup

    assert run(monkeypatch, base) == 0

    certs = base / "test" / "cert"
    rsa_cert = certs / "example.com_www.example.com-cert-combined.rsa2048.test.pem"
    ec_cert = certs / "example.com_www.example.com-cert-combined.prime256v1.test.pem"
    for cert in (rsa_cert, ec_cert):
        leaf = x509.load_pem_x509_certificates(cert.read_bytes())[0]
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san.value.get_values_for_type(x509.DNSName) == [
            "example.com",
            "www.example.com",
        ]
    # SAN names get symlinks to the combined certificate
    assert os.readlink(certs / "www.example.com-cert-combined.rsa2048.test.pem") == (
        rsa_cert.name
    )
    assert len(server.issued) == 4  # 2 certificates x (RSA + EC)
    # http-01 validated once per name; the EC orders reused the authorizations
    assert server.count("POST", "/challenge") == 3
    assert server.count("POST", "/new-account") == 4  # once per issuance

    lines = log.read_text().splitlines()
    assert sorted(lines[-1].split()[1:]) == ["example.com", "mail.example.org"]
    assert lines[0].startswith("upload ")

    # Nothing is due on the next run: no orders, no actions
    log.unlink()
    assert run(monkeypatch, base, "--status", "--json") == 0
    status = json.loads(capsys.readouterr().out)
    assert status["summary"]["ok"] == 4
    assert run(monkeypatch, base) == 0
    assert len(server.issued) == 4
    assert not log.exists()


def test_validation_failure_is_not_retried(monkeypatch, setup):
    base, server, log = setup
    server.reject_validation = True

    assert run(monkeypatch, base, "--domain", "mail.example.org") == 1

    # RSA and EC each make one validation attempt (a failed authorization is
    # never reused) and neither is retried: previously every failure was
    # retried three times, spending Let's Encrypt's failed-validation limit.
    assert server.count("POST", "/challenge") == 2
    assert not log.exists()


def test_transient_failures_are_retried_after_retry_after(monkeypatch, setup):
    base, _, _ = setup
    attempts: list[int] = []
    waits: list[float] = []

    def flaky(**kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise ServerError("serverInternal", "try again", retry_after=5)
        raise ChallengeError("unauthorized", "stop")

    monkeypatch.setattr(lematt.manager, "issue_certificate", flaky)
    monkeypatch.setattr(lematt.manager.time, "sleep", waits.append)
    monkeypatch.setattr(lematt.manager, "MAX_RETRY_WAIT", 60.0)

    assert run(monkeypatch, base, "--domain", "mail.example.org") == 1

    # RSA: transient failure, wait 5s, then a permanent failure; EC: one try
    assert len(attempts) == 3
    assert waits == [5]


def test_state_and_history_track_issuance(monkeypatch, setup, capsys):
    base, server, _ = setup

    assert run(monkeypatch, base, "--domain", "mail.example.org") == 0

    store = StateStore(base / "test" / "state")
    state = store.load_cert("mail.example.org.prime256v1")
    leaf = server.issued[-1]
    assert state.issued.serial == f"{leaf.serial_number:x}"
    assert state.issued.ari_id == ari_id(leaf)
    assert state.attempts.consecutive_failures == 0
    assert [e["event"] for e in store.history()] == ["issued", "issued"]

    assert (
        run(monkeypatch, base, "--status", "--json", "--domain", "mail.example.org")
        == 0
    )
    renewal = json.loads(capsys.readouterr().out)["certificates"][0]["renewal"]
    assert renewal["renew_now"] is False
    assert renewal["basis"] == "lifetime"  # ARI not consulted yet
    assert renewal["last_success"] is not None


def test_failures_back_off_until_forced(monkeypatch, setup):
    base, server, _ = setup
    server.reject_validation = True

    assert run(monkeypatch, base, "--domain", "mail.example.org") == 1
    store = StateStore(base / "test" / "state")
    state = store.load_cert("mail.example.org.rsa2048")
    assert state.attempts.consecutive_failures == 1
    assert "unauthorized" in state.attempts.last_error
    assert store.history()[-1]["event"] == "renewal_failed"

    # The next run (within the backoff window) doesn't contact the CA
    challenges = server.count("POST", "/challenge")
    assert run(monkeypatch, base, "--domain", "mail.example.org") == 0
    assert server.count("POST", "/challenge") == challenges

    # An operator can retry right away
    server.reject_validation = False
    assert run(monkeypatch, base, "--domain", "mail.example.org", "--force-renew") == 0
    assert (
        store.load_cert("mail.example.org.rsa2048").attempts.consecutive_failures == 0
    )
