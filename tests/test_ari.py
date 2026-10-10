"""ARI (RFC 9773) client against the fake CA."""

import datetime
import random

import pytest
from cryptography import x509
from fake_acme import DIRECTORY_URL, FakeAcmeServer
from test_acme_client import account_key, csr_for

from lematt.acme import (
    AccountKey,
    AcmeError,
    AcmeTransport,
    Http01Solver,
    issue_certificate,
)
from lematt.acme.ari import DEFAULT_CHECK_INTERVAL, RenewalInfo, fetch_renewal_info
from lematt.acme.errors import AcmeProtocolError
from lematt.crypto import ari_cert_id


@pytest.fixture
def issued(tmp_path):
    challenges = tmp_path / "challenges"
    challenges.mkdir()
    server = FakeAcmeServer(challenge_dir=challenges)
    transport = AcmeTransport(
        DIRECTORY_URL,
        AccountKey.from_file(account_key(tmp_path)),
        client=server.http_client(),
    )
    result = issue_certificate(
        directory_url=DIRECTORY_URL,
        account_key_path="unused",
        csr_pem=csr_for(tmp_path),
        challenge_dir=challenges,
        transport=transport,
        solver=Http01Solver(challenges, client=server.http_client()),
    )
    leaf = x509.load_pem_x509_certificates(result.pem.encode())[0]
    return server, transport, leaf, ari_cert_id(leaf)


def test_fetches_the_suggested_window(issued):
    server, transport, leaf, cert_id = issued

    info = fetch_renewal_info(transport, cert_id)

    not_after = leaf.not_valid_after_utc.replace(tzinfo=None)
    assert info.window_start < info.window_end < not_after
    assert info.check_after == server.ari_retry_after
    assert info.explanation_url is None


def test_reports_explanations_for_early_renewal(issued):
    server, transport, _, cert_id = issued
    now = datetime.datetime(2026, 10, 10)
    server.ari_windows[cert_id] = (
        now,
        now + datetime.timedelta(hours=1),
        "https://ca/incident",
    )

    info = fetch_renewal_info(transport, cert_id)

    assert (info.window_start, info.explanation_url) == (now, "https://ca/incident")


@pytest.mark.parametrize(
    ("retry_after", "expected"),
    [(5, 60.0), (3600, 3600.0), (10**7, 86_400.0)],
)
def test_retry_after_is_clamped(issued, retry_after, expected):
    server, transport, _, cert_id = issued
    server.ari_retry_after = retry_after

    assert fetch_renewal_info(transport, cert_id).check_after == expected


def test_missing_retry_after_means_six_hours(issued, monkeypatch):
    server, transport, _, cert_id = issued
    original = server._reply

    def without_retry_after(*args, **kwargs):
        headers = kwargs.get("headers") or {}
        headers.pop("Retry-After", None)
        return original(*args, **kwargs)

    monkeypatch.setattr(server, "_reply", without_retry_after)

    assert fetch_renewal_info(transport, cert_id).check_after == DEFAULT_CHECK_INTERVAL


def test_inverted_window_is_rejected(issued):
    server, transport, _, cert_id = issued
    now = datetime.datetime(2026, 10, 10)
    server.ari_windows[cert_id] = (now, now - datetime.timedelta(hours=1), None)

    with pytest.raises(AcmeProtocolError, match="ends before it starts"):
        fetch_renewal_info(transport, cert_id)


def test_ca_without_ari_is_reported(issued):
    server, transport, _, cert_id = issued
    server.renewal_info = False
    transport._directory = None  # re-read the directory

    with pytest.raises(AcmeError, match="does not offer renewal information"):
        fetch_renewal_info(transport, cert_id)


def test_selected_time_is_uniform_within_the_window():
    start = datetime.datetime(2026, 11, 1)
    info = RenewalInfo(start, start + datetime.timedelta(days=2), check_after=60)
    rng = random.Random(1)

    picks = [info.select_time(rng) for _ in range(200)]

    assert all(info.window_start <= p <= info.window_end for p in picks)
    assert min(picks) < start + datetime.timedelta(hours=6)
    assert max(picks) > start + datetime.timedelta(hours=42)
