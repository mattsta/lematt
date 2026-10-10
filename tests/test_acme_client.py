"""ACME client behavior against the in-process fake CA."""

from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from fake_acme import DIRECTORY_URL, FakeAcmeServer

from lematt.acme import (
    AccountKey,
    AcmeError,
    AcmeTransport,
    ChallengeError,
    Http01Solver,
    RateLimitedError,
    issue_certificate,
)
from lematt.acme.errors import parse_retry_after
from lematt.config import KeyType
from lematt.crypto import create_csr, generate_private_key

NAMES = ["example.com", "www.example.com"]


@pytest.fixture
def server(tmp_path):
    challenges = tmp_path / "challenges"
    challenges.mkdir()
    return FakeAcmeServer(challenge_dir=challenges)


def account_key(tmp_path, kind: str = "rsa"):
    key = {
        "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "p256": lambda: ec.generate_private_key(ec.SECP256R1()),
        "p384": lambda: ec.generate_private_key(ec.SECP384R1()),
    }[kind]()
    path = tmp_path / f"account-{kind}.pem"
    path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return path


def csr_for(tmp_path, names=NAMES) -> bytes:
    key = tmp_path / "cert-key.pem"
    key.write_bytes(generate_private_key(KeyType.EC))
    return create_csr(key, names)


def issue(server, tmp_path, *, kind="rsa", transport=None, names=NAMES, **kwargs):
    transport = transport or AcmeTransport(
        DIRECTORY_URL,
        AccountKey.from_file(account_key(tmp_path, kind)),
        client=server.http_client(),
    )
    sleeps: list[float] = []
    kwargs.setdefault(
        "solver", Http01Solver(server.challenge_dir, client=server.http_client())
    )
    issued = issue_certificate(
        directory_url=DIRECTORY_URL,
        account_key_path="unused",
        csr_pem=csr_for(tmp_path, names),
        challenge_dir=server.challenge_dir,
        transport=transport,
        sleep=sleeps.append,
        **kwargs,
    )
    return issued, sleeps, transport


@pytest.mark.parametrize("kind", ["rsa", "p256", "p384"])
def test_issues_certificate_with_each_account_key_type(server, tmp_path, kind):
    issued, _, _ = issue(server, tmp_path, kind=kind)

    leaf = x509.load_pem_x509_certificates(issued.pem.encode())[0]
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == NAMES
    assert len(x509.load_pem_x509_certificates(issued.pem.encode())) == 2  # + chain
    order_id = issued.order_url.rsplit("/", 1)[1]
    assert issued.alternate_urls == (f"https://acme.test/cert/{order_id}/1",)
    assert list(server.challenge_dir.iterdir()) == []  # challenge files removed


def test_nonces_from_responses_are_reused(server, tmp_path):
    issue(server, tmp_path)

    assert server.count("HEAD", "/new-nonce") == 1


def test_bad_nonce_is_retried_transparently(server, tmp_path):
    server.bad_nonces = 2

    issued, _, _ = issue(server, tmp_path)

    assert issued.pem.startswith("-----BEGIN CERTIFICATE-----")


def test_already_valid_authorizations_are_not_revalidated(server, tmp_path):
    _, _, transport = issue(server, tmp_path)
    challenges_before = server.count("POST", "/challenge")

    issue(server, tmp_path, transport=transport)  # e.g. the EC cert after RSA

    assert server.count("POST", "/challenge") == challenges_before
    assert server.count("POST", "/new-account") == 1  # account reused via kid


def test_order_polling_honors_retry_after(server, tmp_path):
    server.processing_polls = 2
    server.retry_after = 7

    _, sleeps, _ = issue(server, tmp_path)

    assert sleeps.count(7) == 2


def test_rate_limit_surfaces_retry_after(server, tmp_path):
    server.rate_limit_new_order = 3600

    with pytest.raises(RateLimitedError) as caught:
        issue(server, tmp_path)

    assert caught.value.retry_after == 3600
    assert not caught.value.retryable
    assert "too many new orders" in str(caught.value)


def test_ca_validation_failure_reports_ca_detail_and_cleans_up(server, tmp_path):
    server.reject_validation = True

    with pytest.raises(ChallengeError) as caught:
        issue(server, tmp_path)

    assert caught.value.problem == "unauthorized"
    assert "example.com" in str(caught.value)
    assert list(server.challenge_dir.iterdir()) == []


def test_self_check_failure_stops_before_asking_the_ca(server, tmp_path):
    # Files land in a directory the web server doesn't serve
    unserved = tmp_path / "not-the-webroot"
    unserved.mkdir()
    solver = Http01Solver(unserved, client=server.http_client())

    with pytest.raises(ChallengeError, match="is challengeDropDir served there"):
        issue(server, tmp_path, solver=solver)

    assert server.count("POST", "/challenge") == 0  # no failed validation spent


def test_profiles_are_validated_and_sent(server, tmp_path):
    with pytest.raises(AcmeError, match="profile 'bogus' is not offered"):
        issue(server, tmp_path, profile="bogus")
    assert "new-order" not in server.payloads

    issued, _, _ = issue(server, tmp_path, profile="shortlived")

    assert server.payloads["new-order"][-1]["profile"] == "shortlived"
    leaf = x509.load_pem_x509_certificates(issued.pem.encode())[0]
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc < timedelta(days=7)


def test_replaces_is_only_sent_when_the_ca_supports_ari(server, tmp_path):
    issue(server, tmp_path, replaces="aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")
    assert (
        server.payloads["new-order"][-1]["replaces"]
        == "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
    )

    server.renewal_info = False
    issue(server, tmp_path, replaces="aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")
    assert "replaces" not in server.payloads["new-order"][-1]


def test_unsafe_tokens_are_refused(tmp_path):
    with pytest.raises(ChallengeError, match="unsafe challenge token"):
        Http01Solver(tmp_path).present("example.com", "../../etc/passwd", "x")


@pytest.mark.parametrize(
    ("header", "seconds"),
    [
        ("120", 120.0),
        (None, None),
        ("soon", None),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0),
    ],
)
def test_retry_after_parsing(header, seconds):
    assert parse_retry_after(header) == seconds


@pytest.mark.parametrize(
    "header",
    [
        '<https://ca/a/3>;rel="alternate", <https://ca/dir>;rel="index"',
        "<https://ca/a/3>; rel=alternate, <https://ca/dir>; rel=index",
        '<https://ca/dir>;rel="index up", <https://ca/a/3>;rel="alternate"',
    ],
)
def test_link_header_parsing(header):
    import httpx

    from lematt.acme.transport import links

    response = httpx.Response(200, headers={"Link": header})

    assert links(response, "alternate") == ["https://ca/a/3"]
