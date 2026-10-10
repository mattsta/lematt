"""Keys, CSRs and certificate parsing."""

import datetime
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from lematt.config import KeyType, LemattConfig
from lematt.crypto import create_csr, get_certificate_info, load_private_key
from lematt.health import HealthChecker, HealthStatus
from lematt.manager import CertificateManager


@pytest.fixture
def manager(tmp_path):
    return CertificateManager(
        LemattConfig(
            config_base=str(tmp_path),
            challenge_dir=str(tmp_path),
            account_key=str(tmp_path / "account.key"),
            ec_curve="secp384r1",
        )
    )


def load_csr(path) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(path.read_bytes())


def sans(request) -> list[str]:
    ext = request.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return ext.value.get_values_for_type(x509.DNSName)


@pytest.mark.parametrize("key_type", [KeyType.RSA, KeyType.EC])
def test_san_csr_lists_all_domains_without_must_staple(manager, tmp_path, key_type):
    key, csr = tmp_path / "key.pem", tmp_path / "req.csr"
    domains = ["example.com", "www.example.com", "mail.example.com"]

    assert manager.generate_key(str(key), key_type)
    assert manager.generate_csr(str(key), domains, str(csr))

    request = load_csr(csr)
    assert request.is_signature_valid
    assert sans(request) == domains
    assert request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "example.com"
    )
    with pytest.raises(x509.ExtensionNotFound):
        request.extensions.get_extension_for_class(x509.TLSFeature)


def test_keys_are_private_pkcs8_with_configured_parameters(manager, tmp_path):
    rsa_key, ec_key = tmp_path / "rsa.pem", tmp_path / "ec.pem"

    assert manager.generate_key(str(rsa_key), KeyType.RSA)
    assert manager.generate_key(str(ec_key), KeyType.EC)

    for key in (rsa_key, ec_key):
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        assert key.read_text().startswith("-----BEGIN PRIVATE KEY-----")
    assert load_private_key(rsa_key).key_size == 2048
    assert load_private_key(ec_key).curve.name == "secp384r1"


def test_regenerating_a_key_replaces_the_whole_file(manager, tmp_path):
    key = tmp_path / "key.pem"
    key.write_text("x" * 10_000)  # longer than any new key

    assert manager.generate_key(str(key), KeyType.EC)

    assert load_private_key(key)  # no trailing bytes from the old file
    assert list(tmp_path.glob(".key.pem.*")) == []  # no temp files left


def test_single_name_csr_still_uses_subject_alt_name(manager, tmp_path):
    key = tmp_path / "key.pem"
    manager.generate_key(str(key), KeyType.EC)

    request = x509.load_pem_x509_csr(create_csr(key, ["example.com"]))

    assert sans(request) == ["example.com"]


def test_names_too_long_for_common_name_go_only_in_san(manager, tmp_path):
    key = tmp_path / "key.pem"
    manager.generate_key(str(key), KeyType.EC)
    long_name = f"{'a' * 60}.example.com"

    request = x509.load_pem_x509_csr(create_csr(key, [long_name]))

    assert request.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == []
    assert sans(request) == [long_name]


def write_certificate(path, *, days_left: float, names: list[str]) -> datetime.datetime:
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
            x509.NameAttribute(NameOID.COMMON_NAME, "YE1"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    not_after = (now + datetime.timedelta(days=days_left)).replace(microsecond=0)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x1234ABCD)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False
        )
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(Encoding.PEM))
    return not_after.replace(tzinfo=None)


def test_certificate_info_reads_leaf_fields(tmp_path):
    cert = tmp_path / "cert.pem"
    not_after = write_certificate(cert, days_left=30, names=["a.example", "b.example"])

    info = get_certificate_info(cert)

    assert info.not_after == not_after
    assert info.san_domains == ["a.example", "b.example"]
    assert info.subject_cn is None  # modern profiles omit the CN
    assert info.issuer == "YE1"
    assert info.issuer_dn == "C=US, O=Let's Encrypt, CN=YE1"
    assert info.serial_number == str(0x1234ABCD)


def test_health_check_uses_utc_expiry(tmp_path):
    config = LemattConfig(
        config_base=str(tmp_path), challenge_dir="", account_key="", is_test=True
    )
    cert = tmp_path / "cert.pem"
    write_certificate(cert, days_left=10.5, names=["example.com"])

    health = HealthChecker(config=config).check_certificate_file(
        cert, "example.com", "rsa"
    )

    assert health.status == HealthStatus.WARNING
    assert health.days_until_expiry == 10
    assert health.issuer == "C=US, O=Let's Encrypt, CN=YE1"


def make_cert(path, *, serial: int, aki: bytes | None, crl: str | None = None):
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "YE2")]))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=45))
    )
    if aki is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(aki, None, None), critical=False
        )
    if crl:
        point = x509.DistributionPoint(
            [x509.UniformResourceIdentifier(crl)], None, None, None
        )
        builder = builder.add_extension(x509.CRLDistributionPoints([point]), False)
    path.write_bytes(builder.sign(key, hashes.SHA384()).public_bytes(Encoding.PEM))


def test_ari_id_matches_rfc_9773_example(tmp_path):
    # RFC 9773 section 4.1: keyIdentifier 69:88:5B:...:D4, serial 0x87654321
    aki = bytes.fromhex("69885B6B87464041E1B37B847BA0AE2CDE01C8D4")
    make_cert(tmp_path / "c.pem", serial=0x87654321, aki=aki)

    assert get_certificate_info(tmp_path / "c.pem").ari_id == (
        "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
    )


def test_metadata_for_renewal_and_monitoring(tmp_path):
    crl = "http://ye2.c.lencr.org/42.crl"
    make_cert(tmp_path / "c.pem", serial=0x7F, aki=b"\x01\x02", crl=crl)

    info = get_certificate_info(tmp_path / "c.pem")

    assert info.ari_id == "AQI.fw"  # no leading zero needed below 0x80
    assert info.serial_hex == "7f"
    assert info.crl_urls == [crl]
    assert (info.key_type, info.key_size) == ("ec", 384)
    assert info.lifetime == datetime.timedelta(days=45)


def test_ari_id_absent_without_authority_key_identifier(tmp_path):
    make_cert(tmp_path / "c.pem", serial=5, aki=None)

    assert get_certificate_info(tmp_path / "c.pem").ari_id is None
