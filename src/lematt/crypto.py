"""Key, CSR and certificate handling for lematt (via the cryptography library)."""

import base64
import datetime
import os
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from lematt.config import CertificateInfo, KeyType

# OpenSSL curve names accepted in configuration
CURVES: dict[str, type[ec.EllipticCurve]] = {
    "prime256v1": ec.SECP256R1,
    "secp256r1": ec.SECP256R1,
    "secp384r1": ec.SECP384R1,
    "secp521r1": ec.SECP521R1,
}

# X.509 limits the Subject commonName to 64 characters
MAX_COMMON_NAME_LENGTH = 64

type PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def generate_private_key(
    key_type: KeyType,
    rsa_bits: int = 2048,
    ec_curve: str = "prime256v1",
) -> bytes:
    """Generate a private key and return it as unencrypted PKCS#8 PEM."""
    key: PrivateKey
    if key_type == KeyType.RSA:
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    else:
        if ec_curve not in CURVES:
            raise ValueError(f"Unsupported curve: {ec_curve}")
        key = ec.generate_private_key(CURVES[ec_curve]())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(path: str | Path) -> PrivateKey:
    """Load an unencrypted PEM private key (RSA or EC)."""
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise ValueError(f"{path}: unsupported key type {type(key).__name__}")
    return key


def create_csr(private_key_path: str | Path, domains: list[str]) -> bytes:
    """Create a PEM CSR for the given names (primary name first).

    Every name goes into subjectAltName. The primary name is also the
    Subject CN when it fits (at most 64 characters).
    """
    key = load_private_key(private_key_path)
    subject = (
        [x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]
        if len(domains[0]) <= MAX_COMMON_NAME_LENGTH
        else []
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(subject))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def write_file_atomically(path: str | Path, data: bytes, mode: int = 0o644) -> None:
    """Replace ``path`` with ``data`` so readers never see a partial file.

    The data is written to a temporary file in the same directory (created
    with ``mode``), flushed to disk, then renamed over ``path``.
    """
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _utc(moment: datetime.datetime) -> datetime.datetime:
    """Naive UTC datetime (the convention used throughout lematt)."""
    return moment.astimezone(datetime.UTC).replace(tzinfo=None)


def get_certificate_info(cert_path: str | Path) -> CertificateInfo:
    """Read the leaf (first) certificate of a PEM file."""
    path = str(cert_path)
    if not os.path.isfile(path):
        return CertificateInfo(exists=False, path=path)

    try:
        cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
    except Exception as e:
        return CertificateInfo(exists=True, path=path, parse_error=str(e))

    def common_name(name: x509.Name) -> str | None:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attrs[0].value) if attrs else None

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_domains = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_domains = []

    public_key = cert.public_key()
    key_type, key_size = (
        ("rsa", public_key.key_size)
        if isinstance(public_key, rsa.RSAPublicKey)
        else ("ec", public_key.curve.key_size)
        if isinstance(public_key, ec.EllipticCurvePublicKey)
        else (None, None)
    )

    return CertificateInfo(
        exists=True,
        path=path,
        not_after=_utc(cert.not_valid_after_utc),
        not_before=_utc(cert.not_valid_before_utc),
        subject_cn=common_name(cert.subject),
        san_domains=san_domains,
        issuer=common_name(cert.issuer),
        issuer_dn=", ".join(attr.rfc4514_string() for attr in cert.issuer),
        serial_number=str(cert.serial_number),
        serial_hex=f"{cert.serial_number:x}",
        ari_id=ari_cert_id(cert),
        crl_urls=_crl_urls(cert),
        key_type=key_type,
        key_size=key_size,
    )


def ari_cert_id(cert: x509.Certificate) -> str | None:
    """RFC 9773 certificate identifier: base64url(AKI keyIdentifier) "."
    base64url(DER serial number bytes), or None without an AKI."""
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    except x509.ExtensionNotFound:
        return None
    key_id = aki.value.key_identifier
    if not key_id:
        return None
    serial = cert.serial_number
    # DER INTEGER content: minimal big-endian two's complement (a leading
    # zero byte when the high bit would otherwise be set)
    serial_der = serial.to_bytes(serial.bit_length() // 8 + 1, "big")

    return f"{_b64url(key_id)}.{_b64url(serial_der)}"


def _crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []
    return [
        name.value
        for point in ext.value
        for name in point.full_name or []
        if isinstance(name, x509.UniformResourceIdentifier)
    ]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
