"""Cryptography functions for lematt.

This module provides unified cryptographic operations with optional native
cryptography library support. Falls back to openssl subprocess if the
cryptography library is not available.
"""

import contextlib
import datetime
import os
import re
import subprocess

from loguru import logger

from lematt.config import CertificateInfo, KeyType

# Try to import cryptography for native crypto operations
# Falls back to openssl subprocess if not available
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ============================================================================
# Native Cryptography Library Functions (optional)
# ============================================================================


def generate_rsa_key_native(bits: int = 2048) -> bytes:
    """Generate RSA private key using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_ec_key_native(curve_name: str = "prime256v1") -> bytes:
    """Generate EC private key using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    # Map curve names to cryptography curve objects
    curve_map = {
        "prime256v1": ec.SECP256R1(),
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }

    if curve_name not in curve_map:
        raise ValueError(f"Unsupported curve: {curve_name}")

    private_key = ec.generate_private_key(
        curve_map[curve_name],
        backend=default_backend(),
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def parse_certificate_native(cert_path: str) -> CertificateInfo:
    """Parse certificate using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    if not os.path.isfile(cert_path):
        return CertificateInfo(exists=False, path=cert_path)

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Extract subject CN
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            cn = None

        # Extract SAN domains
        san_domains: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_domains = [
                name.value for name in san_ext.value if isinstance(name, x509.DNSName)
            ]
        except x509.ExtensionNotFound:
            pass

        # Extract issuer
        try:
            issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            issuer = None

        # Handle both old and new cryptography library API
        not_after = (
            cert.not_valid_after_utc.replace(tzinfo=None)
            if hasattr(cert, "not_valid_after_utc")
            else cert.not_valid_after.replace(tzinfo=None)
        )
        not_before = (
            cert.not_valid_before_utc.replace(tzinfo=None)
            if hasattr(cert, "not_valid_before_utc")
            else cert.not_valid_before.replace(tzinfo=None)
        )

        return CertificateInfo(
            exists=True,
            path=cert_path,
            not_after=not_after,
            not_before=not_before,
            subject_cn=cn,
            san_domains=san_domains,
            issuer=issuer,
            serial_number=str(cert.serial_number),
        )
    except Exception as e:
        return CertificateInfo(
            exists=True,
            path=cert_path,
            parse_error=str(e),
        )


def generate_csr_native(
    private_key_path: str,
    domains: list[str],
    ocsp_must_staple: bool = False,
) -> bytes:
    """Generate CSR using cryptography library."""
    if not HAS_CRYPTOGRAPHY:
        raise ImportError("cryptography library not available")

    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend(),
        )

    # Build CSR
    primary_domain = domains[0]
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, primary_domain),
        ])
    )

    # Always add SAN extension for consistency
    san_names = [x509.DNSName(d) for d in domains]
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_names),
        critical=False,
    )

    # Add OCSP Must-Staple if requested
    if ocsp_must_staple:
        builder = builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    # Sign and return
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)


# ============================================================================
# Unified Crypto Functions (native with openssl fallback)
# ============================================================================


def generate_private_key(
    key_type: KeyType,
    rsa_bits: int = 2048,
    ec_curve: str = "prime256v1",
) -> bytes:
    """Generate a private key, using native crypto if available."""
    if HAS_CRYPTOGRAPHY:
        if key_type == KeyType.RSA:
            return generate_rsa_key_native(rsa_bits)
        return generate_ec_key_native(ec_curve)

    # Fall back to openssl subprocess
    if key_type == KeyType.RSA:
        result = subprocess.run(
            ["openssl", "genrsa", str(rsa_bits)],
            capture_output=True,
            check=True,
        )
    else:
        result = subprocess.run(
            ["openssl", "ecparam", "-genkey", "-name", ec_curve],
            capture_output=True,
            check=True,
        )
    return result.stdout


def get_certificate_info(cert_path: str) -> CertificateInfo:
    """Get certificate information, using native crypto if available."""
    if HAS_CRYPTOGRAPHY:
        return parse_certificate_native(cert_path)

    # Fall back to openssl subprocess
    if not os.path.isfile(cert_path):
        return CertificateInfo(exists=False, path=cert_path)

    try:
        # Get expiration date
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                cert_path,
                "-noout",
                "-enddate",
                "-startdate",
                "-subject",
                "-issuer",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        info = CertificateInfo(exists=True, path=cert_path)
        ssl_date_fmt = r"%b %d %H:%M:%S %Y %Z"

        for line in result.stdout.strip().split("\n"):
            if line.startswith("notAfter="):
                with contextlib.suppress(ValueError):
                    info.not_after = datetime.datetime.strptime(line[9:], ssl_date_fmt)
            elif line.startswith("notBefore="):
                with contextlib.suppress(ValueError):
                    info.not_before = datetime.datetime.strptime(line[10:], ssl_date_fmt)
            elif line.startswith("subject="):
                # Extract CN from subject
                cn_match = re.search(r"CN\s*=\s*([^,/]+)", line)
                if cn_match:
                    info.subject_cn = cn_match.group(1).strip()
            elif line.startswith("issuer="):
                cn_match = re.search(r"CN\s*=\s*([^,/]+)", line)
                if cn_match:
                    info.issuer = cn_match.group(1).strip()

        # Get SAN domains
        try:
            san_result = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
                capture_output=True,
                text=True,
                check=True,
            )
            san_match = re.search(
                r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)",
                san_result.stdout,
            )
            if san_match:
                san_line = san_match.group(1)
                info.san_domains = [
                    d.replace("DNS:", "").strip()
                    for d in san_line.split(",")
                    if d.strip().startswith("DNS:")
                ]
        except subprocess.CalledProcessError:
            pass

        return info

    except (subprocess.CalledProcessError, OSError) as e:
        return CertificateInfo(
            exists=True,
            path=cert_path,
            parse_error=str(e),
        )


def create_csr(
    private_key_path: str,
    domains: list[str],
    output_path: str,
    ocsp_must_staple: bool = False,
) -> bool:
    """Create a CSR, using native crypto if available."""
    if HAS_CRYPTOGRAPHY:
        try:
            csr_bytes = generate_csr_native(private_key_path, domains, ocsp_must_staple)
            with open(output_path, "wb") as f:
                f.write(csr_bytes)
            return True
        except Exception as e:
            logger.warning(f"Native CSR generation failed, falling back to openssl: {e}")

    # Fall back to openssl subprocess
    primary_domain = domains[0]
    use_san = len(domains) > 1

    san_config = ""
    cmd_san = ""
    if use_san:
        alt_names = [f"DNS:{domain}" for domain in domains]
        san_config = ",".join(alt_names)
        cmd_san = "-reqexts SAN"

    ocsp_line = ""
    if ocsp_must_staple:
        ocsp_line = "1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05"

    stdin_config = f"""[req]
distinguished_name=req_dn

[req_dn]

[v3_req]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
{ocsp_line}

[SAN]
subjectAltName={san_config}"""

    try:
        cmd = f"openssl req -new -sha256 -key {private_key_path} -subj /CN={primary_domain} {cmd_san} -config -"
        result = subprocess.run(
            cmd.split(),
            input=stdin_config.encode(),
            capture_output=True,
            check=True,
        )
        with open(output_path, "wb") as f:
            f.write(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"CSR generation failed: {e}")
        return False
