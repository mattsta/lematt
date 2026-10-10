"""CSRs request exactly the configured names and nothing Let's Encrypt rejects."""

import pytest

x509 = pytest.importorskip("cryptography.x509")

from lematt.config import KeyType, LemattConfig
from lematt.manager import CertificateManager


@pytest.mark.parametrize("key_type", [KeyType.RSA, KeyType.EC])
def test_san_csr_lists_all_domains_without_must_staple(tmp_path, key_type):
    manager = CertificateManager(
        LemattConfig(
            config_base=str(tmp_path),
            challenge_dir=str(tmp_path),
            account_key=str(tmp_path / "account.key"),
        )
    )
    key, csr = str(tmp_path / "key.pem"), str(tmp_path / "req.csr")
    domains = ["example.com", "www.example.com", "mail.example.com"]

    assert manager.generate_key(key, key_type)
    assert manager.generate_csr(key, domains, csr)

    request = x509.load_pem_x509_csr((tmp_path / "req.csr").read_bytes())
    san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == domains
    with pytest.raises(x509.ExtensionNotFound):
        request.extensions.get_extension_for_class(x509.TLSFeature)
