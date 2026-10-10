"""ACME account keys and JWS signing (RFC 7515/7518 as profiled by RFC 8555)."""

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Curve name -> (JWS alg, JWK crv, hash, coordinate size in bytes)
_EC_ALGORITHMS: dict[str, tuple[str, str, hashes.HashAlgorithm, int]] = {
    "secp256r1": ("ES256", "P-256", hashes.SHA256(), 32),
    "secp384r1": ("ES384", "P-384", hashes.SHA384(), 48),
}


def b64url(data: bytes) -> str:
    """Unpadded base64url, as JOSE requires."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_bytes(value: int, size: int | None = None) -> bytes:
    return value.to_bytes(size or (value.bit_length() + 7) // 8, "big")


@dataclass(frozen=True)
class AccountKey:
    """An ACME account key: RSA (RS256) or EC P-256/P-384 (ES256/ES384)."""

    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

    @classmethod
    def from_file(cls, path: str | Path) -> AccountKey:
        return cls.from_pem(Path(path).read_bytes(), source=str(path))

    @classmethod
    def from_pem(cls, pem: bytes, *, source: str = "key") -> AccountKey:
        """A signing key from PEM (an account key, or a certificate's key)."""
        key = serialization.load_pem_private_key(pem, password=None)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            if key.curve.name not in _EC_ALGORITHMS:
                raise ValueError(
                    f"{source}: keys must be RSA, P-256 or P-384 (got {key.curve.name})"
                )
        elif not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"{source}: unsupported key type {type(key).__name__}")
        return cls(key)

    @property
    def alg(self) -> str:
        if isinstance(self.key, rsa.RSAPrivateKey):
            return "RS256"
        return _EC_ALGORITHMS[self.key.curve.name][0]

    @property
    def jwk(self) -> dict[str, str]:
        """Public JWK with members in lexicographic order (for thumbprints)."""
        if isinstance(self.key, rsa.RSAPrivateKey):
            numbers = self.key.public_key().public_numbers()
            return {
                "e": b64url(_int_bytes(numbers.e)),
                "kty": "RSA",
                "n": b64url(_int_bytes(numbers.n)),
            }
        _, crv, _, size = _EC_ALGORITHMS[self.key.curve.name]
        point = self.key.public_key().public_numbers()
        return {
            "crv": crv,
            "kty": "EC",
            "x": b64url(_int_bytes(point.x, size)),
            "y": b64url(_int_bytes(point.y, size)),
        }

    @property
    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint (used in challenge key authorizations)."""
        canonical = json.dumps(self.jwk, sort_keys=True, separators=(",", ":"))
        return b64url(hashlib.sha256(canonical.encode()).digest())

    def key_authorization(self, token: str) -> str:
        return f"{token}.{self.thumbprint}"

    def sign(self, data: bytes) -> bytes:
        """Raw JWS signature over ``data``."""
        if isinstance(self.key, rsa.RSAPrivateKey):
            return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        _, _, digest, size = _EC_ALGORITHMS[self.key.curve.name]
        r, s = decode_dss_signature(self.key.sign(data, ec.ECDSA(digest)))
        return _int_bytes(r, size) + _int_bytes(s, size)

    def jws(
        self,
        url: str,
        payload: dict[str, Any] | None,
        *,
        nonce: str,
        kid: str | None,
    ) -> dict[str, str]:
        """Flattened JWS for an ACME request (``payload=None`` is POST-as-GET)."""
        protected: dict[str, Any] = {"alg": self.alg, "nonce": nonce, "url": url}
        if kid is None:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = kid
        protected64 = b64url(json.dumps(protected).encode())
        payload64 = "" if payload is None else b64url(json.dumps(payload).encode())
        signature = self.sign(f"{protected64}.{payload64}".encode("ascii"))
        return {
            "protected": protected64,
            "payload": payload64,
            "signature": b64url(signature),
        }
