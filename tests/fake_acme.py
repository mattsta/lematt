"""In-process fake ACME server (RFC 8555) for exercising lematt's client.

It enforces the parts of the protocol a real CA would reject us for:
JWS signatures (RS256/ES256/ES384), single-use nonces, matching ``url``
headers, ``jwk`` only for newAccount, and http-01 key authorizations
(validated by reading the challenge directory, like a CA fetching the
file). It also serves that directory over plain HTTP for the client's
self-check, and issues real certificates from a throwaway CA.

Fault injection knobs let tests reproduce CA behaviors: bad nonces, rate
limits, failed validation, slow issuance with Retry-After.
"""

import base64
import datetime
import hashlib
import itertools
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

BASE = "https://acme.test"
DIRECTORY_URL = f"{BASE}/directory"
PROBLEM = "urn:ietf:params:acme:error:"


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _thumbprint(jwk: dict[str, str]) -> str:
    members = {
        k: jwk[k]
        for k in (
            ("e", "kty", "n") if jwk["kty"] == "RSA" else ("crv", "kty", "x", "y")
        )
    }
    canonical = json.dumps(members, sort_keys=True, separators=(",", ":"))
    return _b64encode(hashlib.sha256(canonical.encode()).digest())


def _verify(jwk: dict[str, str], alg: str, signature: bytes, data: bytes) -> None:
    def num(name: str) -> int:
        return int.from_bytes(_b64decode(jwk[name]), "big")

    if jwk["kty"] == "RSA":
        assert alg == "RS256", alg
        key = rsa.RSAPublicNumbers(num("e"), num("n")).public_key()
        key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return
    curve, digest, size = {
        "P-256": (ec.SECP256R1(), hashes.SHA256(), 32),
        "P-384": (ec.SECP384R1(), hashes.SHA384(), 48),
    }[jwk["crv"]]
    assert alg == {"P-256": "ES256", "P-384": "ES384"}[jwk["crv"]], alg
    assert len(signature) == 2 * size
    public = ec.EllipticCurvePublicNumbers(num("x"), num("y"), curve).public_key()
    r, s = (
        int.from_bytes(signature[:size], "big"),
        int.from_bytes(signature[size:], "big"),
    )
    public.verify(encode_dss_signature(r, s), data, ec.ECDSA(digest))


class Problem(Exception):
    def __init__(
        self, status: int, kind: str, detail: str, retry_after: int | None = None
    ):
        self.status, self.kind, self.detail, self.retry_after = (
            status,
            kind,
            detail,
            retry_after,
        )


@dataclass
class FakeAcmeServer:
    challenge_dir: Path
    profiles: tuple[str, ...] = ("classic", "tlsserver", "shortlived")
    renewal_info: bool = True

    # Fault injection
    bad_nonces: int = 0  # reject this many valid nonces with badNonce
    rate_limit_new_order: int | None = None  # Retry-After seconds
    reject_validation: bool = False  # CA-side validation fails
    processing_polls: int = 0  # order stays "processing" this many polls
    retry_after: int = 3  # Retry-After sent while processing
    ari_retry_after: int = 21600  # Retry-After on renewalInfo responses
    # ARI window overrides by certificate ID: (start, end, explanationURL)
    ari_windows: dict[str, tuple[datetime.datetime, datetime.datetime, str | None]] = (
        field(default_factory=dict)
    )

    # Observations
    requests: list[tuple[str, str]] = field(default_factory=list)
    payloads: dict[str, list[Any]] = field(default_factory=dict)
    issued: list[x509.Certificate] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._ids = itertools.count(1)
        self._nonces: set[str] = set()
        self._accounts: dict[str, dict[str, str]] = {}  # kid -> jwk
        self._orders: dict[str, dict[str, Any]] = {}
        self._authz: dict[str, dict[str, Any]] = {}
        self._valid_authz: dict[tuple[str, str], str] = {}  # (kid, name) -> authz id
        self._certs: dict[str, str] = {}
        self._by_ari_id: dict[str, x509.Certificate] = {}
        self.replaced: set[str] = set()
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Encrypt"),
                x509.NameAttribute(NameOID.COMMON_NAME, "FAKE-YE1"),
            ]
        )

    # -- plumbing ----------------------------------------------------------

    def http_client(self) -> httpx.Client:
        return httpx.Client(
            transport=httpx.MockTransport(self.handle), follow_redirects=True
        )

    def count(self, method: str, path_prefix: str) -> int:
        return sum(
            1 for m, p in self.requests if m == method and p.startswith(path_prefix)
        )

    def _nonce(self) -> str:
        nonce = f"nonce-{next(self._ids)}"
        self._nonces.add(nonce)
        return nonce

    def _reply(
        self,
        status: int,
        body: Any = None,
        *,
        headers: dict[str, str] | None = None,
        content_type: str = "application/json",
        nonce: bool = True,
    ) -> httpx.Response:
        headers = dict(headers or {})
        if nonce:
            headers["Replay-Nonce"] = self._nonce()
        if body is None:
            return httpx.Response(status, headers=headers)
        content = body if isinstance(body, str) else json.dumps(body)
        return httpx.Response(
            status, headers={**headers, "Content-Type": content_type}, content=content
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if request.url.host != "acme.test":
            return self._serve_challenge(request)
        try:
            return self._route(request)
        except Problem as p:
            headers = {"Retry-After": str(p.retry_after)} if p.retry_after else {}
            return self._reply(
                p.status,
                {"type": PROBLEM + p.kind, "detail": p.detail, "status": p.status},
                headers=headers,
                content_type="application/problem+json",
            )

    def _serve_challenge(self, request: httpx.Request) -> httpx.Response:
        token = request.url.path.removeprefix("/.well-known/acme-challenge/")
        path = self.challenge_dir / token
        if not path.is_file():
            return httpx.Response(404)
        return httpx.Response(200, content=path.read_bytes())

    def _route(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/directory":
            meta: dict[str, Any] = {
                "termsOfService": f"{BASE}/terms",
                "profiles": {p: f"{BASE}/docs#{p}" for p in self.profiles},
            }
            directory = {
                "newNonce": f"{BASE}/new-nonce",
                "newAccount": f"{BASE}/new-account",
                "newOrder": f"{BASE}/new-order",
                "revokeCert": f"{BASE}/revoke",
                "keyChange": f"{BASE}/key-change",
                "meta": meta,
            }
            if self.renewal_info:
                directory["renewalInfo"] = f"{BASE}/renewal-info"
            return self._reply(200, directory, nonce=False)
        if path == "/new-nonce":
            return self._reply(200 if request.method == "HEAD" else 204)
        if path.startswith("/renewal-info/") and request.method == "GET":
            return self._renewal_info(path.removeprefix("/renewal-info/"))

        kid, jwk, payload = self._authenticate(request)
        self.payloads.setdefault(path.split("/")[1], []).append(payload)

        if path == "/new-account":
            return self._new_account(jwk, payload)
        if path == "/new-order":
            return self._new_order(kid, payload)
        kind, _, ident = path.strip("/").partition("/")
        if kind == "authz":
            return self._reply(200, self._authz_view(ident))
        if kind == "challenge":
            return self._challenge(kid, ident)
        if kind == "order":
            return self._order(ident)
        if kind == "finalize":
            return self._finalize(ident, payload)
        if kind == "cert":
            return self._reply(
                200,
                self._certs[ident],
                headers={
                    "Link": f'<{BASE}/cert/{ident}/1>;rel="alternate", <{BASE}/directory>;rel="index"'
                },
                content_type="application/pem-certificate-chain",
            )
        raise Problem(404, "malformed", f"no such resource {path}")

    def _authenticate(
        self, request: httpx.Request
    ) -> tuple[str | None, dict[str, str], Any]:
        jws = json.loads(request.content)
        protected = json.loads(_b64decode(jws["protected"]))
        if protected.get("url") != str(request.url):
            raise Problem(400, "unauthorized", "url header mismatch")
        nonce = protected.get("nonce")
        if nonce not in self._nonces:
            raise Problem(400, "badNonce", "unknown or reused nonce")
        self._nonces.discard(nonce)
        if self.bad_nonces:
            self.bad_nonces -= 1
            raise Problem(400, "badNonce", "injected bad nonce")

        if "jwk" in protected:
            if request.url.path != "/new-account":
                raise Problem(400, "malformed", "jwk only allowed for newAccount")
            jwk, kid = protected["jwk"], None
        else:
            kid = protected.get("kid")
            if kid not in self._accounts:
                raise Problem(400, "accountDoesNotExist", f"unknown kid {kid}")
            jwk = self._accounts[kid]
        _verify(
            jwk,
            protected["alg"],
            _b64decode(jws["signature"]),
            f"{jws['protected']}.{jws['payload']}".encode(),
        )
        payload = json.loads(_b64decode(jws["payload"])) if jws["payload"] else None
        return kid, jwk, payload

    # -- resources ---------------------------------------------------------

    def _new_account(
        self, jwk: dict[str, str], payload: dict[str, Any]
    ) -> httpx.Response:
        assert payload.get("termsOfServiceAgreed") is True
        for existing, known in self._accounts.items():
            if known == jwk:
                return self._reply(
                    200, {"status": "valid"}, headers={"Location": existing}
                )
        url = f"{BASE}/acct/{next(self._ids)}"
        self._accounts[url] = jwk
        return self._reply(201, {"status": "valid"}, headers={"Location": url})

    def _new_order(self, kid: str | None, payload: dict[str, Any]) -> httpx.Response:
        if self.rate_limit_new_order is not None:
            raise Problem(
                429,
                "rateLimited",
                "too many new orders recently",
                self.rate_limit_new_order,
            )
        if replaces := payload.get("replaces"):
            if replaces in self.replaced:
                raise Problem(
                    409, "alreadyReplaced", f"{replaces} was already replaced"
                )
            self.replaced.add(replaces)
        names = [i["value"] for i in payload["identifiers"]]
        authz_urls = []
        for name in names:
            authz_id = self._valid_authz.get((kid or "", name))
            if authz_id is None:
                authz_id = str(next(self._ids))
                self._authz[authz_id] = {
                    "kid": kid,
                    "name": name,
                    "status": "pending",
                    "token": f"tok_{authz_id}-x",
                    "error": None,
                }
            authz_urls.append(f"{BASE}/authz/{authz_id}")
        order_id = str(next(self._ids))
        self._orders[order_id] = {
            "status": "pending",
            "names": names,
            "authz": authz_urls,
            "profile": payload.get("profile"),
            "polls": 0,
        }
        return self._reply(
            201,
            self._order_view(order_id),
            headers={"Location": f"{BASE}/order/{order_id}"},
        )

    def _authz_view(self, authz_id: str) -> dict[str, Any]:
        a = self._authz[authz_id]
        challenge: dict[str, Any] = {
            "type": "http-01",
            "url": f"{BASE}/challenge/{authz_id}",
            "token": a["token"],
            "status": a["status"],
        }
        if a["error"]:
            challenge["error"] = a["error"]
        dns = {
            "type": "dns-01",
            "url": f"{BASE}/challenge/{authz_id}-dns",
            "token": a["token"],
            "status": "pending",
        }
        return {
            "identifier": {"type": "dns", "value": a["name"]},
            "status": a["status"],
            "challenges": [dns, challenge],
        }

    def _challenge(self, kid: str | None, authz_id: str) -> httpx.Response:
        a = self._authz[authz_id]
        expected = f"{a['token']}.{_thumbprint(self._accounts[kid])}"
        path = self.challenge_dir / a["token"]
        served = path.read_text() if path.is_file() else None
        if self.reject_validation or served != expected:
            a["status"] = "invalid"
            a["error"] = {
                "type": PROBLEM + "unauthorized",
                "detail": f"Invalid response from http://{a['name']}/.well-known/acme-challenge/{a['token']}: 404",
            }
        else:
            a["status"] = "valid"
            self._valid_authz[(kid or "", a["name"])] = authz_id
        return self._reply(
            200,
            {
                "type": "http-01",
                "status": "processing",
                "url": f"{BASE}/challenge/{authz_id}",
                "token": a["token"],
            },
        )

    def _order_view(self, order_id: str) -> dict[str, Any]:
        o = self._orders[order_id]
        if o["status"] == "pending":
            statuses = {
                self._authz[url.rsplit("/", 1)[1]]["status"] for url in o["authz"]
            }
            if "invalid" in statuses:
                o["status"] = "invalid"
            elif statuses == {"valid"}:
                o["status"] = "ready"
        view: dict[str, Any] = {
            "status": o["status"],
            "identifiers": [{"type": "dns", "value": n} for n in o["names"]],
            "authorizations": o["authz"],
            "finalize": f"{BASE}/finalize/{order_id}",
        }
        if o["status"] == "valid":
            view["certificate"] = f"{BASE}/cert/{order_id}"
        return view

    def _order(self, order_id: str) -> httpx.Response:
        o = self._orders[order_id]
        if o["status"] == "processing":
            if o["polls"] < self.processing_polls:
                o["polls"] += 1
                return self._reply(
                    200,
                    self._order_view(order_id),
                    headers={"Retry-After": str(self.retry_after)},
                )
            o["status"] = "valid"
        return self._reply(200, self._order_view(order_id))

    def _finalize(self, order_id: str, payload: dict[str, Any]) -> httpx.Response:
        o = self._orders[order_id]
        if self._order_view(order_id)["status"] != "ready":
            raise Problem(403, "orderNotReady", f"order is {o['status']}")
        csr = x509.load_der_x509_csr(_b64decode(payload["csr"]))
        assert csr.is_signature_valid
        names = csr.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        if sorted(names) != sorted(o["names"]):
            raise Problem(400, "badCSR", f"CSR names {names} != order {o['names']}")
        now = datetime.datetime.now(datetime.UTC)
        lifetime = {
            "shortlived": datetime.timedelta(hours=160),
            "tlsserver": datetime.timedelta(days=45),
        }.get(o["profile"] or "", datetime.timedelta(days=90))
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.ca_name)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + lifetime)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()
                ),
                False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(self.ca_name)
            .issuer_name(self.ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self.ca_key, hashes.SHA256())
        )
        self.issued.append(leaf)
        self._by_ari_id[ari_id(leaf)] = leaf
        self._certs[order_id] = (
            leaf.public_bytes(Encoding.PEM) + ca.public_bytes(Encoding.PEM)
        ).decode()
        o["status"] = "processing"
        return self._reply(
            200,
            self._order_view(order_id),
            headers={"Location": f"{BASE}/order/{order_id}"},
        )

    def _renewal_info(self, cert_id: str) -> httpx.Response:
        leaf = self._by_ari_id.get(cert_id)
        if leaf is None:
            raise Problem(404, "malformed", f"unknown certificate {cert_id}")
        start, end, explanation = self.ari_windows.get(cert_id) or self._default_window(
            leaf
        )
        body: dict[str, Any] = {
            "suggestedWindow": {
                "start": start.isoformat() + "Z",
                "end": end.isoformat() + "Z",
            }
        }
        if explanation:
            body["explanationURL"] = explanation
        return self._reply(
            200, body, headers={"Retry-After": str(self.ari_retry_after)}, nonce=False
        )

    @staticmethod
    def _default_window(
        leaf: x509.Certificate,
    ) -> tuple[datetime.datetime, datetime.datetime, None]:
        not_before = leaf.not_valid_before_utc.replace(tzinfo=None)
        not_after = leaf.not_valid_after_utc.replace(tzinfo=None)
        start = not_after - (not_after - not_before) / 3
        return (
            start - datetime.timedelta(days=1),
            start + datetime.timedelta(days=1),
            None,
        )


def ari_id(cert: x509.Certificate) -> str:
    """RFC 9773 certificate ID, computed independently of lematt."""
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    serial = cert.serial_number
    der = serial.to_bytes(serial.bit_length() // 8 + 1, "big")
    return f"{_b64encode(aki.key_identifier)}.{_b64encode(der)}"
