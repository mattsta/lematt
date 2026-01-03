"""Modern ACME client for Let's Encrypt certificate issuance.

Refactored from acme-tiny (https://github.com/diafygi/acme-tiny)
Copyright Daniel Roesler, under MIT license

Modernized for lematt with:
- Loguru integration
- Type hints
- Class-based design
- Contextual logging
- Shutdown event support
"""

import base64
import binascii
import contextlib
import hashlib
import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any
from urllib.request import Request, urlopen

from loguru import logger

DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
STAGING_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"


@dataclass
class AcmeConfig:
    """Configuration for ACME certificate requests."""

    account_key: str
    challenge_dir: str
    directory_url: str = DEFAULT_DIRECTORY_URL
    contact: list[str] | None = None
    disable_check: bool = False


class AcmeClient:
    """Modern ACME client for Let's Encrypt integration.

    Features:
    - Loguru logging with domain context
    - Shutdown event support
    - Cleaner output (only logs important steps)
    - Type-safe modern Python
    """

    def __init__(
        self,
        config: AcmeConfig,
        domain_context: str = "",
        shutdown_event: Event | None = None,
    ):
        """Initialize ACME client.

        Args:
            config: ACME configuration
            domain_context: Domain name for logging context (e.g., "example.com[rsa]")
            shutdown_event: Optional event to check for cancellation
        """
        self.config = config
        self.domain_context = domain_context
        self.shutdown_event = shutdown_event

        # ACME protocol state
        self.directory: dict[str, Any] | None = None
        self.acct_headers: dict[str, Any] | None = None
        self.alg: str | None = None
        self.jwk: dict[str, Any] | None = None

    def _log(self, message: str, level: str = "info") -> None:
        """Log with domain context."""
        msg = f"[{self.domain_context}] {message}" if self.domain_context else message

        if level == "debug":
            logger.debug(msg)
        elif level == "warning":
            logger.warning(msg)
        elif level == "error":
            logger.error(msg)
        else:
            logger.info(msg)

    def _check_shutdown(self) -> None:
        """Check if shutdown was requested."""
        if self.shutdown_event and self.shutdown_event.is_set():
            raise InterruptedError("Shutdown requested")

    @staticmethod
    def _b64(data: bytes) -> str:
        """Base64 encode for JOSE spec."""
        return base64.urlsafe_b64encode(data).decode("utf8").replace("=", "")

    def _run_openssl(
        self,
        cmd: list[str],
        stdin_data: bytes | None = None,
        error_msg: str = "OpenSSL error",
    ) -> bytes:
        """Run OpenSSL command and return output."""
        self._check_shutdown()

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_data else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate(stdin_data)

        if proc.returncode != 0:
            raise OSError(f"{error_msg}: {err.decode('utf8')}")

        return out

    def _http_request(
        self, url: str, data: bytes | None = None, depth: int = 0
    ) -> tuple[Any, int, dict]:
        """Make HTTP request and parse JSON response."""
        self._check_shutdown()

        try:
            req = Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/jose+json",
                    "User-Agent": "lematt-acme-client",
                },
            )
            resp = urlopen(req, timeout=30)
            resp_data = resp.read().decode("utf8")
            code = resp.getcode()
            headers = dict(resp.headers)
        except OSError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code = getattr(e, "code", None)
            headers = {}

        # Try to parse JSON
        with contextlib.suppress(ValueError):
            resp_data = json.loads(resp_data)

        # Handle bad nonce - retry
        if (
            depth < 100
            and code == 400
            and isinstance(resp_data, dict)
            and resp_data.get("type") == "urn:ietf:params:acme:error:badNonce"
        ):
            raise IndexError("Bad nonce - will retry")

        # Check for errors
        if code not in [200, 201, 204]:
            error_detail = resp_data if isinstance(resp_data, dict) else str(resp_data)
            raise ValueError(f"HTTP {code} error from {url}: {error_detail}")

        return resp_data, code, headers

    def _send_signed_request(
        self, url: str, payload: dict | None, depth: int = 0
    ) -> tuple[Any, int, dict]:
        """Send signed ACME request."""
        payload64 = (
            "" if payload is None else self._b64(json.dumps(payload).encode("utf8"))
        )

        # Get new nonce
        _, _, nonce_headers = self._http_request(self.directory["newNonce"])
        new_nonce = nonce_headers["Replay-Nonce"]

        # Build protected header
        protected = {"url": url, "alg": self.alg, "nonce": new_nonce}
        if self.acct_headers is None:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.acct_headers["Location"]

        protected64 = self._b64(json.dumps(protected).encode("utf8"))

        # Sign the request
        signature_input = f"{protected64}.{payload64}".encode()
        signature = self._run_openssl(
            ["openssl", "dgst", "-sha256", "-sign", self.config.account_key],
            stdin_data=signature_input,
        )

        # Build JWS
        jws = {
            "protected": protected64,
            "payload": payload64,
            "signature": self._b64(signature),
        }

        # Send request
        try:
            return self._http_request(url, json.dumps(jws).encode("utf8"), depth)
        except IndexError:  # Bad nonce - retry
            return self._send_signed_request(url, payload, depth + 1)

    def _poll_until_ready(
        self, url: str, pending_statuses: list[str], timeout: int = 3600
    ) -> dict:
        """Poll URL until status is no longer pending."""
        start_time = time.time()
        result = None
        attempt = 0

        while result is None or result.get("status") in pending_statuses:
            self._check_shutdown()

            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"Polling timeout after {timeout}s")

            if result is not None:
                attempt += 1
                # Log every 5 attempts (10 seconds) to show we're still waiting
                if attempt % 5 == 0:
                    self._log(
                        f"⏳ Waiting for ACME server... ({int(elapsed)}s elapsed)"
                    )
                time.sleep(2)

            result, _, _ = self._send_signed_request(url, None)

        return result

    def get_certificate(self, csr_path: str) -> str:
        """Request signed certificate from ACME server.

        Args:
            csr_path: Path to Certificate Signing Request file

        Returns:
            PEM-encoded signed certificate

        Raises:
            Various exceptions for ACME protocol errors
        """
        self._log("🔐 Requesting certificate from Let's Encrypt")

        # Parse account key
        self._log("Parsing account key...")
        pub_key_output = self._run_openssl(
            ["openssl", "rsa", "-in", self.config.account_key, "-noout", "-text"]
        )

        pub_pattern = r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
        match = re.search(
            pub_pattern, pub_key_output.decode("utf8"), re.MULTILINE | re.DOTALL
        )
        if not match:
            raise ValueError("Failed to parse account key")

        pub_hex, pub_exp = match.groups()
        pub_exp = f"{int(pub_exp):x}"
        pub_exp = f"0{pub_exp}" if len(pub_exp) % 2 else pub_exp

        self.alg = "RS256"
        self.jwk = {
            "e": self._b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": self._b64(
                binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))
            ),
        }
        accountkey_json = json.dumps(self.jwk, sort_keys=True, separators=(",", ":"))
        thumbprint = self._b64(hashlib.sha256(accountkey_json.encode("utf8")).digest())

        # Parse CSR to get domains
        self._log("Parsing CSR...")
        csr_output = self._run_openssl(
            ["openssl", "req", "-in", csr_path, "-noout", "-text"]
        )

        domains = set()
        common_name = re.search(
            r"Subject:.*? CN\s?=\s?([^\s,;/]+)", csr_output.decode("utf8")
        )
        if common_name:
            domains.add(common_name.group(1))

        san_match = re.search(
            r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n",
            csr_output.decode("utf8"),
            re.MULTILINE | re.DOTALL,
        )
        if san_match:
            for san in san_match.group(1).split(", "):
                if san.startswith("DNS:"):
                    domains.add(san[4:])

        if not domains:
            raise ValueError("No domains found in CSR")

        self._log(f"Found domains: {', '.join(sorted(domains))}")

        # Get ACME directory
        self._log("Getting directory...")
        self.directory, _, _ = self._http_request(self.config.directory_url)
        self._log("Directory found!")

        # Register account
        self._log("Registering account...")
        reg_payload = {"termsOfServiceAgreed": True}
        if self.config.contact:
            reg_payload["contact"] = self.config.contact

        account, code, self.acct_headers = self._send_signed_request(
            self.directory["newAccount"], reg_payload
        )

        if code == 201:
            self._log("Account registered!")
        else:
            self._log("Already registered!")

        # Create new order
        self._log("Creating new order...")
        order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        order, _, order_headers = self._send_signed_request(
            self.directory["newOrder"], order_payload
        )
        self._log("Order created!")

        # Complete authorizations
        for auth_url in order["authorizations"]:
            self._check_shutdown()

            authorization, _, _ = self._send_signed_request(auth_url, None)
            domain = authorization["identifier"]["value"]

            self._log(f"Verifying domain: {domain}")

            # Find http-01 challenge
            challenge = next(
                (c for c in authorization["challenges"] if c["type"] == "http-01"),
                None,
            )
            if not challenge:
                raise ValueError(f"No http-01 challenge found for {domain}")

            # Write challenge file
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge["token"])
            keyauth = f"{token}.{thumbprint}"
            challenge_path = Path(self.config.challenge_dir) / token

            challenge_path.write_text(keyauth)

            # Verify challenge file is accessible
            if not self.config.disable_check:
                wellknown_url = f"http://{domain}/.well-known/acme-challenge/{token}"
                try:
                    resp_data, _, _ = self._http_request(wellknown_url)
                    if resp_data != keyauth:
                        raise ValueError(
                            f"Challenge file mismatch: expected {keyauth}, got {resp_data}"
                        )
                except Exception as e:
                    raise ValueError(
                        f"Challenge file not accessible at {wellknown_url}: {e}"
                    )

            # Tell ACME server we're ready
            self._send_signed_request(challenge["url"], {})
            self._log(f"Waiting for ACME to validate challenge...")

            # Wait for validation
            authorization = self._poll_until_ready(auth_url, ["pending"], timeout=300)

            if authorization["status"] != "valid":
                raise ValueError(f"Authorization failed for {domain}: {authorization}")

            # Clean up challenge file
            challenge_path.unlink(missing_ok=True)
            self._log(f"✓ Domain verified: {domain}")

        # Finalize order with CSR
        self._log("Finalizing certificate order...")
        csr_der = self._run_openssl(
            ["openssl", "req", "-in", csr_path, "-outform", "DER"]
        )
        self._send_signed_request(order["finalize"], {"csr": self._b64(csr_der)})
        self._log("Waiting for ACME to issue certificate...")

        # Wait for certificate
        order = self._poll_until_ready(
            order_headers["Location"], ["pending", "processing"], timeout=300
        )

        if order["status"] != "valid":
            raise ValueError(f"Order failed: {order}")

        # Download certificate
        self._log("Downloading signed certificate...")
        cert_pem, _, _ = self._send_signed_request(order["certificate"], None)
        self._log("Certificate signed!")

        self._log("✅ Certificate issued successfully")
        return cert_pem


# Legacy function wrapper for backward compatibility
def get_crt(
    account_key: str,
    csr: str,
    acme_dir: str,
    log=None,  # Ignored - uses loguru
    CA: str = "",  # Deprecated
    disable_check: bool = False,
    directory_url: str = DEFAULT_DIRECTORY_URL,
    contact: list[str] | None = None,
    domain_context: str = "",  # Domain context for logging
) -> str:
    """Legacy function wrapper for backward compatibility.

    New code should use AcmeClient class directly.
    """
    # Handle deprecated CA parameter
    if CA and CA != "https://acme-v02.api.letsencrypt.org":
        directory_url = f"{CA}/directory"

    config = AcmeConfig(
        account_key=account_key,
        challenge_dir=acme_dir,
        directory_url=directory_url,
        contact=contact,
        disable_check=disable_check,
    )

    client = AcmeClient(config, domain_context=domain_context)
    return client.get_certificate(csr)
