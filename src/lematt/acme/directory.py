"""The ACME directory object (RFC 8555 section 7.1.1) and its extensions."""

from dataclasses import dataclass, field
from typing import Any

from lematt.acme.errors import AcmeProtocolError

LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


@dataclass(frozen=True)
class Directory:
    """Endpoints and capabilities advertised by an ACME server.

    Attributes:
        renewal_info: ARI endpoint (RFC 9773), if the server supports it.
        profiles: Certificate profiles the server offers (name -> description
            URL), from the ACME profiles extension.
    """

    new_nonce: str
    new_account: str
    new_order: str
    revoke_cert: str | None = None
    key_change: str | None = None
    renewal_info: str | None = None
    terms_of_service: str | None = None
    website: str | None = None
    caa_identities: tuple[str, ...] = ()
    profiles: dict[str, str] = field(default_factory=dict)
    external_account_required: bool = False

    @classmethod
    def from_json(cls, data: Any) -> Directory:
        if not isinstance(data, dict):
            raise AcmeProtocolError("", "ACME directory is not a JSON object")
        missing = [k for k in ("newNonce", "newAccount", "newOrder") if k not in data]
        if missing:
            raise AcmeProtocolError("", f"ACME directory lacks {', '.join(missing)}")
        meta = data.get("meta") or {}
        return cls(
            new_nonce=data["newNonce"],
            new_account=data["newAccount"],
            new_order=data["newOrder"],
            revoke_cert=data.get("revokeCert"),
            key_change=data.get("keyChange"),
            renewal_info=data.get("renewalInfo"),
            terms_of_service=meta.get("termsOfService"),
            website=meta.get("website"),
            caa_identities=tuple(meta.get("caaIdentities") or ()),
            profiles=dict(meta.get("profiles") or {}),
            external_account_required=bool(meta.get("externalAccountRequired")),
        )
