# Private and Custom ACME CAs

lematt is built and tested against Let's Encrypt. This document covers
running it against other ACME servers: an internal CA for private
systems (step-ca), and Let's Encrypt's own CA software for integration
testing (Boulder). It lists what lematt needs before either works, how
each server would be set up, and what to watch for.

Status as of 2026-10-10: **not supported yet.** The ACME directory URLs
are fixed to Let's Encrypt, lematt only trusts the system CA store for
the ACME endpoint, and it can't register accounts that need External
Account Binding. [What lematt needs](#what-lematt-needs) describes the
changes.

## Why not grow lematt's test CA into one

`tests/fake_acme.py` is an in-process ACME server for lematt's tests. It
covers the protocol (accounts, orders, http-01, finalize, ARI,
revocation) in about 550 lines, but the protocol is the small part of a
CA:

| Area               | The test fake                   | A production CA needs                                                                                                                      |
| ------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| CA keys            | Throwaway key in memory         | Offline root, online intermediate, keys in an HSM or KMS, key ceremonies, rotation                                                         |
| Issuance policy    | Issues whatever is asked        | Name constraints limiting the CA to internal domains, rules for which accounts get which names, certificate linting, unpredictable serials |
| Validation         | Fetches tokens through the fake | Real http-01/dns-01 checks over the network, internal DNS, protection against spoofing                                                     |
| Accounts           | Anyone can register             | External Account Binding (only authorized systems get accounts), account key rollover                                                      |
| Revocation         | Marks a flag                    | Published CRLs, or certificates short-lived enough not to need them                                                                        |
| State and uptime   | In memory, single process       | Transactional database, nonces shared across replicas, high availability, rate limits, audit log, backups                                  |
| Trust distribution | Not applicable                  | The root installed in every OS, browser, JVM and container image that must trust it                                                        |

A CA is also a security dependency: whoever controls it can impersonate
every system that trusts it. Use an established CA server instead, and
keep the fake as lematt's fast test double.

## The servers

| Server                                            | Use it for                      | Notes                                                                                                                                                          |
| ------------------------------------------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [step-ca](https://smallstep.com/docs/step-ca/)    | A private CA for internal names | Built for internal PKI: ACME provisioners, issuance policies, configurable lifetimes, http-01, dns-01 and tls-alpn-01                                          |
| [Boulder](https://github.com/letsencrypt/boulder) | Integration testing only        | The software Let's Encrypt runs. Its README says it "is intended only to support the Web PKI" and that its Docker setup is "not suitable for production usage" |

## What lematt needs

Three changes would let lematt use any standards-compliant ACME server.
Each is self-contained.

### 1. Configurable directory URLs

`LemattConfig` already has `staging_url` and `production_url`, but the
config files can't set them. Proposed settings:

| TOML `[config]`          | INI `[config]`         | Used for | Default                  |
| ------------------------ | ---------------------- | -------- | ------------------------ |
| `acme_directory`         | `acmeDirectory`        | `--prod` | Let's Encrypt production |
| `acme_staging_directory` | `acmeStagingDirectory` | `--test` | Let's Encrypt staging    |

Notes:

- Saved accounts (`state/account.json`) already record their directory
  URL, so switching CAs registers a new account automatically.
- `--test` and `--prod` keep separate files and state, so a staging CA
  and a production CA stay apart, as they do for Let's Encrypt.
- `--caa-records` prints Let's Encrypt's CAA identity. It should use the
  directory's `meta.caaIdentities`, and say so when the CA has none.

### 2. Trusting a private root

An internal CA's ACME endpoint is served with a certificate from that CA.
Proposed setting: `acme_ca_bundle` / `acmeCABundle`, a PEM file of extra
trusted roots, used for:

- the ACME client's HTTPS connections (`lematt.acme.transport`)
- `--health-check --check-live`, which verifies served chains against
  the system store today

The http-01 self-check doesn't verify certificates, because the CA
doesn't either, so it needs no change. Installing the root system-wide
(`step certificate install` for step-ca) works without this setting but
affects every program on the host.

### 3. External Account Binding

CAs that restrict who may open an account hand out a key ID and an HMAC
key, which the client must bind to its first `newAccount` request
(RFC 8555 §7.3.4). Proposed settings:

- `eab_kid` / `eabKid`
- `eab_hmac_key_file` / `eabHmacKeyFile`: a file holding the
  base64url HMAC key, so the secret doesn't sit in the config

The binding is a JWS over the account's public JWK, signed with HS256
using the HMAC key, and placed in `externalAccountBinding`. It's only
needed at registration; the saved account is reused afterwards.
`tests/fake_acme.py` would learn to require and verify it.

### What already works

- **Renewal timing.** CAs without ARI have no `renewalInfo` in their
  directory, and lematt falls back to renewing with 1/3 of the lifetime
  left (half below 10 days).
- **Profiles.** Leave `profile` unset; lematt only requests profiles the
  CA advertises.
- **Revocation** works if the CA implements `revokeCert`.
- **http-01** works wherever the CA can reach the names on port 80.
  dns-01 isn't implemented yet ([challenges.md](challenges.md)).

## step-ca: a private CA for internal names

The examples use `internal.example` for internal names and
`ca.internal.example` for the CA.

### Set up the CA

```bash
# On the CA host (see step-ca's docs for installation)
step ca init --name "Internal CA" --dns ca.internal.example \
  --address :443 --provisioner admin@internal.example

# An ACME provisioner named "acme"
step ca provisioner add acme --type ACME

# Only issue for internal names (authority-wide policy)
step ca policy authority x509 allow dns "*.internal.example"

step-ca "$(step path)/config/ca.json"
```

- The ACME directory is
  `https://ca.internal.example/acme/acme/directory`
  (`/acme/<provisioner name>/directory`).
- The root certificate is `$(step path)/certs/root_ca.crt`. Copy it to
  the lematt host (e.g. `/etc/lematt/internal-root.pem`).
- `*.internal.example` doesn't cover `internal.example` itself; add it
  separately if needed.
- step-ca can require External Account Binding on an ACME provisioner
  (`--require-eab`) and issue keys with
  `step ca acme eab add acme <reference>`. Check Smallstep's
  documentation for which editions support it.

### Certificate lifetime

step-ca issues **24-hour** certificates by default. lematt would renew
them with 12 hours left, so it must run more often than that, plus the
timer's random delay. Either:

- install the timer with `--systemd-preset aggressive` (every 6 hours),
  or
- issue longer certificates to lematt's ACME provisioner, for example 30
  days:

  ```bash
  step ca provisioner update acme \
    --x509-default-dur=720h --x509-max-dur=2160h
  ```

  Then reload step-ca (`SIGHUP`) or restart it.

### Validation

step-ca validates http-01 like Let's Encrypt does: it resolves each name
and fetches the token from port 80. The names must resolve to the right
hosts from the CA host, and lematt's self-check needs them to resolve
from the lematt host too. `prepare` actions that forward challenges work
unchanged.

### Configure lematt (once supported)

```toml
[config]
challenge_dir = "/var/www/html/.well-known/acme-challenge"
account_key = "/etc/lematt/internal-account.key"
acme_directory = "https://ca.internal.example/acme/acme/directory"
acme_staging_directory = "https://ca-test.internal.example/acme/acme/directory"
acme_ca_bundle = "/etc/lematt/internal-root.pem"
# eab_kid = "..."
# eab_hmac_key_file = "/etc/lematt/internal-eab.key"

[[domains]]
primary = "app.internal.example"
sans = ["api.internal.example"]
```

```bash
uv run lematt --test --config /etc/lematt/lematt.toml --validate-config
uv run lematt --test --config /etc/lematt/lematt.toml
uv run lematt --prod --config /etc/lematt/lematt.toml --status
```

Use a separate lematt config directory (and account key) per CA, so
Let's Encrypt and internal certificates never share state or files.
Systems that serve these certificates must trust the internal root.

## Boulder: integration testing against Let's Encrypt's CA

Boulder is Let's Encrypt's CA software. Running it locally tests lematt
against the real server implementation (validation, problem documents,
ARI, profiles) instead of the fake. It is not a private CA: its README
recommends a centrally managed PKI for organizations evaluating it for
internal use.

### Run Boulder

```bash
git clone https://github.com/letsencrypt/boulder
cd boulder
docker compose run bsetup    # generate the test certificates once
docker compose up
```

- ACME directory: `http://localhost:4001/directory`, or
  `https://localhost:4431/directory` with the TLS root
  `test/certs/ipki/minica.pem`.
- Boulder's fake DNS resolves every name to 127.0.0.1. Set `FAKE_DNS` to
  the Docker host's address (in `docker-compose.yml` or with `-e`) so its
  validation requests reach the machine running lematt's webroot, and
  allow them through the host firewall.
- The Docker host needs at least 2 GB of RAM.

### Point lematt at it (once supported)

```toml
[config]
challenge_dir = "/tmp/lematt-boulder/challenges"
account_key = "/tmp/lematt-boulder/account.key"
acme_staging_directory = "https://localhost:4431/directory"
acme_ca_bundle = "/path/to/boulder/test/certs/ipki/minica.pem"

[[domains]]
primary = "lematt-test.example.com"
```

```bash
uv run lematt --test --config /tmp/lematt-boulder/lematt.toml
```

- Serve `challenge_dir` at `/.well-known/acme-challenge/` on port 80 of
  the address in `FAKE_DNS`.
- lematt fetches each token before asking the CA. Make the test names
  resolve to that address on the lematt host too (e.g. `/etc/hosts`), or
  the self-check fails before Boulder is asked.
- Boulder issues from throwaway test roots that nothing trusts.

### As a CI target

A CI job that starts Boulder's Docker setup and runs a lematt issue,
renew (with `replaces`) and revoke cycle against it would catch protocol
drift that the fake can't. It would sit next to the existing fast tests,
not replace them.

## References

- step-ca: https://smallstep.com/docs/step-ca/
- step-ca ACME clients and lifetimes:
  https://smallstep.com/docs/tutorials/acme-protocol-acme-clients/
- step-ca issuance policies: https://smallstep.com/docs/step-ca/policies/
- step CLI `ca acme eab add`:
  https://smallstep.com/docs/step-cli/reference/ca/acme/eab/add/
- Boulder: https://github.com/letsencrypt/boulder
- ACME External Account Binding: RFC 8555 §7.3.4
