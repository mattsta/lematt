# Domain Validation: Challenge Types, Wildcards, and What Comes Next

lematt proves control of each name with **http-01**. This document explains
what that allows, how to handle wildcard certificates today, and how the
DNS-based challenge types would fit into lematt, including what to watch
for before building them.

Status as of 2026-10-10.

## Challenge types at a glance

| Type             | Let's Encrypt       | lematt          | Proves control by                                                            | Wildcards                   |
| ---------------- | ------------------- | --------------- | ---------------------------------------------------------------------------- | --------------------------- |
| `http-01`        | Supported           | **Supported**   | Serving a token at `http://<name>/.well-known/acme-challenge/`               | No                          |
| `dns-01`         | Supported (years)   | Not implemented | A fresh `_acme-challenge.<name>` TXT record per validation                   | Yes                         |
| `dns-persist-01` | Announced, not live | Not implemented | One standing `_validation-persist.<name>` TXT record naming the ACME account | Yes, with `policy=wildcard` |
| `tls-alpn-01`    | Supported           | Not planned     | A special certificate on port 443 via ALPN                                   | No                          |

### http-01 in lematt

- Every name must answer on port 80, from anywhere: Let's Encrypt
  validates from several network perspectives with unpublished IPs.
- `challengeDropDir` must be served at `/.well-known/acme-challenge/` for
  every name, directly or through redirects. Hosts without that webroot
  use a `prepare` action (for example
  `ssh -tt <host> uv run leforward.py --baseurl http://<webroot host>`,
  with `contrib/leforward.py`) to redirect challenges to the host that
  has it.
- lematt fetches each token itself before asking the CA to validate, so
  misconfigurations fail without spending Let's Encrypt's failed-validation
  limit (5 per name per hour).
- Up to 100 names per certificate line.

`tls-alpn-01` isn't planned: it requires lematt to answer TLS on port 443
during validation, which conflicts with the web servers lematt deploys to.

## Wildcard certificates today

Let's Encrypt only issues wildcards (`*.example.com`) after DNS validation,
so lematt can't issue them. Options, in order of preference:

1. **List the names instead.** A certificate line holds up to 100 names
   (`example.com www api mail …`). This is usually simplest with lematt:
   no DNS credentials, and the deploy actions already handle the result.
2. **Use a DNS-capable ACME client for the wildcard names only** (for
   example lego, acme.sh, or certbot with a DNS plugin) and keep lematt for
   everything else. Deploy its output with that client's own hooks.
3. **Mind your CAA records.** If you published lematt's `--caa-records`
   (`issue "letsencrypt.org; accounturi=…; validationmethods=http-01"`),
   the other client also needs permission. Add an `issuewild` record for
   its account and `dns-01`, for example:

   ```
   example.com. IN CAA 0 issuewild "letsencrypt.org; accounturi=<other client's account URL>; validationmethods=dns-01"
   ```

   `issuewild` governs wildcard certificates separately from `issue`.

## dns-01 in lematt (when needed)

dns-01 works with Let's Encrypt today; lematt just doesn't implement it.
Design notes for adding it:

- **Configuration.** A per-certificate option `challenge=dns-01` on domains
  lines (`[[domains]] challenge = "dns-01"` in TOML), with hook commands
  in the action groups, consistent with `prepare`/`update`:
  - `dnsPresent`: create the TXT record, with placeholders `RECORD`
    (`_acme-challenge.<name>`) and `VALUE` (base64url of SHA-256 of the
    key authorization)
  - `dnsCleanup`: remove it again

  Wildcard names (`*.example.com`) would be allowed only on dns-01 lines,
  and filenames would need the `*` mapped to something safe.

- **Code.** A `lematt.acme.dns01.Dns01Solver` implementing the existing
  `ChallengeSolver` protocol (`present`/`cleanup`).
  `AcmeClient.complete_authorizations()` currently always picks http-01;
  it would pick the challenge matching the solver's type instead.
- **Propagation.** After `dnsPresent`, poll the zone's authoritative name
  servers until every one serves the value (with a timeout) before asking
  the CA to validate. Remove stale values so responses stay small.
- **Least-privilege DNS.** Recommend CNAME delegation: point
  `_acme-challenge.example.com` at a record in a dedicated validation zone,
  so lematt's DNS credentials can't change anything else.
- **Shorter authorization reuse.** Let's Encrypt cuts authorization reuse
  to 10 days (February 2027) and 7 hours (February 2028), so dns-01 hooks
  will run on nearly every renewal. dns-persist-01 avoids that.
- **Tests.** Extend `tests/fake_acme.py` with a DNS lookup hook, the way it
  already serves http-01 tokens.

## dns-persist-01 (not live yet)

**What it is.** One long-lived TXT record authorizes a specific ACME
account to get certificates for a name, with no per-renewal DNS changes:

```
_validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"
```

Optional parameters:

- `policy=wildcard`: also covers `*.example.com` and subdomains
- `persistUntil=<unix seconds>`: the record stops working at that time
  and must be renewed before then

Authorization comes from the account, so the ACME account key becomes the
asset to protect.

**Status.** CA/Browser Forum ballot SC-088v3 passed in October 2025 and the
IETF ACME working group adopted the draft. Let's Encrypt announced support
in February 2026 (staging late Q1, production "some time in Q2 2026"), but
the rollout slipped pending draft revisions, including wildcard procedures.
As of 2026-10-10 it isn't available in production; Pebble supports the
draft. One industry estimate (not Let's Encrypt's) is mid-2027.

**How it would fit lematt.** lematt already persists its account URL
(`state/account.json`) and prints account-bound CAA records, so the pieces
line up:

- `--dns-persist-records`, like `--caa-records`: print the
  `_validation-persist` records for each configured name, with
  `policy=wildcard` for wildcard lines and an optional `persistUntil`.
- A solver with no per-renewal work: check (via DNS) that the record
  exists and names lematt's account, then accept the CA's
  `dns-persist-01` challenge.
- Opt in per certificate with `challenge=dns-persist-01`; allow wildcard
  names on such lines.
- Health checks warn ahead of `persistUntil` expiry and when the record no
  longer matches the account (for example after an account key change).
- Its own tests against the fake CA, plus a Pebble integration test once a
  Pebble binary is available in CI.

**When to build it.** Watch for any of these:

- A Let's Encrypt announcement (blog or the API Announcements category on
  community.letsencrypt.org) that dns-persist-01 is in production
- `dns-persist-01` listed on https://letsencrypt.org/docs/challenge-types/
- Production authorizations offering a `dns-persist-01` challenge (staging
  first: `uv run lematt --test` against the staging directory)
- The draft (draft-ietf-acme-dns-persist) becoming an RFC, or lego/certbot
  releases with support

## References

- Let's Encrypt challenge types: https://letsencrypt.org/docs/challenge-types/
- DNS-PERSIST-01 announcement: https://letsencrypt.org/2026/02/18/dns-persist-01
- Deployment status thread: https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468
- CAA account and method binding: RFC 8657
- ACME: RFC 8555; renewal information (ARI): RFC 9773
