# lematt - Matt's Let's Encrypt Automation

lematt issues and renews Let's Encrypt certificates for many domains and
deploys them to the servers that use them. It renews when Let's Encrypt
suggests (ACME Renewal Information), validates with http-01, keeps state
between runs, and runs your upload and reload commands per group of domains.

## Features

- **CA-guided renewal**: renews inside the window Let's Encrypt suggests for
  each certificate (ARI, RFC 9773), with a lifetime-based fallback that
  adapts to shorter certificate lifetimes
- **RSA and EC**: every certificate line gets an RSA and an EC (ECDSA)
  certificate
- **Multi-name certificates**: up to 100 names per certificate, validated
  with http-01 (see [docs/challenges.md](docs/challenges.md) for wildcards)
- **ACME profiles**: `classic`, `tlsserver` or `shortlived`, globally or per
  certificate
- **Deployment actions**: `prepare` commands while validating (e.g.
  challenge forwarders on other hosts), then upload and reload commands per
  group of domains
- **Safe under failure**: per-certificate error isolation, backoff after
  failures, a run lock against overlapping runs, atomic file installs
- **Revocation**: revoke, re-issue and redeploy in one command
- **Monitoring**: lifetime-aware health checks, Prometheus metrics, JSON
  output, and alerts by email, Slack/Discord/generic webhook, PagerDuty,
  ntfy, journald or a custom command
- **Automation**: systemd timer and service, printed or installed
- **Terminal tools**: live dashboard, inventory and renewal reports, and
  searchable help topics
- **Configuration**: one TOML file, or the classic INI files
- **Test mode**: the Let's Encrypt staging environment, with separate files
  and state

## Requirements

- [uv](https://docs.astral.sh/uv/) (installs Python 3.14 and lematt's
  dependencies)
- A web server that serves one directory at
  `http://<name>/.well-known/acme-challenge/` for every name, reachable on
  port 80 from anywhere (or a `prepare` action that forwards challenges)
- An ACME account key

## Quick Start

All commands run from the lematt checkout; `uv run` uses its environment.

```bash
git clone https://github.com/mattsta/lematt
cd lematt
uv sync

# ACME account key
mkdir -p /etc/lematt
openssl genrsa 4096 > /etc/lematt/account.key
chmod 600 /etc/lematt/account.key
```

Write a configuration: either edit the INI files in `conf/` (the default
`--config` is `conf/lematt.conf`), or create a TOML file:

```bash
# Writes conf/lematt.toml (next to --config); edit it, then pass it as --config
uv run lematt --init-toml
```

Check it, then issue staging certificates:

```bash
uv run lematt --test --config conf/lematt.toml --validate-config
uv run lematt --test --config conf/lematt.toml --list-domains
uv run lematt --test --config conf/lematt.toml --dry-run
uv run lematt --test --config conf/lematt.toml
uv run lematt --test --config conf/lematt.toml --status
```

When staging works, switch to production and schedule it:

```bash
uv run lematt --prod --config conf/lematt.toml
sudo uv run lematt --prod --config "$PWD/conf/lematt.toml" --install-systemd
```

`--test` and `--prod` keep separate files and state, so a staging run never
touches production certificates. Production rate limits are low (5
certificates per exact set of names per 7 days, and each line uses two:
RSA and EC); always validate changes with `--test` first.

> If `uv` isn't on root's `PATH`, use `sudo "$(command -v uv)" run lematt ...`.

---

## How It Works

### Processing Flow

```
1. Load the configuration (TOML or INI) and validate it
2. Take the run lock (an overlapping run exits with code 75)
3. For each certificate line (in parallel with --parallel N):
   a. Refresh the CA's renewal window (ARI) when the CA's Retry-After allows
   b. Decide per key type: ARI window, lifetime fallback, overrides, backoff
   c. If either key type is due: start the line's prepare actions
   d. Generate the key and CSR if needed, order (with `replaces`), check each
      http-01 token is reachable, let the CA validate, download the chain
   e. Install the files atomically, record the result, stop prepare actions
4. After all lines: run upload and update actions once per action group
5. Send notifications for the run (failures, early renewals, revocations,
   renewals)
```

Deployment still runs after Ctrl-C/SIGTERM for whatever was renewed
(exit code 130). The first signal stops new lines from starting and lets
in-flight ones finish; a second one terminates the workers.

### Renewal Timing

1. **ARI first.** Let's Encrypt suggests a renewal window for every
   certificate (RFC 9773). lematt fetches it when the CA's Retry-After
   allows (clamped to between 1 minute and 1 day, 6 hours by default),
   picks a random moment inside the window, and renews then. The CA can
   move the window earlier, for example ahead of a mass revocation; lematt
   logs the explanation URL and sends a warning notification.
2. **Lifetime fallback.** Without ARI data, lematt renews when 1/3 of the
   certificate's lifetime remains (half for certificates valid less than
   10 days). This stays correct as Let's Encrypt shortens lifetimes to 64
   days (February 2027) and 45 days (February 2028).
3. **Operator overrides** (`reauthorize_days`,
   `generate_new_certs_after_days`) can only make renewal earlier.
   `reauthorize_days` is ignored for certificates whose whole lifetime is
   shorter, because it would renew them on every run.
4. **Backoff.** After a failure, lematt waits 1 minute, 10 minutes, 100
   minutes, then a day between attempts, or longer if the CA's Retry-After
   asks (rate limits), so a broken configuration can't exhaust Let's
   Encrypt's limits. `--force-renew` retries immediately.

Transient errors (network, 5xx) are retried up to 3 times within a run.
Orders for certificates lematt issued carry `replaces` (the ARI ID of the
old certificate), and lematt retries without it if the CA refuses.

`--status` shows when each certificate renews and why.

### State

State lives in `<config dir>/<prod|test>/state/`:

| Path                | Contents                                                        |
| ------------------- | --------------------------------------------------------------- |
| `account.json`      | ACME account URL (reused instead of looking the account up)     |
| `certs/<cert>.json` | Issued serial and ARI ID, renewal window, revocation, attempts  |
| `history.jsonl`     | Append-only event log (rotated to `history.jsonl.1` above 5 MB) |
| `run.lock`          | Held during a run or revocation; an overlapping run exits 75    |

lematt rebuilds missing state from the certificates on disk. Deleting it
forgets the ARI windows, failure history and revocation marks, and the
next renewal of each certificate is ordered without `replaces`. `--dry-run`
takes no lock, writes no state and fetches no ARI.

### Files

Keys, certificates and CSRs live below the config directory, per mode:

```
<config dir>/prod/key/example.com-key.rsa2048.pem
<config dir>/prod/cert/example.com-cert-combined.rsa2048.pem
<config dir>/prod/csr/example.com-csr.rsa2048.csr
<config dir>/test/cert/example.com-cert-combined.prime256v1.test.pem
```

The tags come from `rsa_tag`/`curve_tag` (default `rsa<bits>` and the curve
name). A multi-name line is named after all its names joined with `_`
(`example.com_www.example.com-...`), and each name also gets a symlink to
it (`www.example.com-cert-combined.rsa2048.pem`). Private keys are written
with mode 0600. New files replace old ones atomically.

### Source Layout

```
src/lematt/
├── cli.py            # Command-line interface: one handler per command
├── config.py         # Configuration dataclasses and file naming
├── config_loader.py  # INI/TOML loading and validation, --init-toml template
├── manager.py        # CertificateManager: plan, issue, install, record, revoke;
│                     # prepare actions
├── renewal.py        # Renewal policy: ARI window, lifetime fallback, backoff
├── state.py          # Persistent state: account, per-certificate, history, run lock
├── session.py        # Shared ACME session (transport + account) per certificate line
├── acme/             # ACME client: JWS, transport, directory, orders, http-01,
│                     # ARI (RFC 9773), revocation, problem documents
├── executor.py       # Sequential/parallel runs, error isolation, signal handling
├── actions.py        # ActionRunner: upload and update actions per action group
├── crypto.py         # Keys, CSRs, certificate parsing (cryptography library)
├── health.py         # Lifetime- and renewal-aware health checks, Prometheus metrics
├── notifications.py  # Alert backends (email, webhooks, PagerDuty, ntfy, ...)
├── systemd.py        # systemd service/timer units (print or install)
├── reports.py        # Inventory and renewal reports (console, JSON, Markdown)
├── help.py           # Help topics (--help-topic, --help-search)
├── display.py        # Rich styles and console helpers
├── log.py            # Loguru logging (EVENT level for --cron)
└── tui/              # Interactive --dashboard (Textual)
```

---

## Configuration

`--config` names the main file (default `conf/lematt.conf`, relative to
the current directory). A `.toml` file is read as TOML; anything else as
INI. Keys, certificates and state are written below the same directory.

| File           | Format | Purpose                                                    |
| -------------- | ------ | ---------------------------------------------------------- |
| `lematt.toml`  | TOML   | Settings, plus optional domains, actions and notifications |
| `lematt.conf`  | INI    | Settings                                                   |
| `domains`      | Text   | Certificate lines (INI, or TOML without `[[domains]]`)     |
| `actions.conf` | INI    | Action groups (INI, or TOML without `[actions.*]`)         |

With an INI config, notifications come from the `[notifications]` table of
a `lematt.toml` in the same directory, if there is one.

### TOML

```toml
[config]
# Served at http://<name>/.well-known/acme-challenge/ for every name
challenge_dir = "/var/www/html/.well-known/acme-challenge"
account_key = "/etc/lematt/account.key"

key_bits_rsa = 2048
ec_curve = "prime256v1"
always_generate_new_keys = false

# Optional
# profile = "tlsserver"
# reauthorize_days = 30
# generate_new_certs_after_days = 7

[[domains]]
primary = "example.com"
sans = ["www", "api"]            # shorthand for www.example.com, api.example.com

[[domains]]
primary = "cdn.example.com"
sans = ["static.example.com"]    # full names work too

[[domains]]
primary = "mail.example.com"
sans = ["smtp.example.com"]
profile = "shortlived"           # this certificate only

[actions.default]
upload_certs = ["rsync -avz --chmod=F644 CERTS /etc/ssl/certs/"]
upload_keys = ["rsync -avz --chmod=F640 KEYS /etc/ssl/private/"]
update = ["systemctl reload nginx"]

[actions.every]
update = ["/usr/local/bin/backup-certs.sh"]

[actions.mail]
domains = ["mail.example.com", "smtp.example.com"]
prepare = ["ssh -tt forwarder.example.net uv run leforward.py --baseurl http://example.com"]
upload_certs = ["rsync -avz CERTS mail.example.net:/etc/ssl/certs/"]
upload_keys = ["rsync -avz KEYS mail.example.net:/etc/ssl/private/"]
update = [
    "ssh mail.example.net sudo systemctl reload postfix",
    "ssh mail.example.net sudo systemctl reload dovecot",
]

[notifications]
email_to = "admin@example.com"
```

`uv run lematt --init-toml` writes a commented starting point.

#### `[config]`

| Key                             | Type   | Default      | Description                                 |
| ------------------------------- | ------ | ------------ | ------------------------------------------- |
| `challenge_dir`                 | string | required     | Webroot directory for http-01 tokens        |
| `account_key`                   | string | required     | ACME account key (RSA, or EC P-256/P-384)   |
| `key_bits_rsa`                  | int    | 2048         | RSA key size (2048 to 4096)                 |
| `ec_curve`                      | string | "prime256v1" | `prime256v1` (= `secp256r1`) or `secp384r1` |
| `always_generate_new_keys`      | bool   | false        | New private keys on every renewal           |
| `profile`                       | string | CA default   | ACME profile for all certificates           |
| `reauthorize_days`              | float  | unset        | Renew no later than N days before expiry    |
| `generate_new_certs_after_days` | float  | 0 (off)      | Renew once a certificate is N days old      |
| `rsa_tag`                       | string | "rsa{bits}"  | Filename tag for RSA files                  |
| `curve_tag`                     | string | "{curve}"    | Filename tag for EC files                   |

`challenge_dir` must exist for runs, `--revoke` and `--test-notification`;
read-only commands don't need it. Unknown keys are warned about.

#### `[[domains]]`

| Key       | Type         | Default  | Description                                               |
| --------- | ------------ | -------- | --------------------------------------------------------- |
| `primary` | string       | required | Primary name (certificate subject)                        |
| `sans`    | list[string] | []       | More names; a name without a dot means `<name>.<primary>` |
| `profile` | string       | unset    | ACME profile for this certificate                         |

#### `[actions.<group>]`

| Key            | Type         | Description                                               |
| -------------- | ------------ | --------------------------------------------------------- |
| `domains`      | list[string] | Names this group handles (required; not in default/every) |
| `prepare`      | list[string] | Started before validation, stopped after (`DOMAIN`)       |
| `upload_certs` | list[string] | Upload renewed certificates (`CERTS`)                     |
| `upload_keys`  | list[string] | Upload their private keys (`KEYS`)                        |
| `update`       | list[string] | Run after uploads (`DOMAINS_CN`, `DOMAINS_ALL`)           |

See [Deployment Actions](#deployment-actions) for how groups match and run.

### INI

**lematt.conf**

```ini
[config]
challengeDropDir: /var/www/html/.well-known/acme-challenge
accountKey: /etc/lematt/account.key
keyBitsRSA: 2048
curve: prime256v1
alwaysGenerateNewKeys: no

# Optional
#profile: tlsserver
#reauthorizeDays: 30
#generateNewCertsAfterDays: 7
#rsaTag: rsa2048
#curveTag: prime256v1
```

**domains**: one certificate line per line; the first name is the primary
name, the rest are added to the same certificate.

```
# Lines starting with # are comments (no comments after names)
example.com www api
cdn.example.com static.example.com
mail.example.com smtp profile=shortlived
```

`profile=NAME` selects an ACME profile for that line. Lines with the
obsolete `+ocsp`/`-ocsp` flags still load; the flags are ignored with a
warning because Let's Encrypt no longer supports OCSP.

**actions.conf**: commands are JSON lists; `domains` is space-separated.

```ini
[default]
uploadCerts: ["rsync -avz --chmod=F644 CERTS /etc/ssl/certs/"]
uploadKeys: ["rsync -avz --chmod=F640 KEYS /etc/ssl/private/"]
update: ["systemctl reload nginx"]

[every]
update: ["/usr/local/bin/backup-certs.sh"]

[mail]
domains: mail.example.com smtp.example.com
prepare: ["ssh -tt forwarder.example.net uv run leforward.py --baseurl http://example.com"]
uploadCerts: ["rsync -avz CERTS mail.example.net:/etc/ssl/certs/"]
uploadKeys: ["rsync -avz KEYS mail.example.net:/etc/ssl/private/"]
update: ["ssh mail.example.net sudo systemctl reload postfix"]
```

`conf/` holds commented versions of all three files.

### INI to TOML

| INI                            | TOML                                                            |
| ------------------------------ | --------------------------------------------------------------- |
| `challengeDropDir: /path`      | `challenge_dir = "/path"`                                       |
| `accountKey: /path`            | `account_key = "/path"`                                         |
| `keyBitsRSA: 2048`             | `key_bits_rsa = 2048`                                           |
| `curve: prime256v1`            | `ec_curve = "prime256v1"`                                       |
| `alwaysGenerateNewKeys: yes`   | `always_generate_new_keys = true`                               |
| `profile: tlsserver`           | `profile = "tlsserver"`                                         |
| `reauthorizeDays: 30`          | `reauthorize_days = 30`                                         |
| `generateNewCertsAfterDays: 7` | `generate_new_certs_after_days = 7`                             |
| `rsaTag` / `curveTag`          | `rsa_tag` / `curve_tag`                                         |
| `example.com www profile=X`    | `[[domains]]` with `primary`, `sans = ["www"]`, `profile = "X"` |
| `[name]` in actions.conf       | `[actions.name]`                                                |
| `domains: a.com b.com`         | `domains = ["a.com", "b.com"]`                                  |
| `uploadCerts` / `uploadKeys`   | `upload_certs` / `upload_keys`                                  |
| `prepare`, `update`            | `prepare`, `update`                                             |

TOML action keys must use the snake_case names; others are ignored.

---

## Deployment Actions

### Groups

| Group     | Applies to                                             |
| --------- | ------------------------------------------------------ |
| `default` | Names not listed in any other group                    |
| `every`   | Every renewed certificate, in addition to its group(s) |
| any name  | The names in its `domains` list                        |

Groups match per name, SANs included. A certificate whose names fall into
two groups is deployed by both (each with the whole certificate), so keep
a certificate's names in one group. A name listed in several groups
belongs to the last one.

### When They Run

1. **prepare**: only when a certificate line is due. Each name's group
   (and `every`) starts its prepare commands in the background, with
   `DOMAIN` replaced by that name. They keep running while the RSA and EC
   certificates are validated, then get SIGTERM (SIGKILL after 2 seconds).
   Prepare actions for the same name never overlap across parallel workers.
2. After all certificate lines are processed, each group with renewed
   certificates runs, once:
   1. **upload_certs**
   2. **upload_keys**
   3. **update**

A failed command is logged and doesn't stop the remaining commands or
change the exit code.

### Placeholders

| Placeholder   | In             | Expands to                                                               |
| ------------- | -------------- | ------------------------------------------------------------------------ |
| `DOMAIN`      | `prepare`      | The name being validated                                                 |
| `CERTS`       | `upload_certs` | One quoted glob per renewed name: `'/etc/lematt/prod/cert/example.com'*` |
| `KEYS`        | `upload_keys`  | The same for keys: `'/etc/lematt/prod/key/example.com'*`                 |
| `DOMAINS_CN`  | `update`       | The primary names renewed in this group                                  |
| `DOMAINS_ALL` | `update`       | Every name renewed in this group, SANs included                          |

Each glob matches the RSA and EC files and the name's symlinks, so
`rsync -avz CERTS host:/etc/ssl/` copies everything for those names.

### Forwarding Challenges from Other Hosts

http-01 tokens are written to `challenge_dir` on the lematt host. For names
served elsewhere, copy [`contrib/leforward.py`](contrib/leforward.py)
(standard library only) to that host and start it from a `prepare` action.
While validation runs, it listens on port 80 and redirects
`/.well-known/acme-challenge/` requests to a host that serves
`challenge_dir`:

```toml
prepare = ["ssh -tt forwarder.example.net uv run leforward.py --baseurl http://example.com"]
```

The ssh user needs permission to bind port 80 on the forwarding host.

Use `ssh -tt`: it forces a pseudo-terminal even when lematt runs without
one (cron, systemd), so the remote forwarder exits when lematt ends the
session. lematt warns about prepare commands using a single `-t`.
[`contrib/ssh-transfer-only.sh`](contrib/ssh-transfer-only.sh) is a forced
command for `authorized_keys` that limits an upload key to `scp`/`rsync`.

---

## Commands

Every command except `--help-topic`, `--help-search` and `--init-toml` needs
`--test` (staging) or `--prod` (production).

### Renewing

```bash
uv run lematt --test                          # staging run
uv run lematt --prod                          # production run
uv run lematt --prod --cron                   # quiet unless something changes
uv run lematt --prod --parallel 5             # up to 5 certificate lines at once (max 10)
uv run lematt --prod --domain example.com     # only lines containing this name
uv run lematt --prod --dry-run                # show what would happen
uv run lematt --prod --force-renew --domain example.com   # renew now, ignoring timing
```

Exit codes: 0 success, 1 a certificate failed or the configuration is
invalid, 75 another run holds the lock (nothing done), 130 interrupted.

`--parallel` runs certificate lines in separate processes; each line's RSA
and EC certificates are issued together.

### Inspecting

```bash
uv run lematt --prod --status                 # renewal status table
uv run lematt --prod --status --json          # the same as JSON
uv run lematt --prod --status --domain example.com
uv run lematt --prod --list-domains [--json]  # configured certificate lines
uv run lematt --prod --validate-config        # check settings, domains and actions
uv run lematt --prod --caa-records            # CAA records for your names
```

`--validate-config` checks the configuration itself; missing challenge
directories or account keys show up on the first run.

```
Domain                    Expires      Days Left  Renews                Status
--------------------------------------------------------------------------------
example.com (RSA)         2026-12-19   69         2026-11-19 (lifetime) ✅ OK
example.com (EC)          2026-12-19   69         2026-11-19 (lifetime) ✅ OK
api.example.com (RSA)     2026-10-25   14         now (lifetime)        🟡 RENEW SOON
api.example.com (EC)      N/A          N/A        now (missing)         ⚠️  MISSING
```

### Configuration Helpers

```bash
uv run lematt --init-toml                     # write an example lematt.toml next to --config
uv run lematt --test --config /etc/lematt/lematt.toml --validate-config
uv run lematt --test -v                       # debug output
```

### All Options

```
usage: lematt [-h] [--prod | --test] [--cron] [--parallel N] [--config PATH]
              [-v] [--dry-run] [--status] [--json] [--list-domains]
              [--validate-config] [--domain NAME] [--force-renew]
              [--init-toml] [--caa-records] [--print-systemd-units]
              [--install-systemd] [--uninstall-systemd] [--systemd-status]
              [--systemd-preset {default,aggressive,conservative}] [--revoke]
              [--reason {unspecified,keyCompromise,superseded,cessationOfOperation}]
              [--key-type {rsa,ec}] [--sign-with-certificate-key] [--replace]
              [--yes] [--health-check] [--check-live] [--warning-days N]
              [--critical-days N] [--prometheus] [--write-health PATH]
              [--test-notification] [--dashboard]
              [--dashboard-refresh SECONDS] [--dashboard-compact] [--report]
              [--report-output PATH] [--report-format {console,json,markdown}]
              [--help-topic [TOPIC]] [--help-search QUERY]
```

`uv run lematt --test --help` describes each option.

---

## JSON Output

### `--status --json`

```json
{
  "certificates": [
    {
      "domain": "example.com",
      "san_domains": ["www.example.com"],
      "key_type": "rsa",
      "profile": null,
      "cert_path": "/etc/lematt/prod/cert/example.com_www.example.com-cert-combined.rsa2048.pem",
      "exists": true,
      "expires": "2026-12-19T22:04:55",
      "days_until_expiry": 69,
      "status": "ok",
      "renewal": {
        "renew_now": false,
        "due_at": "2026-11-19T22:04:55",
        "basis": "lifetime",
        "reason": "next renewal 2026-11-19 22:04 UTC (lifetime)",
        "blocked_until": null,
        "ari_window": null,
        "last_success": null,
        "last_failure": null,
        "last_error": null,
        "consecutive_failures": 0
      }
    }
  ],
  "summary": {
    "total": 4,
    "ok": 2,
    "renew_soon": 1,
    "critical": 0,
    "expired": 0,
    "missing": 1
  }
}
```

- `status` is one of `ok`, `renew_soon` (renewal due or backing off),
  `critical` (under 1/10 of the lifetime left), `expired`, `missing`,
  `revoked`, `parse_error` or `unknown`. The summary counts the first five.
- `renewal.basis` says what set the renewal time: `ari`, `lifetime`,
  `reauthorizeDays`, `generateNewCertsAfterDays`, `missing`, `unreadable`,
  `revoked` or `forced`. `blocked_until` is set while lematt backs off
  after failures.
- `ari_window` has `start`, `end` and `explanation_url` once ARI is known.
- Times are UTC.

### `--list-domains --json`

```json
[
  {
    "primary": "example.com",
    "sans": ["www.example.com", "api.example.com"],
    "all_domains": ["example.com", "www.example.com", "api.example.com"]
  }
]
```

---

## Revoking Certificates

```bash
# See what would be revoked
uv run lematt --prod --revoke --domain example.com --dry-run

# Replaced by a new certificate: revoke, re-issue and deploy right away
uv run lematt --prod --revoke --domain example.com --reason superseded --replace

# Private key exposed: revoke, re-issue with NEW keys, deploy (no prompt)
uv run lematt --prod --revoke --domain example.com --reason keyCompromise --replace --yes

# Site retired / names no longer yours
uv run lematt --prod --revoke --domain old.example.com --reason cessationOfOperation
```

- `--domain` selects the configured lines containing that name (both key
  types; `--key-type rsa|ec` for one). lematt lists the certificates and
  asks you to type `revoke` unless `--yes` is given; without a terminal,
  `--yes` is required.
- Reasons are the ones Let's Encrypt accepts: `unspecified` (default),
  `keyCompromise`, `superseded`, `cessationOfOperation`.
- Revocation is signed with lematt's ACME account, or with the
  certificate's own key via `--sign-with-certificate-key` (useful if the
  account key is lost).
- Revoked certificates show as `revoked` in `--status`, are critical in
  health checks, and are renewed by the next run if `--replace` wasn't
  used. Revocations are recorded in `history.jsonl` and notified.

## Validation and Wildcards

lematt validates names with http-01, so it can't issue wildcard
certificates (Let's Encrypt requires DNS validation for those). List the
names on a certificate line instead (up to 100), or use a DNS-capable
client for wildcard names. [docs/challenges.md](docs/challenges.md) covers
the options, the CAA interplay, and how dns-01 and the upcoming
dns-persist-01 would be added to lematt.

---

## Automated Renewals with systemd

Install lematt somewhere stable (e.g. `/opt/lematt`) and give it an
absolute `--config`; the unit runs lematt with the same config and mode:

```bash
cd /opt/lematt
sudo uv run lematt --prod --config /etc/lematt/lematt.toml --install-systemd
sudo uv run lematt --prod --config /etc/lematt/lematt.toml --install-systemd --systemd-preset aggressive
uv run lematt --prod --systemd-status [--json]
sudo uv run lematt --prod --uninstall-systemd

# Print the units instead (for configuration management)
uv run lematt --prod --config /etc/lematt/lematt.toml --print-systemd-units
```

`--install-systemd` writes the units to `/etc/systemd/system`, reloads
systemd and enables and starts the timer; `--dry-run` shows what install
or uninstall would do.

| Preset         | Schedule                       | Random delay |
| -------------- | ------------------------------ | ------------ |
| `default`      | `*-*-* 00,12:00:00` (2x daily) | 1 hour       |
| `aggressive`   | `*-*-* 00,06,12,18:00:00`      | 30 minutes   |
| `conservative` | `*-*-* 03:00:00` (daily)       | 2 hours      |

Let's Encrypt recommends checking at least twice a day; renewal timing
itself comes from the CA, so frequent runs cost nothing when nothing is
due.

```ini
# /etc/systemd/system/lematt-renew.service
[Unit]
Description=Lematt Certificate Renewal
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/mattsta/lematt

[Service]
Type=oneshot
User=root
WorkingDirectory=/etc/lematt
ExecStart=/opt/lematt/.venv/bin/python3 -m lematt --config /etc/lematt/lematt.toml --prod --cron
TimeoutStartSec=3h
SuccessExitStatus=75
PrivateTmp=true
SyslogIdentifier=lematt-renew

# /etc/systemd/system/lematt-renew.timer
[Unit]
Description=Lematt Certificate Renewal Timer
Documentation=https://github.com/mattsta/lematt

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

`ExecStart` runs the project environment's Python that `uv run` used for
the install, so scheduled runs don't depend on `uv` or network access to
start. Exit code 75 (the previous run is still going) isn't a failure.
The service isn't sandboxed (no `ProtectSystem`/`ProtectHome`/
`NoNewPrivileges`) because deployment actions need ssh keys, arbitrary
upload paths and `sudo`; add a drop-in if your actions allow hardening.

```bash
sudo systemctl start lematt-renew.service     # run now
journalctl -u lematt-renew.service -f         # follow the logs
systemctl list-timers lematt-renew.timer      # next run
```

---

## Health Checks and Monitoring

Let's Encrypt no longer sends expiry emails; monitor your certificates.

```bash
uv run lematt --prod --health-check
uv run lematt --prod --health-check --json
uv run lematt --prod --health-check --prometheus
uv run lematt --prod --health-check --check-live      # also check what servers serve
uv run lematt --prod --health-check --warning-days 21 --critical-days 7
uv run lematt --prod --health-check --prometheus --write-health /var/lib/node_exporter/textfile/lematt.prom
```

```
Health Check: ✗ critical
Certificates: 1 critical, 1 warning, 2 healthy
------------------------------------------------------------
  ✓ example.com (rsa): Certificate valid for 69 days; renews 2026-11-19 (lifetime)
  ✓ example.com (ec): Certificate valid for 69 days; renews 2026-11-19 (lifetime)
  ⚠ api.example.com (rsa): Renewal overdue since 2026-09-25 22:04 UTC; expires in 14 days
  ✗ api.example.com (ec): Certificate file not found
```

By default the checks follow each certificate's lifetime and renewal plan:

| Status   | When                                                                             |
| -------- | -------------------------------------------------------------------------------- |
| critical | Missing, expired, revoked, or under 1/10 of the lifetime left                    |
| warning  | Renewal overdue (past its due time by a day, or 1/10 of the lifetime if shorter) |
| unknown  | The file doesn't parse                                                           |
| healthy  | Otherwise                                                                        |

`--warning-days`/`--critical-days` switch to fixed thresholds (14 and 7
days for whichever isn't given). `--check-live` connects to each primary
name on port 443, verifies the chain and hostname, and warns when the
served certificate has under 1/4 of its lifetime left (the renewed one
probably wasn't deployed).

`--write-health PATH` also writes the result to a file: Prometheus format
with `--prometheus`, JSON otherwise.

**Exit codes:** 0 healthy (or only unknown), 1 warning or configuration
error, 2 critical. Output goes to stderr; `--json` and `--prometheus`
output goes to stdout.

### JSON

```json
{
  "status": "critical",
  "summary": "Certificates: 1 critical, 1 warning, 2 healthy",
  "checked_at": "2026-10-10T22:05:22.808796+00:00",
  "counts": {
    "healthy": 2,
    "warning": 1,
    "critical": 1,
    "unknown": 0,
    "total": 4
  },
  "certificates": [
    {
      "domain": "example.com",
      "key_type": "rsa",
      "status": "healthy",
      "message": "Certificate valid for 69 days; renews 2026-11-19 (lifetime)",
      "cert_path": "/etc/lematt/prod/cert/example.com_www.example.com-cert-combined.rsa2048.pem",
      "days_until_expiry": 69,
      "not_after": "2026-12-19T22:04:55",
      "issuer": "C=US, O=Let's Encrypt, CN=YR1",
      "details": {},
      "renewal": {
        "due_at": "2026-11-19T22:04:55",
        "basis": "lifetime",
        "last_success": null,
        "consecutive_failures": 0,
        "last_error": null
      }
    }
  ]
}
```

### Prometheus

| Metric                                              | Labels               | Meaning                                     |
| --------------------------------------------------- | -------------------- | ------------------------------------------- |
| `lematt_certificate_expiry_days`                    | `domain`, `key_type` | Days until expiry                           |
| `lematt_certificate_status`                         | `domain`, `key_type` | 0 healthy, 1 warning, 2 critical, 3 unknown |
| `lematt_certificate_expiry_timestamp_seconds`       | `domain`, `key_type` | Expiry time                                 |
| `lematt_certificate_renewal_due_timestamp_seconds`  | `domain`, `key_type` | When lematt plans to renew                  |
| `lematt_certificate_last_renewal_timestamp_seconds` | `domain`, `key_type` | Last successful renewal                     |
| `lematt_certificate_renewal_failures`               | `domain`, `key_type` | Consecutive failed attempts                 |
| `lematt_certificates_total`                         | `status`             | Certificates per status                     |
| `lematt_health_check_timestamp_seconds`             |                      | Time of the check                           |

Live checks use `key_type="live"`. Alert on
`lematt_certificate_renewal_failures > 0` for a few hours, and on
`lematt_certificate_status >= 2`.

### Scheduling Checks

```bash
# /etc/cron.d/lematt-health: textfile collector for node_exporter
*/30 * * * * root cd /opt/lematt && uv run lematt --prod --config /etc/lematt/lematt.toml --health-check --prometheus --write-health /var/lib/node_exporter/textfile/lematt.prom
```

For Nagios/Icinga, run the same command without `--prometheus`; exit codes
0, 1 and 2 map to OK, WARNING and CRITICAL.

---

## Notifications

Alerts come from renewal runs and `--health-check`, through the backends in
a TOML `[notifications]` table: in the `--config` file when it is TOML, or
in a `lematt.toml` next to an INI `lematt.conf`. Without that table,
nothing is sent.

```toml
[notifications]
email_to = "admin@example.com"
email_from = "lematt@example.com"

webhook_url = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
webhook_format = "slack"

ntfy_topic = "my-cert-alerts"

notify_on_success = true
```

```bash
uv run lematt --test --test-notification     # send a test event to every backend
```

The test reports each backend as sent (✓), failed (✗), or skipped: with
`pagerduty_only_failure`, PagerDuty doesn't take test events.

| Key                      | Default            | Description                                     |
| ------------------------ | ------------------ | ----------------------------------------------- |
| `email_to`               | unset              | Enables email                                   |
| `email_from`             | "lematt@localhost" | Sender                                          |
| `email_use_sendmail`     | true               | `/usr/sbin/sendmail -t`; false uses SMTP        |
| `email_smtp_host`        | "localhost"        | SMTP server (no TLS or authentication)          |
| `email_smtp_port`        | 25                 | SMTP port                                       |
| `webhook_url`            | unset              | Enables the webhook                             |
| `webhook_format`         | "slack"            | `slack`, `discord` or `generic` (event as JSON) |
| `pagerduty_key`          | unset              | Enables PagerDuty (Events API v2 routing key)   |
| `pagerduty_only_failure` | true               | Only page for failures                          |
| `ntfy_topic`             | unset              | Enables ntfy                                    |
| `ntfy_server`            | "https://ntfy.sh"  | ntfy server                                     |
| `ntfy_token`             | unset              | ntfy access token                               |
| `custom_command`         | unset              | Command run per event (see below)               |
| `journald_enabled`       | true               | Log events via `logger` to syslog/journald      |
| `journald_identifier`    | "lematt"           | Syslog identifier                               |
| `notify_on_failure`      | true               | Send failure events                             |
| `notify_on_warning`      | true               | Send warning events                             |
| `notify_on_success`      | false              | Send success events                             |

Unknown keys are warned about.

### Events

| Type      | Sent for                                                                                             |
| --------- | ---------------------------------------------------------------------------------------------------- |
| `failure` | Renewals that failed in a run (CA error, next attempt); critical health results                      |
| `warning` | Early renewal requested by the CA (ARI explanation); revocations; overdue renewals in a health check |
| `success` | Certificates renewed in a run                                                                        |
| `info`    | `--test-notification`                                                                                |

A run sends at most one event per type, listing every certificate. Health
notifications come from `--health-check` only, not from `--check-live`
results. `--dry-run` sends nothing.

### Custom Command

`custom_command` is split into words like a shell command line (quotes
work; pipes, redirects and variables don't) and run without a shell. Five
arguments are appended: event type, title, message, hostname and
timestamp. It must exit 0 within 60 seconds.

```toml
custom_command = "/usr/local/bin/lematt-notify --channel 'ops alerts'"
```

```bash
#!/bin/sh
# /usr/local/bin/lematt-notify --channel NAME event_type title message hostname timestamp
channel="$2"; shift 2
curl -fsS -X POST https://alerts.example.com/hook \
  --data-urlencode "channel=$channel" --data-urlencode "event=$1" \
  --data-urlencode "title=$2" --data-urlencode "message=$3"
```

---

## Dashboard, Reports and Help

### Dashboard

```bash
uv run lematt --prod --dashboard
uv run lematt --prod --dashboard --dashboard-refresh 10
uv run lematt --prod --dashboard --dashboard-compact   # start without paths
```

| Key     | Action                                              |
| ------- | --------------------------------------------------- |
| `1`-`4` | Overview, Certificates, Health, Activity log        |
| `Enter` | Certificate details (Certificates and Health views) |
| `e`     | Export the shown certificate as JSON (details view) |
| `Esc`   | Close the details view                              |
| `r`     | Refresh now (and resume)                            |
| `p`     | Pause/resume auto-refresh                           |
| `c`     | Show/hide certificate paths (compact mode)          |
| `q`     | Quit                                                |

The dashboard uses the same health checks as `--health-check`, including
`--warning-days`/`--critical-days`.

### Reports

```bash
uv run lematt --prod --report                              # in the terminal
uv run lematt --prod --report --report-output report.json  # JSON
uv run lematt --prod --report --report-output report.md    # Markdown
uv run lematt --prod --report --report-format json | jq .  # JSON to stdout
```

A report has the health summary, certificate inventory (with paths),
renewal schedule, configuration summary (mode, ACME directory, key,
certificate and challenge directories, key settings) and deployment
action groups.

The format is `--report-format` if given, else taken from the
`--report-output` extension: `.json` is JSON, `.md`/`.markdown` is
Markdown, and anything else is the terminal report as plain text.
Without `--report-output`, the report goes to stdout.

The renewal schedule sorts certificates by days until lematt renews them:
`immediate` (overdue), `soon` (within 7 days), `scheduled` (within 14),
`ok`, or `unknown` (no certificate).

### Help Topics

```bash
uv run lematt --help-topic              # list topics
uv run lematt --help-topic run
uv run lematt --help-search wildcard
```

Topics: `run`, `revoke`, `status`, `health`, `dashboard`, `config`,
`configuration`, `domains`, `actions`, `challenges`, `systemd`,
`monitoring`, `notifications`, `troubleshooting`.

---

## Troubleshooting

**Validation fails.** lematt fetches each token over plain HTTP before
asking Let's Encrypt, so this fails fast without spending the CA's
failed-validation limit (5 per name per hour):

```bash
echo test > /var/www/html/.well-known/acme-challenge/test
curl -v http://example.com/.well-known/acme-challenge/test
```

Port 80 must be open to everyone (Let's Encrypt validates from several
unpublished locations), and `challenge_dir` must be served for every name
on the certificate, or forwarded by a `prepare` action.

**"Config file not found".** `--config` defaults to `conf/lematt.conf`
relative to the current directory; run from the lematt checkout or pass an
absolute path. A TOML file must be passed explicitly
(`--config conf/lematt.toml`).

**"Account key doesn't exist".** Create it:
`openssl genrsa 4096 > /etc/lematt/account.key && chmod 600 /etc/lematt/account.key`.

**"Config error: Challenge directory does not exist".** Create the
directory and serve it at `/.well-known/acme-challenge/`.

**`rateLimited: ... (retry after Ns)`.** The CA's limits: 5 certificates
per exact set of names per 7 days (each line uses two), 50 per registered
domain per 7 days. lematt backs off until the CA's retry time; use
`--test` while changing configuration, and don't `--force-renew`
repeatedly in production.

**Certificate renewed but not served.** Check the upload and update
action output in the run log, and run
`uv run lematt --prod --health-check --check-live`.

**Debugging.**

```bash
uv run lematt --test -v --dry-run
uv run lematt --test -v --domain example.com
journalctl -u lematt-renew.service
```

---

## Python API

lematt's command line is built from importable parts:

```python
from pathlib import Path

from lematt import ActionRunner, CertificateExecutor, CertificateManager, ConfigLoader


def main() -> None:
    loader = ConfigLoader(
        config_base=Path("/etc/lematt"),
        config_file=Path("/etc/lematt/lematt.toml"),
    )
    loader.load()
    errors, warnings = loader.validate(require_write_access=True)
    if errors:
        raise SystemExit("\n".join(errors))

    config = loader.get_lematt_config(is_test=True, concurrency=5)
    domains = loader.get_domains()
    actions = loader.get_actions()

    CertificateManager(config).ensure_directories()
    summary = CertificateExecutor(config).process_batch(
        domains=domains, domain_actions=actions
    )
    ActionRunner(config, actions=actions).process_updated_certs(summary.results)
    print(f"Renewed: {summary.renewed_count}, Failed: {summary.failed_count}")


if __name__ == "__main__":  # required: parallel runs use worker processes
    main()
```

```bash
uv run python renew.py
```

`lematt` also exports the health checker (`HealthChecker`,
`PrometheusMetrics`), notifications (`NotificationConfig`,
`NotificationManager`, `NotificationEvent`), reports, `SystemdInstaller`,
and the crypto helpers (`generate_private_key`, `create_csr`,
`get_certificate_info`).

---

## Security Considerations

1. **Private keys** are written with mode 0600; keep the config directory
   readable only by the user running lematt.
2. **The account key** controls revocation and (with CAA `accounturi`)
   issuance for your names. Keep it out of version control.
3. **Action commands** run with lematt's privileges; review them like
   any root cron job.
4. **CAA records**: `uv run lematt --prod --caa-records` prints DNS CAA
   records that allow only Let's Encrypt to issue for your names, only to
   lematt's ACME account, and only via http-01 (RFC 8657). Publish them
   after the first production run, once the account is recorded.

---

## Development

```bash
git clone https://github.com/mattsta/lematt
cd lematt
uv sync

uv run pytest
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy src
```

These are the checks CI runs. The tests use an in-process fake ACME server
(`tests/fake_acme.py`) and refuse real network access.

---

## License

Apache 2.0

## Acknowledgments

- [acme-tiny](https://github.com/diafygi/acme-tiny): the original basis of
  lematt's ACME client
- [Let's Encrypt](https://letsencrypt.org/): free, automated certificates
- [loguru](https://github.com/Delgan/loguru): logging
