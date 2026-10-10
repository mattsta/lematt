# Changelog

## 3.0.0 — 2026-10-10

Brings lematt in line with the current Let's Encrypt service: renewal
timing follows the CA's ARI windows and shrinking certificate lifetimes, and
lematt now keeps state between runs.

### Upgrade notes

- **Renewal timing changed.** `reauthorizeDays` is now optional and unset by
  default (previously an implicit 15 days). Unset, lematt renews inside the
  CA's suggested window (ARI) or, without one, with 1/3 of the lifetime left
  (30 days before expiry for 90-day certificates). `reauthorizeDays` and
  `generateNewCertsAfterDays` can only make renewal earlier. `reauthorizeDays`
  is ignored for certificates whose whole lifetime is shorter, because it
  would renew them on every run. `generateNewCertsAfterDays` is measured from
  the certificate's real issue date instead of assuming 90 days.
- **State directory.** lematt writes `<config dir>/<prod|test>/state/`
  (ACME account, per-certificate state, history, run lock). It must be
  writable by the user running lematt.
- **Exit code 75** means another renewal run still holds the lock; nothing
  was done.
- **Failures back off** (1 minute, 10 minutes, 100 minutes, then daily, or
  the CA's Retry-After). `--force-renew` retries immediately.
- **Health checks** without `--warning-days`/`--critical-days` are
  lifetime-aware: warning when renewal is overdue, critical under 1/10 of the
  lifetime. Pass both flags to keep fixed thresholds.
- **`--status --json`** `renew_soon` now means "renewal is due or backing
  off" and `critical` "under 1/10 of the lifetime left". The `renewal`
  object and `profile` are new fields. `using_native_crypto` was removed.
- **Notifications** are sent only when a TOML `[notifications]` table exists
  (in the `--config` file, or in `lematt.toml` next to an INI config).
- **systemd units** from `--install-systemd` changed: explicit
  `--prod`/`--test`, `--cron`, the installing Python, no sandboxing, no
  bash notifier. Re-run `--install-systemd`, or use `--print-systemd-units`.
- **Python 3.14+**, and `cryptography` and `httpx` are required
  dependencies.

### Added

- ACME Renewal Information (ARI, RFC 9773). Windows are checked on the CA's
  Retry-After, a random renewal time is picked in each window, and the CA's
  explanation URLs are logged and notified. Orders carry `replaces`, which
  Let's Encrypt exempts from rate limits.
- ACME certificate profiles: global `profile` setting, or per certificate
  with `profile=NAME` on a domains line or in a TOML `[[domains]]` entry.
- Persistent state (`state/`): ACME account reuse instead of registering on
  every request, per-certificate issuance/ARI/attempt records, and an
  append-only `history.jsonl`.
- A run lock against overlapping cron/timer runs.
- `--status` shows when and why each certificate renews.
- Notifications from renewal runs (failures with the CA's error, CA-requested
  early renewals, renewals) and from `--health-check`.
- Prometheus metrics: expiry, planned renewal and last renewal timestamps,
  and consecutive renewal failures.
- `--config path.toml` works (TOML configuration was documented but ignored).
- `--print-systemd-units`.
- A revocation command: `--revoke --domain NAME` with `--reason`,
  `--key-type`, `--sign-with-certificate-key`, `--replace` (re-issue with new
  keys for keyCompromise and deploy), confirmation (`--yes`) and `--dry-run`.
  Revoked certificates are renewed promptly, shown in `--status` and health
  checks, recorded in history and notified.
- EC P-256/P-384 ACME account keys.

### Changed

- New ACME client (`lematt.acme`):
  - JWS signing with `cryptography`, not openssl subprocesses
  - nonce reuse
  - typed errors from problem documents
  - polling honors Retry-After
  - already-valid authorizations are reused
  - the http-01 self-check follows redirects and always cleans up
- Only transient failures (network, 5xx) are retried within a run. Failed
  validations and rate limits fail immediately instead of being retried
  three times.
- Keys, CSRs and certificates are written atomically. Keys are PKCS#8 with
  0600 permissions, CSRs always carry subjectAltName, and certificate parsing
  uses `cryptography`.
- One configuration loader validates everything with one-line error messages.
- `--report` renewal schedules use the renewal policy.

### Removed

- OCSP Must-Staple (`+ocsp`/`-ocsp`, `ocspStapleRequired`,
  `ocsp_staple_required`). Let's Encrypt dropped OCSP and rejects
  Must-Staple. The setting never took effect in lematt. Old configs load with
  a warning.
- The `lematt_legacy.py` script, the acme-tiny-based client
  (`lematt/acme_tiny.py`) and the unused `lematt/dashboard.py`.
- The systemd bash notifier (`lematt-notify.sh`, `notify.conf`,
  `--init-notifications`) and the `weekly` systemd preset.
- `RateLimiter`, `WorkerResult` and the executor's `rate_limit` argument.

### Fixed

- Example and help `prepare` commands used `ssh -t`, which allocates no
  pseudo-terminal when lematt runs without one (cron, systemd), so a remote
  challenge forwarder could keep running after the run. They now use `ssh -tt`,
  and lematt warns about `ssh -t` prepare commands when it has no terminal.
- Production systemd units failed every run (missing `--prod`).
- Regenerated keys could keep trailing bytes of the old key (no truncation).
- A failed renewal with `alwaysGenerateNewKeys` left a new key next to the old
  certificate, and a regenerated key could be submitted with its old CSR. New
  key material is now installed only together with its certificate.
- The http-01 self-check rejected https redirects to an expired or self-signed
  certificate, which the CA accepts.
- Health checks compared UTC expiry times with local time.
- Parallel runs never passed prepare-action locks to worker processes on
  Python 3.14, and their progress updates were dropped.
- The dashboard showed no data until the second refresh, never showed status
  icons, and didn't color the days-left column.
