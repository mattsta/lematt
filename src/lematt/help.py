"""Contextual help system for lematt.

This module provides detailed, context-aware help information including
command documentation, configuration examples, troubleshooting tips,
and interactive help browsing.
"""

from dataclasses import dataclass, field
from enum import Enum, auto

from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .display import console


class HelpCategory(Enum):
    """Categories for help topics."""

    COMMANDS = auto()
    CONFIGURATION = auto()
    CERTIFICATES = auto()
    ACTIONS = auto()
    SYSTEMD = auto()
    MONITORING = auto()
    TROUBLESHOOTING = auto()
    EXAMPLES = auto()


@dataclass
class HelpTopic:
    """A single help topic with content."""

    name: str
    title: str
    category: HelpCategory
    summary: str
    content: str  # Markdown content
    examples: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)


# Define all help topics
HELP_TOPICS: dict[str, HelpTopic] = {
    # Commands
    "run": HelpTopic(
        name="run",
        title="Run Certificate Renewal",
        category=HelpCategory.COMMANDS,
        summary="Renew due certificates and run deployment actions",
        content="""
# Running lematt

Every run must choose an endpoint: `--prod` (Let's Encrypt production)
or `--test` (staging; keys and certificates get a `.test` suffix and live
under `test/`). Always validate changes with `--test` first.

## Options

- `--config PATH`: lematt.conf or a .toml file (default:
  conf/lematt.conf); `domains` and `actions.conf` are read from the same
  directory
- `--domain NAME`: Process only the certificate containing NAME
- `--force-renew`: Renew even if certificates are not due
- `--dry-run`: Show what would happen without changing anything
- `--parallel N`: Process up to N certificates concurrently (max 10)
- `--cron`: Only print output when something is renewed or fails
- `-v, --verbose`: Show debug output

## Workflow

1. Load lematt.conf, domains and actions.conf
2. For each certificate (RSA and EC), check the CA's renewal window (ARI)
   when due for a check, and decide whether renewal is due (see the
   `configuration` topic)
3. If any key type is due, start the certificate's `prepare` actions
4. Generate keys/CSRs if missing and complete ACME http-01 challenges
5. Save the issued certificates and stop the `prepare` actions
6. Run `uploadCerts`, `uploadKeys` and `update` actions once per action
   group for everything that was renewed

## Exit Codes

- 0: Success (nothing failed)
- 1: A certificate failed, or the configuration is invalid
- 75: Another renewal run is still in progress (nothing was done)
- 130: Interrupted (after-issue actions still run for renewed certs)
""",
        examples=[
            "uv run lematt --test                      # Validate against staging",
            "uv run lematt --prod --cron               # Scheduled production run",
            "uv run lematt --prod --domain example.com # One certificate only",
            "uv run lematt --prod --force-renew        # Renew regardless of expiry",
            "uv run lematt --prod --dry-run            # Preview changes",
        ],
        see_also=["status", "domains", "actions"],
        keywords=["renew", "certificate", "acme", "lets encrypt", "cron"],
    ),
    "revoke": HelpTopic(
        name="revoke",
        title="Revoking Certificates",
        category=HelpCategory.COMMANDS,
        summary="Revoke a certificate line's certificates (and replace them)",
        content="""
# Revoking Certificates

`--revoke --domain NAME` revokes the certificates of the configured line
containing NAME (RSA and EC; `--key-type rsa|ec` for one). lematt lists
what it will revoke and asks you to type `revoke` (`--yes` skips this and
is required when not on a terminal; `--dry-run` only shows the list).

## Options

- `--reason`: `unspecified` (default), `keyCompromise` (the private key
  may be exposed; required by the Subscriber Agreement in that case),
  `superseded` (replaced by a new certificate), `cessationOfOperation`
  (you no longer control the names or the site is gone)
- `--sign-with-certificate-key`: Sign with the certificate's own private
  key instead of lematt's ACME account (works if the account key is lost;
  Let's Encrypt may record the reason as keyCompromise)
- `--replace`: Then issue replacements right away and run the deployment
  actions. With `keyCompromise`, the replacements get new private keys.

## Afterwards

A revoked certificate is due for renewal immediately: `--status` shows it
as `revoked`, health checks report it as critical, and the next run
replaces it (if `--replace` didn't already). Revocations are recorded in
the state history and sent to configured notifications.
""",
        examples=[
            "uv run lematt --prod --revoke --domain example.com --dry-run",
            "uv run lematt --prod --revoke --domain example.com --reason superseded --replace",
            "uv run lematt --prod --revoke --domain example.com --reason keyCompromise --replace --yes",
            "uv run lematt --prod --revoke --domain old.example.com --reason cessationOfOperation",
        ],
        see_also=["run", "status", "health"],
        keywords=["revoke", "revocation", "compromise", "replace", "key"],
    ),
    "status": HelpTopic(
        name="status",
        title="Check Certificate Status",
        category=HelpCategory.COMMANDS,
        summary="Display certificate expiry information",
        content="""
# Certificate Status

`--status` lists every configured certificate (RSA and EC) with its
expiry date and days remaining, then exits.

## Options

- `--json`: Output status as JSON
- `--domain NAME`: Only the certificate containing NAME
- `--list-domains`: List configured certificates and their SANs instead
""",
        examples=[
            "uv run lematt --prod --status             # Status table",
            "uv run lematt --prod --status --json      # JSON for scripting",
            "uv run lematt --prod --list-domains       # Configured certificates",
        ],
        see_also=["health", "dashboard", "run"],
        keywords=["certificate", "expiry", "check", "info", "list"],
    ),
    "health": HelpTopic(
        name="health",
        title="Health Check System",
        category=HelpCategory.COMMANDS,
        summary="Check certificate files (and optionally live servers)",
        content="""
# Health Checks

`--health-check` inspects every configured certificate file and reports
healthy, warning, critical or unknown, with an exit code for monitoring.

## Options

- `--check-live`: Also connect to each certificate's primary domain on
  port 443 and check the certificate it serves
- `--warning-days N` / `--critical-days N`: Use fixed day thresholds
  instead of the lifetime-aware defaults below (14 and 7 days for
  whichever isn't given)
- `--json` / `--prometheus`: Machine-readable output
- `--write-health PATH`: Also write the result (JSON, or Prometheus with
  `--prometheus`) to PATH

## Checks Performed

1. **Certificate files**: critical when missing, revoked or expired;
   unknown when the file doesn't parse. By default:
   - critical when under 1/10 of the lifetime is left
   - warning when lematt's renewal is overdue (past its due time by a
     day, or by 1/10 of the lifetime if that's shorter), including the
     failure count and last error
2. **Live servers** (`--check-live`): TLS handshake with chain and
   hostname verification. Warning when the served certificate has under
   1/4 of its lifetime left (the renewed one probably wasn't deployed);
   critical under 1/10 or expired.

## Exit Codes

- 0: All healthy
- 1: At least one warning
- 2: At least one critical
- 3: Unknown: a certificate doesn't parse, a live check couldn't connect,
  or the configuration doesn't load (warning and critical take precedence)
""",
        examples=[
            "uv run lematt --prod --health-check",
            "uv run lematt --prod --health-check --check-live",
            "uv run lematt --prod --health-check --prometheus --write-health /var/lib/node_exporter/lematt.prom",
            "uv run lematt --prod --health-check --warning-days 21 --critical-days 7",
        ],
        see_also=["status", "monitoring", "notifications"],
        keywords=["health", "check", "monitoring", "diagnostics"],
    ),
    "dashboard": HelpTopic(
        name="dashboard",
        title="Interactive Dashboard",
        category=HelpCategory.COMMANDS,
        summary="Live-updating terminal dashboard for monitoring",
        content="""
# Interactive Dashboard

`--dashboard` launches a terminal dashboard with live-updating
certificate status and health information.

## Options

- `--dashboard-refresh SECONDS`: Refresh interval (default: 5)
- `--dashboard-compact`: Use compact display mode
- `--warning-days` / `--critical-days`: Fixed health thresholds (default: lifetime-aware)

## Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit dashboard |
| `r` | Refresh now |
| `p` | Pause/resume auto-refresh |
| `c` | Show/hide certificate paths (compact mode) |
| `1` | Overview view |
| `2` | Certificates view |
| `3` | Health view |
| `4` | Activity log view |
| `e` | Export the selected certificate as JSON (detail view) |
| `Esc` | Close the detail view |
""",
        examples=[
            "uv run lematt --prod --dashboard",
            "uv run lematt --prod --dashboard --dashboard-refresh 10",
            "uv run lematt --prod --dashboard --dashboard-compact",
        ],
        see_also=["status", "health"],
        keywords=["dashboard", "interactive", "monitor", "live", "tui"],
    ),
    "config": HelpTopic(
        name="config",
        title="Configuration Commands",
        category=HelpCategory.COMMANDS,
        summary="Validate configuration and generate examples",
        content="""
# Configuration Commands

- `--validate-config`: Check everything a run reads (settings, domains,
  actions, the challenge directory and the account key), then print a
  summary; unknown keys and certificates spanning action groups are warned
  about
- `--list-domains`: Print the configured certificates and exit
- `--init-toml`: Write an example `lematt.toml` next to `--config`
- `--caa-records`: Print CAA DNS records limiting issuance to Let's
  Encrypt, this ACME account and http-01 validation
- `--report`: Generate an inventory/renewal report (`--report-output`,
  `--report-format console|json|markdown`)

## Configuration Files

`--config` points at the main config file (default: `conf/lematt.conf`).
A `.toml` file is read as TOML (`[config]`, optional `[[domains]]` and
`[actions.*]`); anything else as INI. The `domains` and `actions.conf`
files are read from the same directory unless the TOML file defines
them inline. Keys/certificates/CSRs are written below that directory in
`prod/` or `test/`.
""",
        examples=[
            "uv run lematt --test --validate-config",
            "uv run lematt --test --config /etc/lematt/lematt.conf --list-domains",
            "uv run lematt --prod --report --report-output report.md",
        ],
        see_also=["configuration", "domains", "actions"],
        keywords=["config", "configuration", "validate", "setup"],
    ),
    # Configuration topics
    "configuration": HelpTopic(
        name="configuration",
        title="Configuration File Format",
        category=HelpCategory.CONFIGURATION,
        summary="Settings in lematt.conf",
        content="""
# lematt.conf

```ini
[config]
# Directory served at http://<domain>/.well-known/acme-challenge/
# for every domain lematt requests certificates for
challengeDropDir: /srv/web/challenges/

# ACME account key (RSA, or EC P-256/P-384): openssl genrsa 4096 > account.key
accountKey: /etc/ssl/private/lets-encrypt-account.key.pem

# Key settings for the RSA and EC certificate of every domain
keyBitsRSA: 2048
curve: prime256v1

# Generate a new key for every renewal (default: reuse keys)
alwaysGenerateNewKeys: no
```

## Renewal Timing

By default lematt follows the CA: it renews inside the window Let's
Encrypt suggests for each certificate (ARI), or, without one, when 1/3
of the certificate's lifetime remains (half, below 10 days). After a
failure it backs off (1 minute, 10 minutes, 100 minutes, then daily, or
longer if the CA asks); `--force-renew` retries immediately. `--status`
shows when each certificate will renew and why.

`reauthorizeDays` and `generateNewCertsAfterDays` can only make renewal
earlier. `reauthorizeDays` is ignored for certificates whose whole
lifetime is shorter, because it would renew them on every run.

## Keys

| Key | Default | Description |
|-----|---------|-------------|
| `challengeDropDir` | (required) | Webroot directory for http-01 tokens |
| `accountKey` | (required) | ACME account private key |
| `reauthorizeDays` | (unset) | Renew no later than N days before expiry |
| `generateNewCertsAfterDays` | 0 (off) | Renew once a certificate is N days old |
| `keyBitsRSA` | 2048 | RSA key size |
| `curve` | prime256v1 | EC curve (prime256v1 = secp256r1, or secp384r1) |
| `alwaysGenerateNewKeys` | no | Rotate keys on every renewal |
| `rsaTag` / `curveTag` | rsa<bits> / <curve> | Filename tags |
| `profile` | (CA default) | ACME profile for all certificates (e.g. tlsserver) |
""",
        examples=[
            "[config]",
            "challengeDropDir: /srv/web/challenges/",
            "accountKey: /etc/ssl/private/lets-encrypt-account.key.pem",
        ],
        see_also=["domains", "actions", "config"],
        keywords=["config", "settings", "format", "ini", "lematt.conf"],
    ),
    "domains": HelpTopic(
        name="domains",
        title="Domain Configuration",
        category=HelpCategory.CONFIGURATION,
        summary="One certificate per line in the domains file",
        content="""
# Domain Configuration

The `domains` file (next to lematt.conf) defines one certificate per
line. The first name is the primary name; the rest are added as SANs.
Every line produces both an RSA and an EC certificate.

## Format

```
# primary [san ...]
# "www" and "mail" expand to www.example.com and mail.example.com
example.com www mail
# full names work too
example.org www.example.org
corp.example.com intranet hr git wiki
```

- Names without a dot are shorthand for `<name>.<primary>`
- Comments go on their own line (text after a name is read as more names)
- Up to 100 names per certificate
- Lines starting with `#` are comments
- SAN certificates are also symlinked under each SAN's name
- `profile=NAME` requests an ACME profile for that certificate (e.g.
  `tlsserver` for 45-day or `shortlived` for 6-day certificates)
""",
        examples=[
            "example.com www mail",
            "api.example.com",
        ],
        see_also=["configuration", "actions"],
        keywords=["domain", "san", "certificate", "subdomain"],
    ),
    "actions": HelpTopic(
        name="actions",
        title="Deployment Actions",
        category=HelpCategory.ACTIONS,
        summary="Prepare, upload and reload commands per group of domains",
        content="""
# Deployment Actions (actions.conf)

## Sections

- `[default]`: Domains without a more specific section
- `[every]`: Runs for every renewed certificate, in addition to its
  default/override section
- `[<any-name>]`: Override for the domains listed in its `domains:` key
  (space separated). Sections match per name, SANs included; keep all
  names of a certificate in one section

## Action Keys (JSON lists of shell commands)

- `prepare`: Started (in the background) before certificates for a domain
  are requested and stopped afterwards, e.g. a remote challenge forwarder
  over ssh. `DOMAIN` is replaced with the domain being prepared.
- `uploadCerts`: Runs after renewal. `CERTS` expands to globs matching the
  renewed certificate files (and their SAN symlinks).
- `uploadKeys`: Like uploadCerts with `KEYS` for the private keys.
- `update`: Runs after uploads, e.g. service reloads. `DOMAINS_CN` expands
  to the primary names and `DOMAINS_ALL` to every name renewed in this
  section.

Post-renewal actions run once per section, after all certificates are
processed, for everything renewed in that run. A failed command is
logged and doesn't stop the others.

## Example

```ini
[default]
uploadCerts: ["rsync -avz --chmod=F644 CERTS /etc/ssl/"]
uploadKeys: ["rsync -avz --chmod=F640 KEYS /etc/ssl/private/"]
update: ["sudo systemctl reload nginx"]

[every]
uploadCerts: ["rsync -avz CERTS backup.example.net:/srv/tls/"]

[override-mail]
domains: mail.example.com
prepare: ["ssh -tt forwarder.example.net uv run leforward.py --baseurl http://example.com"]
update: ["ssh mail.example.net sudo systemctl reload postfix"]
```

Use `ssh -tt` for prepare commands so the remote process ends with the
session even when lematt runs without a terminal (cron, systemd).
""",
        examples=[
            "[override-web]",
            "domains: example.com www.example.com",
            'uploadCerts: ["rsync -avz CERTS web1.example.net:/etc/ssl/"]',
            'update: ["ssh web1.example.net sudo systemctl reload nginx"]',
        ],
        see_also=["configuration", "domains", "run"],
        keywords=["actions", "deploy", "upload", "rsync", "reload", "prepare"],
    ),
    # Systemd topics
    "systemd": HelpTopic(
        name="systemd",
        title="Systemd Integration",
        category=HelpCategory.SYSTEMD,
        summary="Install a systemd timer for scheduled renewals",
        content="""
# Systemd Integration

## Commands

- `--print-systemd-units`: Print `lematt-renew.service` and
  `lematt-renew.timer` (e.g. for configuration management to install)
- `--install-systemd`: Write them to /etc/systemd/system, then enable
  and start the timer
- `--uninstall-systemd`: Disable the timer and remove the units
- `--systemd-status`: Show timer state (`--json` supported)
- `--systemd-preset NAME`: Schedule to use
- `--dry-run`: Show what install or uninstall would do

Pass an absolute `--config`: the service uses the same config path and
mode as the install command.

The service runs `<this python> -m lematt --config <path> --prod|--test
--cron` (the mode comes from `--prod`/`--test`), treats exit code 75 (an
overlapping run) as success, and times out after 3 hours. It is not
sandboxed because deployment actions need ssh keys, arbitrary upload
paths and sudo; add hardening with a drop-in if yours don't.

## Presets

| Preset | Schedule |
|--------|----------|
| `default` | Twice daily (00:00 and 12:00, up to 1h random delay) |
| `aggressive` | Four times daily |
| `conservative` | Daily at 03:00 (90-day certificates only) |

Let's Encrypt recommends checking at least twice a day, so renewals
follow the CA's renewal windows and shorter certificate lifetimes.
""",
        examples=[
            "uv run lematt --prod --config /etc/lematt/lematt.toml --print-systemd-units",
            "uv run lematt --prod --config /etc/lematt/lematt.toml --install-systemd --dry-run",
            "sudo uv run lematt --prod --config /etc/lematt/lematt.toml --install-systemd --systemd-preset aggressive",
            "uv run lematt --test --systemd-status",
            "systemctl list-timers lematt-renew.timer",
        ],
        see_also=["notifications", "monitoring"],
        keywords=["systemd", "timer", "cron", "automation", "schedule"],
    ),
    # Monitoring topics
    "monitoring": HelpTopic(
        name="monitoring",
        title="Monitoring Integration",
        category=HelpCategory.MONITORING,
        summary="Integrate with monitoring systems",
        content="""
# Monitoring Integration

Let's Encrypt no longer sends expiry reminder emails, so monitor
certificates yourself.

## Prometheus

Write metrics for the node_exporter textfile collector:

```bash
uv run lematt --prod --health-check --prometheus \\
    --write-health /var/lib/node_exporter/textfile/lematt.prom
```

Metrics:

- `lematt_certificate_expiry_days{domain,key_type}`: Days until expiry
- `lematt_certificate_status{domain,key_type}`: 0=healthy, 1=warning,
  2=critical, 3=unknown
- `lematt_health_check_timestamp_seconds`: Time of the check
- `lematt_certificates_total{status}`: Certificate counts by status
- `lematt_certificate_expiry_timestamp_seconds{domain,key_type}`
- `lematt_certificate_renewal_due_timestamp_seconds{domain,key_type}`:
  when lematt plans to renew
- `lematt_certificate_last_renewal_timestamp_seconds{domain,key_type}`
- `lematt_certificate_renewal_failures{domain,key_type}`: consecutive
  failed attempts (alert on > 0 for a while)

## Nagios/Icinga

`--health-check` exits 0 (OK), 1 (WARNING), 2 (CRITICAL) or 3 (UNKNOWN).

## JSON

```bash
uv run lematt --prod --health-check --json
uv run lematt --prod --status --json
```
""",
        examples=[
            "uv run lematt --prod --health-check --prometheus --write-health /var/lib/node_exporter/textfile/lematt.prom",
            "uv run lematt --prod --health-check --json",
        ],
        see_also=["health", "notifications"],
        keywords=["monitoring", "prometheus", "nagios", "metrics"],
    ),
    "notifications": HelpTopic(
        name="notifications",
        title="Notification System",
        category=HelpCategory.MONITORING,
        summary="Configure alerts and notifications",
        content="""
# Notifications

## Notification Backends

Backends are configured in the `[notifications]` table of the TOML config
(or of a `lematt.toml` next to an INI config): email, Slack/Discord/generic
webhook, PagerDuty, ntfy, custom command, journald. Without the table,
nothing is sent.

After each renewal run lematt sends one notification per kind:
- failure: renewals that failed, with the CA's error and next attempt
- warning: the CA asked for early renewal (ARI explanation URL), and
  certificates revoked with `--revoke`
- success: certificates renewed (only with `notify_on_success = true`;
  `notify_on_failure`/`notify_on_warning` turn the others off)

`--health-check` notifies critical and overdue certificates the same way.
`--test-notification` sends a test event to every configured backend.
""",
        examples=[
            "uv run lematt --test --test-notification",
        ],
        see_also=["systemd", "monitoring", "health"],
        keywords=["notify", "alert", "slack", "email", "webhook"],
    ),
    "challenges": HelpTopic(
        name="challenges",
        title="Validation Methods and Wildcards",
        category=HelpCategory.CONFIGURATION,
        summary="http-01 today; wildcards, dns-01 and dns-persist-01",
        content="""
# Validation Methods and Wildcards

lematt validates names with **http-01**: `challengeDropDir` must be served
at `http://<name>/.well-known/acme-challenge/` for every name, from
anywhere (use a `prepare` action to forward challenges from other hosts).

## Wildcards

Let's Encrypt issues wildcard certificates only after DNS validation, which
lematt doesn't implement. Today, either list the names on a certificate
line (up to 100), or use a DNS-capable ACME client for the wildcard names.
If you published `--caa-records`, give that client an `issuewild` CAA
record for its own account and `dns-01`.

## Coming later

- **dns-01** (available at Let's Encrypt): fresh TXT record per validation
- **dns-persist-01** (announced, not live as of 2026-10): one standing
  `_validation-persist.<name>` TXT record naming lematt's ACME account

See docs/challenges.md for the design notes and when to implement each,
and docs/private-ca.md for using an internal ACME CA (step-ca) or a local
Boulder instance.
""",
        examples=[
            "example.com www api mail",
            "curl -v http://example.com/.well-known/acme-challenge/test",
        ],
        see_also=["domains", "actions", "troubleshooting"],
        keywords=[
            "wildcard",
            "dns",
            "dns-01",
            "dns-persist-01",
            "http-01",
            "challenge",
        ],
    ),
    # Troubleshooting
    "troubleshooting": HelpTopic(
        name="troubleshooting",
        title="Troubleshooting Guide",
        category=HelpCategory.TROUBLESHOOTING,
        summary="Common issues and solutions",
        content="""
# Troubleshooting Guide

## Challenge Verification Failed

lematt checks that each challenge file is reachable over plain HTTP
before asking Let's Encrypt to validate it.

1. **Port 80 blocked**: Let's Encrypt validates from multiple locations
   with unpublished IPs; port 80 must be open to everyone
2. **Webroot mismatch**: `challengeDropDir` must be served at
   `/.well-known/acme-challenge/` for every name on the certificate
3. **Remote host**: Use a `prepare` action to forward challenges (see the
   `actions` topic)

```bash
echo test > /srv/web/challenges/test
curl -v http://example.com/.well-known/acme-challenge/test
```

## Rate Limited

Let's Encrypt's main limits: 5 certificates per exact set of names per
7 days (each lematt line issues an RSA and an EC certificate), 50
certificates per registered domain per 7 days, and 5 failed validations
per name per hour. Errors say when to retry.

1. Use `--test` (staging) while changing configuration
2. Don't `--force-renew` repeatedly in production
3. Wait for the time given in the error message

## Certificate Not Updating on Server

1. Check that the `uploadCerts`/`update` actions succeeded in the output
2. Verify the service reload worked
3. Check the certificate path in the server configuration

## Debugging

```bash
uv run lematt --test --verbose --dry-run
uv run lematt --test --verbose --domain example.com
journalctl -u lematt-renew
```
""",
        examples=[
            "uv run lematt --test --verbose --dry-run",
            "curl http://example.com/.well-known/acme-challenge/test",
            "journalctl -u lematt-renew -f",
        ],
        see_also=["run", "health", "config"],
        keywords=["debug", "error", "fix", "problem", "issue", "rate limit"],
    ),
}


class HelpSystem:
    """Provides contextual help functionality."""

    def __init__(self, topics: dict[str, HelpTopic] | None = None):
        self.topics = topics or HELP_TOPICS

    def get_topic(self, name: str) -> HelpTopic | None:
        """Get a help topic by name."""
        return self.topics.get(name.lower())

    def search(self, query: str) -> list[HelpTopic]:
        """Search for topics matching a query.

        Topics whose name, title, summary or keywords match come first,
        then topics that only mention the query in their text or examples.
        """
        query_lower = query.lower()
        strong, mentions = [], []

        for topic in self.topics.values():
            if (
                query_lower in topic.name.lower()
                or query_lower in topic.title.lower()
                or query_lower in topic.summary.lower()
                or any(query_lower in kw for kw in topic.keywords)
            ):
                strong.append(topic)
            elif query_lower in topic.content.lower() or any(
                query_lower in example.lower() for example in topic.examples
            ):
                mentions.append(topic)

        return strong + mentions

    def list_topics(self, category: HelpCategory | None = None) -> list[HelpTopic]:
        """List all topics, optionally filtered by category."""
        if category:
            return [t for t in self.topics.values() if t.category == category]
        return list(self.topics.values())

    def list_categories(self) -> list[tuple[HelpCategory, int]]:
        """List all categories with topic counts."""
        counts: dict[HelpCategory, int] = {}
        for topic in self.topics.values():
            counts[topic.category] = counts.get(topic.category, 0) + 1
        return [(cat, counts.get(cat, 0)) for cat in HelpCategory]


class HelpRenderer:
    """Renders help content in rich format."""

    def render_topic(self, topic: HelpTopic) -> Panel:
        """Render a help topic as a panel."""
        content_parts: list[RenderableType] = []

        # Summary
        content_parts.append(Text(topic.summary, style="italic cyan"))
        content_parts.append(Text())

        # Main content (markdown)
        content_parts.append(Markdown(topic.content))

        # Examples
        if topic.examples:
            content_parts.append(Text())
            content_parts.append(Text("Examples", style="bold underline"))
            for example in topic.examples:
                content_parts.append(
                    Syntax(example, "bash", theme="monokai", line_numbers=False)
                )

        # See also
        if topic.see_also:
            content_parts.append(Text())
            see_also_text = Text("See also: ", style="dim")
            for i, ref in enumerate(topic.see_also):
                if i > 0:
                    see_also_text.append(", ", style="dim")
                see_also_text.append(f"--help-topic {ref}", style="cyan")
            content_parts.append(see_also_text)

        return Panel(
            Group(*content_parts),
            title=f"[bold]{topic.title}[/bold]",
            subtitle=f"[dim]{topic.category.name.lower()}[/dim]",
            border_style="cyan",
        )

    def render_topic_list(
        self, topics: list[HelpTopic], title: str = "Help Topics"
    ) -> Table:
        """Render a list of topics as a table."""
        table = Table(
            title=title,
            show_header=True,
            header_style="bold cyan",
            border_style="bright_black",
        )

        table.add_column("Topic", style="bold")
        table.add_column("Category", style="dim", width=15)
        table.add_column("Description")

        for topic in topics:
            table.add_row(
                topic.name,
                topic.category.name.lower(),
                topic.summary,
            )

        return table

    def render_category_tree(self, help_system: HelpSystem) -> Tree:
        """Render all topics organized by category."""
        tree = Tree("[bold cyan]lematt Help[/bold cyan]")

        for category, count in help_system.list_categories():
            if count == 0:
                continue

            category_node = tree.add(f"[bold]{category.name.lower()}[/bold] ({count})")

            for topic in help_system.list_topics(category):
                topic_text = Text()
                topic_text.append(topic.name, style="cyan")
                topic_text.append(f" - {topic.summary}", style="dim")
                category_node.add(topic_text)

        return tree

    def render_search_results(
        self, results: list[HelpTopic], query: str
    ) -> Panel | Table:
        """Render search results."""
        if not results:
            return Panel(
                f"[dim]No results found for '[/dim]{query}[dim]'[/dim]\n\n"
                "Try `uv run lematt --help-topic` to list all topics.",
                title="[bold]Search Results[/bold]",
                border_style="yellow",
            )

        return self.render_topic_list(results, title=f"Results for '{query}'")


def print_help(topic_name: str | None = None) -> None:
    """Print help to the console.

    Args:
        topic_name: Specific topic to show, or None for overview
    """
    help_system = HelpSystem()
    renderer = HelpRenderer()

    if topic_name:
        topic = help_system.get_topic(topic_name)
        if topic:
            console.print(renderer.render_topic(topic))
        else:
            # Try search
            results = help_system.search(topic_name)
            if results:
                console.print(renderer.render_search_results(results, topic_name))
            else:
                console.print(f"[yellow]No help found for '{topic_name}'[/yellow]")
                console.print()
                console.print(renderer.render_category_tree(help_system))
    else:
        # Show overview
        console.print(renderer.render_category_tree(help_system))
        console.print()
        console.print(
            "[dim]Use 'uv run lematt --help-topic <topic>' for detailed help[/dim]"
        )


def search_help(query: str) -> None:
    """Search help topics and display results.

    Args:
        query: Search query string
    """
    help_system = HelpSystem()
    renderer = HelpRenderer()

    results = help_system.search(query)
    console.print(renderer.render_search_results(results, query))


def get_quick_help(command: str) -> str:
    """Get a quick one-line help string for a command.

    Args:
        command: Command name

    Returns:
        Short help string
    """
    help_system = HelpSystem()
    topic = help_system.get_topic(command)

    if topic:
        return topic.summary
    return f"No help available for '{command}'"
