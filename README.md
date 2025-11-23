# lematt - Matt's Let's Encrypt Automation

A high-performance, type-safe certificate management system for automated Let's Encrypt certificate provisioning, renewal, and deployment.

## Features

- **Parallel Processing**: Process hundreds of certificates concurrently with configurable worker pools
- **Dual Key Support**: Generate both RSA and EC (ECDSA) certificates for each domain
- **SAN/SNI/UCC Support**: Up to 100 domain names per certificate
- **Workflow Automation**: Pre-request prepare actions and post-renewal deployment triggers
- **Multiple Output Formats**: Human-readable tables or JSON for monitoring integration
- **Modern Python**: Type-safe dataclasses, Python 3.14+, native cryptography support
- **TOML Configuration**: Modern config format with native list support (INI still supported)
- **OCSP Must-Staple**: Per-domain OCSP stapling configuration
- **Test Mode**: Isolated staging environment to validate configuration safely

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/mattsta/lematt
cd lematt

# Install with uv (recommended)
uv sync

# Or install with pip
pip install -e .

# Optional: Install native crypto for ~5x performance
uv sync --extra crypto
# or: pip install -e ".[crypto]"
```

### Generate Example Configuration

```bash
# Create example TOML config (recommended for new installations)
lematt --test --init-toml

# Or use the existing INI config files in conf/
```

### Validate Configuration

```bash
# Validate without processing any certificates
lematt --test --validate-config

# List all configured domains
lematt --test --list-domains

# Check certificate status
lematt --test --status
```

### Run Certificate Management

```bash
# Test mode (uses Let's Encrypt staging - always test first!)
lematt --test

# Production mode
lematt --prod

# With parallel processing (up to 10 workers)
lematt --prod --parallel 5

# Dry run to see what would happen
lematt --prod --dry-run

# Force renewal of all certificates
lematt --prod --force-renew

# Process single domain
lematt --prod --domain example.com
```

---

## Architecture

### Design Principles

1. **Error Isolation**: Individual certificate failures don't affect other certificates
2. **Rate Limiting**: Built-in token bucket rate limiter respects Let's Encrypt API limits
3. **Graceful Shutdown**: Clean cancellation on SIGINT/SIGTERM preserves partial progress
4. **Type Safety**: All configuration and data structures use typed dataclasses
5. **No Global State**: All components accept configuration through constructors

### Component Overview

```
lematt/
├── cli.py           # Command-line interface and argument parsing
├── config.py        # Configuration dataclasses (LemattConfig, DomainConfig, etc.)
├── config_loader.py # Unified INI/TOML configuration loading
├── manager.py       # CertificateManager - core certificate operations
├── executor.py      # CertificateExecutor - parallel processing with error isolation
├── actions.py       # ActionRunner - pre/post certificate workflow execution
├── crypto.py        # Key generation, CSR creation, certificate parsing
└── log.py           # Loguru-based structured logging
```

### Processing Flow

```
1. Load Configuration (INI or TOML)
        ↓
2. Validate Configuration
        ↓
3. Load Domain List (with OCSP flags)
        ↓
4. For each domain + key type (RSA, EC):
   a. Check if renewal needed
   b. Run prepare actions (start temp servers, open ports)
   c. Generate key (if needed)
   d. Generate CSR (with OCSP Must-Staple if configured)
   e. Request certificate from Let's Encrypt
   f. Cleanup prepare actions
        ↓
5. Run post-renewal actions (upload, reload services)
```

---

## Configuration

lematt supports two configuration formats:

- **TOML** (recommended): Modern format with native lists, better readability
- **INI** (legacy): Original format, still fully supported

### Configuration Files

| File | Format | Purpose |
|------|--------|---------|
| `lematt.toml` | TOML | All-in-one modern config (domains + actions + settings) |
| `lematt.conf` | INI | Global settings |
| `domains` | Text | Domain list with optional OCSP flags |
| `actions.conf` | INI | Pre/post certificate actions |

lematt auto-detects format: if `lematt.toml` exists, it's used; otherwise falls back to INI files.

---

## TOML Configuration (Recommended)

### Complete Example

```toml
# lematt.toml - Modern configuration format

[config]
# ACME challenge directory (served at /.well-known/acme-challenge/)
challenge_dir = "/var/www/html/.well-known/acme-challenge"

# Account key for Let's Encrypt
# Generate with: openssl genrsa 4096 > account.key
account_key = "/etc/lematt/account.key"

# Renew certificates this many days before expiration
reauthorize_days = 15

# RSA key size (2048, 3072, or 4096)
key_bits_rsa = 2048

# EC curve (prime256v1, secp384r1, or secp521r1)
ec_curve = "prime256v1"

# Always generate new keys on renewal (enables key rotation)
always_generate_new_keys = false


# Domain Configurations
# Each [[domains]] entry creates one certificate (RSA + EC)

[[domains]]
primary = "example.com"
sans = ["www", "mail", "api"]  # Shorthand expands to www.example.com, etc.
ocsp_staple_required = false

[[domains]]
primary = "secure.example.com"
ocsp_staple_required = true    # Enable OCSP Must-Staple

[[domains]]
primary = "cdn.example.com"
sans = ["static.example.com", "assets.example.com"]  # Full FQDNs work too


# Action Configurations

[actions.default]
# Default actions for domains without specific overrides
upload_certs = ["rsync -avz --chmod=F644 CERTS /etc/ssl/certs/"]
upload_keys = ["rsync -avz --chmod=F640 KEYS /etc/ssl/private/"]
update = ["systemctl reload nginx"]

[actions.every]
# Actions that run for EVERY renewed certificate (in addition to others)
update = ["/usr/local/bin/backup-certs.sh"]

[actions.mail_servers]
# Override for specific domains
domains = ["mail.example.com", "smtp.example.com"]
prepare = ["ssh mail-server 'systemctl start acme-responder'"]
upload_certs = ["rsync -avz CERTS mail-server:/etc/ssl/certs/"]
upload_keys = ["rsync -avz KEYS mail-server:/etc/ssl/private/"]
update = [
    "ssh mail-server 'systemctl reload postfix'",
    "ssh mail-server 'systemctl reload dovecot'",
]
```

### TOML Key Reference

#### `[config]` Section

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `challenge_dir` | string | required | Directory for ACME challenge files |
| `account_key` | string | required | Path to Let's Encrypt account key |
| `reauthorize_days` | float | 15.0 | Days before expiry to renew |
| `generate_new_certs_after_days` | float | 0.0 | Renew based on cert age (0 = disabled) |
| `always_generate_new_keys` | bool | false | Generate new keys on each renewal |
| `key_bits_rsa` | int | 2048 | RSA key size |
| `ec_curve` | string | "prime256v1" | EC curve name |
| `rsa_tag` | string | "rsa{bits}" | Filename tag for RSA certs |
| `curve_tag` | string | "{curve}" | Filename tag for EC certs |

#### `[[domains]]` Array

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `primary` | string | required | Primary domain name (CN) |
| `sans` | list[string] | [] | Subject Alternative Names |
| `ocsp_staple_required` | bool | false | Enable OCSP Must-Staple extension |

#### `[actions.*]` Tables

| Key | Type | Description |
|-----|------|-------------|
| `domains` | list[string] | Domains using this action group (not for default/every) |
| `prepare` | list[string] | Commands to run before cert request (killed after) |
| `upload_certs` | list[string] | Commands to upload certificates (CERTS replaced) |
| `upload_keys` | list[string] | Commands to upload private keys (KEYS replaced) |
| `update` | list[string] | Commands to run after successful renewal |

---

## INI Configuration (Legacy)

### lematt.conf

```ini
[config]
# Renew this many days before expiration
reauthorizeDays: 15

# OR: Renew when cert is N days old (overrides reauthorizeDays)
# generateNewCertsAfterDays: 7

# ACME challenge directory
challengeDropDir: /var/www/html/.well-known/acme-challenge

# Account key path
accountKey: /etc/lematt/account.key

# Key configuration
keyBitsRSA: 2048
curve: prime256v1

# Rotate keys on each renewal
alwaysGenerateNewKeys: no
```

### domains

```
# Each line = one certificate
# Format: primary_domain [san1] [san2] ... [+ocsp|-ocsp]

# Basic single domain
example.com

# Domain with SANs (shorthand - "www" becomes "www.example.com")
example.com www mail api

# Domain with full FQDNs as SANs
example.com www.example.com mail.example.com

# Enable OCSP Must-Staple for this certificate
secure.example.com +ocsp

# Explicitly disable OCSP (default)
legacy.example.com -ocsp

# Complex example with multiple SANs and OCSP
corp.example.com intranet hr payroll git wiki +ocsp
```

### actions.conf

```ini
# Default actions (applied when no override matches)
[default]
update: ["systemctl reload nginx"]
uploadCerts: ["rsync -avz CERTS /etc/ssl/certs/"]
uploadKeys: ["rsync -avz KEYS /etc/ssl/private/"]

# Actions for EVERY certificate (in addition to default/override)
[every]
update: ["/usr/local/bin/backup-certs.sh"]

# Override for specific domains
[mail-servers]
domains: mail.example.com smtp.example.com
prepare: ["ssh mail-server 'systemctl start acme-responder'"]
uploadCerts: ["rsync -avz CERTS mail-server:/etc/ssl/certs/"]
uploadKeys: ["rsync -avz KEYS mail-server:/etc/ssl/private/"]
update: ["ssh mail-server 'systemctl reload postfix'"]
```

---

## Migration Guide: INI to TOML

### Configuration Translation

| INI (lematt.conf) | TOML (lematt.toml) |
|-------------------|---------------------|
| `reauthorizeDays: 15` | `reauthorize_days = 15` |
| `challengeDropDir: /path` | `challenge_dir = "/path"` |
| `accountKey: /path` | `account_key = "/path"` |
| `keyBitsRSA: 2048` | `key_bits_rsa = 2048` |
| `curve: prime256v1` | `ec_curve = "prime256v1"` |
| `alwaysGenerateNewKeys: yes` | `always_generate_new_keys = true` |
| `generateNewCertsAfterDays: 7` | `generate_new_certs_after_days = 7` |

### Domains Translation

**INI (domains file):**
```
example.com www mail +ocsp
api.example.com
```

**TOML:**
```toml
[[domains]]
primary = "example.com"
sans = ["www", "mail"]
ocsp_staple_required = true

[[domains]]
primary = "api.example.com"
```

### Actions Translation

**INI (actions.conf):**
```ini
[default]
update: ["systemctl reload nginx"]
uploadCerts: ["rsync -avz CERTS /etc/ssl/"]

[mail-override]
domains: mail.example.com
prepare: ["ssh mail start-responder"]
update: ["ssh mail reload-postfix"]
```

**TOML:**
```toml
[actions.default]
update = ["systemctl reload nginx"]
upload_certs = ["rsync -avz CERTS /etc/ssl/"]

[actions.mail_override]
domains = ["mail.example.com"]
prepare = ["ssh mail start-responder"]
update = ["ssh mail reload-postfix"]
```

### Key Differences

| Aspect | INI | TOML |
|--------|-----|------|
| Lists | JSON syntax: `["a", "b"]` | Native TOML: `["a", "b"]` |
| Booleans | `yes`/`no` | `true`/`false` |
| Key naming | camelCase | snake_case |
| OCSP config | In domains file: `+ocsp` | In `[[domains]]`: `ocsp_staple_required = true` |
| Domains | Separate file | Inline `[[domains]]` array |
| Actions | Separate file | Inline `[actions.*]` tables |

---

## CLI Reference

### Mode Selection (Required)

```bash
lematt --test    # Use Let's Encrypt staging endpoint (always test first!)
lematt --prod    # Use Let's Encrypt production endpoint
```

### Information Commands

```bash
# Show certificate status
lematt --test --status

# Status as JSON (for monitoring systems)
lematt --test --status --json

# List all configured domains
lematt --test --list-domains

# List domains as JSON
lematt --test --list-domains --json

# Validate configuration only
lematt --test --validate-config
```

### Processing Options

```bash
# Parallel processing (max 10 workers)
lematt --prod --parallel 5

# Process single domain
lematt --prod --domain example.com

# Force renewal regardless of expiration
lematt --prod --force-renew

# Dry run (show what would happen)
lematt --prod --dry-run

# Minimize output (for cron)
lematt --prod --cron
```

### Configuration

```bash
# Use custom config path
lematt --test --config /path/to/lematt.conf

# Generate example TOML config
lematt --test --init-toml

# Verbose output
lematt --test -v
```

### Complete Options

```
usage: lematt [-h] (--prod | --test) [--cron] [--parallel N] [--config PATH]
              [-v] [--dry-run] [--status] [--json] [--list-domains]
              [--validate-config] [--domain DOMAIN] [--force-renew]
              [--init-toml]

Options:
  --prod              Use production Let's Encrypt endpoint
  --test              Use staging Let's Encrypt endpoint
  --cron              Minimize output (only errors and renewals)
  --parallel N        Process N certificates in parallel (max 10)
  --config PATH       Path to configuration file
  -v, --verbose       Enable debug output
  --dry-run           Show what would be done without changes
  --status            Show certificate status and exit
  --json              Output as JSON (use with --status or --list-domains)
  --list-domains      List all configured domains and exit
  --validate-config   Validate configuration without processing
  --domain DOMAIN     Process only specified domain
  --force-renew       Force renewal regardless of expiration
  --init-toml         Create example lematt.toml and exit
```

---

## JSON Output Examples

### Certificate Status

```bash
lematt --test --status --json
```

```json
{
  "certificates": [
    {
      "domain": "example.com",
      "san_domains": ["www.example.com"],
      "key_type": "rsa",
      "cert_path": "/path/to/cert.pem",
      "exists": true,
      "status": "ok",
      "expires": "2024-06-15T12:00:00",
      "days_until_expiry": 45
    },
    {
      "domain": "example.com",
      "san_domains": ["www.example.com"],
      "key_type": "ec",
      "cert_path": "/path/to/cert.pem",
      "exists": true,
      "status": "renew_soon",
      "expires": "2024-05-10T12:00:00",
      "days_until_expiry": 12
    }
  ],
  "summary": {
    "total": 4,
    "ok": 2,
    "renew_soon": 1,
    "critical": 0,
    "expired": 0,
    "missing": 1
  },
  "using_native_crypto": true
}
```

### Domain List

```bash
lematt --test --list-domains --json
```

```json
[
  {
    "primary": "example.com",
    "sans": ["www.example.com", "mail.example.com"],
    "all_domains": ["example.com", "www.example.com", "mail.example.com"],
    "ocsp_staple_required": false
  },
  {
    "primary": "secure.example.com",
    "sans": [],
    "all_domains": ["secure.example.com"],
    "ocsp_staple_required": true
  }
]
```

---

## Workflow Actions

### Action Types

| Action | When | Variables | Purpose |
|--------|------|-----------|---------|
| `prepare` | Before cert request | `DOMAIN` | Start temp servers, open ports |
| `upload_certs` | After successful renewal | `CERTS` | Copy certificates |
| `upload_keys` | After successful renewal | `KEYS` | Copy private keys |
| `update` | After successful renewal | `DOMAINS_CN`, `DOMAINS_ALL` | Reload services |

### Variable Expansion

| Variable | Expands To | Example |
|----------|------------|---------|
| `DOMAIN` | Current domain being prepared | `mail.example.com` |
| `CERTS` | Shell glob for cert files | `'/path/cert/example.com*' '/path/cert/www*'` |
| `KEYS` | Shell glob for key files | `'/path/key/example.com*' '/path/key/www*'` |
| `DOMAINS_CN` | Space-separated primary domains | `example.com other.com` |
| `DOMAINS_ALL` | All domains including SANs | `example.com www.example.com mail.example.com` |

### Execution Order

1. **prepare** actions start (async processes kept alive during challenge)
2. Certificate request to Let's Encrypt
3. **prepare** processes killed (graceful termination)
4. If successful:
   - **upload_certs** commands run
   - **upload_keys** commands run
   - **update** commands run

### Action Groups

| Section | Behavior |
|---------|----------|
| `[default]` | Applied to domains without specific override |
| `[every]` | Applied to ALL renewed certificates (in addition) |
| `[custom-name]` | Applied only to domains listed in `domains` key |

---

## OCSP Must-Staple

OCSP Must-Staple is a certificate extension that tells browsers to require OCSP stapling. This improves security but requires server configuration.

### Per-Domain Configuration

**domains file (INI):**
```
example.com www +ocsp           # Enable OCSP
legacy.example.com -ocsp        # Explicitly disable (default)
```

**TOML:**
```toml
[[domains]]
primary = "example.com"
sans = ["www"]
ocsp_staple_required = true
```

### Server Configuration Required

When using OCSP Must-Staple, configure your web server:

**nginx:**
```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

**Apache:**
```apache
SSLUseStapling On
SSLStaplingCache shmcb:${APACHE_RUN_DIR}/ssl_stapling(32768)
```

---

## Performance

### Native Cryptography

Install the optional `cryptography` package for ~5x faster certificate parsing:

```bash
uv sync --extra crypto
# or: pip install cryptography
```

Check if native crypto is active:
```bash
lematt --test --status  # Shows "(Using native cryptography library)"
```

### Parallel Processing

Process multiple certificates concurrently:

```bash
# Process 5 certificates in parallel
lematt --prod --parallel 5
```

| Workers | 50 Certs Time | Speedup |
|---------|---------------|---------|
| 1 | ~120 seconds | 1x |
| 5 | ~25 seconds | 5x |
| 10 | ~15 seconds | 8x |

**Rate Limiting**: Built-in token bucket limits to 10 requests/second to respect Let's Encrypt API limits.

---

## Testing

### Always Test First

```bash
# 1. Validate configuration
lematt --test --validate-config

# 2. Check domain list
lematt --test --list-domains

# 3. Dry run
lematt --test --dry-run

# 4. Full test run (uses staging endpoint)
lematt --test

# 5. Check results
lematt --test --status
```

### Test vs Production

| Aspect | `--test` | `--prod` |
|--------|----------|----------|
| Endpoint | staging-v02.api.letsencrypt.org | acme-v02.api.letsencrypt.org |
| Rate limits | High (for testing) | Low (production limits) |
| Certificates | Not trusted by browsers | Trusted |
| File suffix | `.test.pem` | `.pem` |
| Directory | `test/` | `prod/` |

---

## Troubleshooting

### Common Issues

**"Config file not found"**
```bash
# Ensure config exists
ls conf/lematt.conf conf/lematt.toml

# Or specify path
lematt --test --config /path/to/lematt.conf
```

**"Account key doesn't exist"**
```bash
# Generate account key
openssl genrsa 4096 > /etc/lematt/account.key
chmod 600 /etc/lematt/account.key
```

**"Challenge directory does not exist"**
```bash
mkdir -p /var/www/html/.well-known/acme-challenge
# Ensure web server serves this path
```

**"Rate limit exceeded"**
- Use `--test` mode for development
- Wait for rate limit window to reset (usually 1 week)
- Consider using `--dry-run` to verify configuration

### Logging

Enable verbose output:
```bash
lematt --test -v
```

All logging uses loguru with structured output including timestamps and log levels.

---

## Programmatic Usage

### Python API

```python
from lematt import (
    LemattConfig,
    DomainConfig,
    CertificateManager,
    CertificateExecutor,
    ActionRunner,
    DomainActions,
)

# Create configuration
config = LemattConfig(
    config_base="/etc/lematt",
    challenge_dir="/var/www/challenges",
    account_key="/etc/lematt/account.key",
    is_test=True,
)

# Define domains
domains = [
    DomainConfig(
        primary_domain="example.com",
        san_domains=["www.example.com"],
        ocsp_staple_required=False,
    ),
]

# Load actions
actions = ActionRunner(config)
actions.load_actions()

# Process certificates
executor = CertificateExecutor(
    config=config,
    max_workers=5,
    rate_limit=10.0,
)

summary = executor.process_batch(
    domains=domains,
    domain_actions=actions.domain_actions,
)

print(f"Renewed: {summary.renewed_count}, Failed: {summary.failed_count}")
```

### Using ConfigLoader

```python
from pathlib import Path
from lematt import ConfigLoader

# Load configuration (auto-detects TOML or INI)
loader = ConfigLoader(config_base=Path("/etc/lematt"))
loader.load()

# Get typed configuration
config = loader.get_lematt_config(
    is_test=True,
    concurrency=5,
)

# Get domains and actions
domains = loader.get_domains()
actions = loader.get_actions()
```

---

## Security Considerations

1. **File Permissions**: Private keys are created with 0600 permissions
2. **Account Key**: Store securely, never commit to version control
3. **Action Commands**: Review carefully - they run with lematt's privileges
4. **Rate Limits**: Don't burn through production limits during testing

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: `uv run pytest`
4. Run linter: `uv run ruff check src/`
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/mattsta/lematt
cd lematt
uv sync --dev
uv run ruff check src/
uv run pytest
```

---

## License

Apache 2.0

---

## Acknowledgments

- [acme-tiny](https://github.com/diafygi/acme-tiny) - ACME client library
- [Let's Encrypt](https://letsencrypt.org/) - Free, automated certificates
- [loguru](https://github.com/Delgan/loguru) - Beautiful Python logging
