"""Contextual help system for lematt.

This module provides detailed, context-aware help information including
command documentation, configuration examples, troubleshooting tips,
and interactive help browsing.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Protocol

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .display import StatusStyle, console


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
        summary="Execute certificate renewal for all or specific domains",
        content="""
# lematt run

The `run` command executes the certificate renewal workflow. It checks
certificate expiry, requests new certificates from Let's Encrypt when
needed, and executes configured deployment actions.

## Options

- `--domain, -d`: Renew only specific domains (can be repeated)
- `--force`: Force renewal even if certificates aren't expiring
- `--dry-run`: Simulate renewal without making changes
- `--test`: Use Let's Encrypt staging environment
- `--concurrent, -c`: Maximum concurrent renewals (default: 4)

## Workflow

1. Load configuration from `lematt.toml`
2. Check certificate expiry for configured domains
3. Generate CSRs for certificates needing renewal
4. Complete ACME HTTP-01 challenges
5. Download and save new certificates
6. Execute deployment actions (prepare, upload, update)

## Exit Codes

- 0: All renewals successful
- 1: Some renewals failed
- 2: Configuration error
""",
        examples=[
            "lematt run                          # Renew all certificates",
            "lematt run --domain example.com    # Renew specific domain",
            "lematt run --force                 # Force renewal",
            "lematt run --dry-run               # Preview changes",
            "lematt run --test                  # Use staging server",
        ],
        see_also=["status", "health", "config"],
        keywords=["renew", "certificate", "acme", "lets encrypt"],
    ),
    "status": HelpTopic(
        name="status",
        title="Check Certificate Status",
        category=HelpCategory.COMMANDS,
        summary="Display current certificate status and expiry information",
        content="""
# lematt status

The `status` command displays the current state of all configured
certificates including expiry dates, health status, and deployment info.

## Options

- `--domain, -d`: Check only specific domains
- `--json`: Output in JSON format
- `--prometheus`: Output in Prometheus metrics format
- `--verbose, -v`: Show additional details

## Output Columns

- **Status**: Health indicator (✓ healthy, ⚠ warning, ✗ critical)
- **Domain**: Primary domain name
- **Type**: Key type (RSA or EC)
- **Expires**: Certificate expiry date
- **Days**: Days until expiration
- **Path**: Certificate file location

## Status Thresholds

- **Healthy**: More than 14 days until expiry
- **Warning**: 7-14 days until expiry
- **Critical**: Less than 7 days or expired
""",
        examples=[
            "lematt status                       # Show all certificates",
            "lematt status --json               # JSON output for scripting",
            "lematt status --prometheus         # Metrics for monitoring",
            "lematt status -v                   # Verbose output",
        ],
        see_also=["health", "dashboard", "run"],
        keywords=["certificate", "expiry", "check", "info"],
    ),
    "health": HelpTopic(
        name="health",
        title="Health Check System",
        category=HelpCategory.COMMANDS,
        summary="Comprehensive health checking for certificates and system",
        content="""
# lematt health

The `health` command performs comprehensive health checks on all
certificates and the overall system, providing detailed diagnostics.

## Options

- `--live`: Check live certificates served by servers
- `--output, -o`: Write results to file
- `--format, -f`: Output format (json, prometheus, text)
- `--warning-days`: Days threshold for warnings (default: 14)
- `--critical-days`: Days threshold for critical (default: 7)

## Checks Performed

1. **Certificate File Checks**
   - File exists and is readable
   - Valid X.509 format
   - Expiry date within thresholds
   - Certificate chain validity

2. **Live Certificate Checks** (--live)
   - SSL/TLS connection to server
   - Certificate matches expected domain
   - Proper chain presentation
   - OCSP stapling (if configured)

## Integration

Health check output can be integrated with monitoring systems:
- Prometheus metrics endpoint
- Nagios/Icinga check scripts
- JSON for custom integrations
""",
        examples=[
            "lematt health                       # Check all certificates",
            "lematt health --live               # Check live servers too",
            "lematt health -f prometheus -o /var/lib/lematt/metrics",
            "lematt health --warning-days 30    # Custom thresholds",
        ],
        see_also=["status", "monitoring", "prometheus"],
        keywords=["health", "check", "monitoring", "diagnostics"],
    ),
    "dashboard": HelpTopic(
        name="dashboard",
        title="Interactive Dashboard",
        category=HelpCategory.COMMANDS,
        summary="Live-updating terminal dashboard for monitoring",
        content="""
# lematt dashboard

The `dashboard` command launches an interactive terminal dashboard
with live-updating certificate status and health information.

## Options

- `--refresh, -r`: Refresh interval in seconds (default: 5)
- `--compact`: Use compact display mode
- `--no-sidebar`: Hide the sidebar

## Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit dashboard |
| `r` | Force refresh |
| `p` | Pause/resume auto-refresh |
| `c` | Toggle compact mode |
| `1` | Overview view |
| `2` | Certificates view |
| `3` | Health details view |
| `4` | Activity log view |

## Views

1. **Overview**: Summary of system health with quick stats
2. **Certificates**: Detailed certificate table
3. **Health**: Extended health information with messages
4. **Logs**: Activity log showing recent operations
""",
        examples=[
            "lematt dashboard                    # Launch dashboard",
            "lematt dashboard --refresh 10      # Slower refresh",
            "lematt dashboard --compact         # Compact mode",
        ],
        see_also=["status", "health"],
        keywords=["dashboard", "interactive", "monitor", "live"],
    ),
    "config": HelpTopic(
        name="config",
        title="Configuration Commands",
        category=HelpCategory.COMMANDS,
        summary="View and validate configuration",
        content="""
# lematt config

Commands for managing lematt configuration.

## Subcommands

### lematt config show

Display the current configuration in a readable tree format.

### lematt config validate

Validate the configuration file and report any errors.

### lematt config init

Create a new configuration file with example values.

## Configuration File

By default, lematt looks for configuration at:
1. `./lematt.toml` (current directory)
2. `/etc/lematt/lematt.toml` (system-wide)
3. Custom path via `--config` flag

## Validation Checks

- TOML syntax validity
- Required fields present
- Path existence verification
- Domain format validation
- Action command safety checks
""",
        examples=[
            "lematt config show                  # Display config",
            "lematt config validate             # Validate config",
            "lematt config init                 # Create example config",
            "lematt --config /path/to/config.toml run",
        ],
        see_also=["configuration", "domains", "actions"],
        keywords=["config", "configuration", "toml", "setup"],
    ),
    # Configuration topics
    "configuration": HelpTopic(
        name="configuration",
        title="Configuration File Format",
        category=HelpCategory.CONFIGURATION,
        summary="Complete guide to lematt.toml configuration",
        content="""
# Configuration File Format

lematt uses TOML format for configuration. The file is organized
into several sections.

## File Structure

```toml
# Global settings
[global]
acme_directory = "https://acme-v02.api.letsencrypt.org/directory"
cert_directory = "/etc/lematt/certs"
webroot_path = "/var/www/.well-known/acme-challenge"
test_mode = false

# Account settings
[account]
email = "admin@example.com"
key_path = "/etc/lematt/account.key"

# Certificate settings
[certificates]
key_types = ["rsa", "ec"]
rsa_key_size = 2048
ec_curve = "secp384r1"
days_before_expiry = 30

# Domain configurations
[[domains]]
primary_domain = "example.com"
san_domains = ["www.example.com"]
ocsp_staple_required = false

# Deployment actions
[actions.default]
update_commands = ["systemctl reload nginx"]
```

## Section Reference

See individual help topics for detailed section documentation:
- `domains` - Domain configuration
- `actions` - Deployment actions
- `certificates` - Certificate settings
""",
        examples=[
            "# Minimal configuration",
            "[account]",
            'email = "admin@example.com"',
            "",
            "[[domains]]",
            'primary_domain = "example.com"',
        ],
        see_also=["domains", "actions", "config"],
        keywords=["toml", "config", "settings", "format"],
    ),
    "domains": HelpTopic(
        name="domains",
        title="Domain Configuration",
        category=HelpCategory.CONFIGURATION,
        summary="Configure domains for certificate generation",
        content="""
# Domain Configuration

Each `[[domains]]` section defines a certificate to manage.

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `primary_domain` | string | Main domain for the certificate |
| `san_domains` | array | Additional domains (SANs) |
| `ocsp_staple_required` | bool | Enable OCSP stapling |
| `key_types` | array | Override global key types |

## SAN Certificates

You can include up to 100 Subject Alternative Names (SANs) per
certificate. This is useful for:

- Multiple subdomains: `www`, `api`, `mail`
- Related domains: `example.com`, `example.org`
- Wildcard alternatives

## Example Configurations

### Simple Single Domain
```toml
[[domains]]
primary_domain = "example.com"
```

### Domain with SANs
```toml
[[domains]]
primary_domain = "example.com"
san_domains = ["www.example.com", "api.example.com"]
```

### Multiple Certificates
```toml
[[domains]]
primary_domain = "example.com"
san_domains = ["www.example.com"]

[[domains]]
primary_domain = "api.example.com"
ocsp_staple_required = true
```
""",
        examples=[
            '[[domains]]',
            'primary_domain = "example.com"',
            'san_domains = ["www.example.com", "mail.example.com"]',
            'ocsp_staple_required = true',
        ],
        see_also=["configuration", "certificates", "actions"],
        keywords=["domain", "san", "certificate", "subdomain"],
    ),
    "actions": HelpTopic(
        name="actions",
        title="Deployment Actions",
        category=HelpCategory.ACTIONS,
        summary="Configure post-renewal deployment actions",
        content="""
# Deployment Actions

Actions are shell commands executed after certificate renewal.
They're organized into phases and can target specific domains.

## Action Phases

1. **prepare**: Run before certificate upload
   - Create directories
   - Stop services temporarily

2. **upload_certs**: Deploy certificate files
   - rsync to remote servers
   - Copy to application directories

3. **upload_keys**: Deploy private keys (separate for security)
   - rsync with restricted permissions
   - Secure copy operations

4. **update**: Run after deployment
   - Reload services (nginx, apache)
   - Restart applications
   - Clear caches

## Configuration

```toml
[actions.default]
# Applies to all domains
update_commands = ["systemctl reload nginx"]

[actions.api-servers]
# Specific domain group
domains = ["api.example.com"]
upload_certs_commands = [
    "rsync -avz certs/ api1.example.com:/etc/ssl/",
    "rsync -avz certs/ api2.example.com:/etc/ssl/",
]
update_commands = [
    "ssh api1.example.com systemctl reload nginx",
    "ssh api2.example.com systemctl reload nginx",
]
```

## Command Variables

Commands can use these variables:
- `{domain}`: Primary domain name
- `{cert_path}`: Full certificate path
- `{key_path}`: Private key path
- `{cert_dir}`: Certificate directory
""",
        examples=[
            "[actions.webservers]",
            'domains = ["example.com", "www.example.com"]',
            "upload_certs_commands = [",
            '    "rsync -avz {cert_path} web1:/etc/ssl/certs/"',
            "]",
            "update_commands = [",
            '    "ssh web1 systemctl reload nginx"',
            "]",
        ],
        see_also=["configuration", "domains", "run"],
        keywords=["actions", "deploy", "upload", "rsync", "reload"],
    ),
    # Systemd topics
    "systemd": HelpTopic(
        name="systemd",
        title="Systemd Integration",
        category=HelpCategory.SYSTEMD,
        summary="Automated renewal with systemd timers",
        content="""
# Systemd Integration

lematt can install systemd timer units for automated certificate
renewal without cron.

## Commands

### Install Timer
```bash
lematt systemd install [--preset NAME]
```

### Uninstall Timer
```bash
lematt systemd uninstall
```

### Check Status
```bash
lematt systemd status
```

## Presets

| Preset | Schedule | Description |
|--------|----------|-------------|
| `default` | Twice daily | Let's Encrypt recommended |
| `aggressive` | 4x daily | Frequent checks |
| `conservative` | Daily at 3 AM | Low frequency |
| `weekly` | Weekly on Monday | Minimal checks |

## Generated Units

The installer creates:
1. `lematt-renew.service` - Renewal service unit
2. `lematt-renew.timer` - Timer for scheduling
3. `/usr/local/bin/lematt-notify.sh` - Notification script
4. `/etc/lematt/notify.conf` - Notification configuration

## Security Hardening

The service unit includes security features:
- PrivateTmp enabled
- ProtectSystem=strict
- ProtectHome=true
- NoNewPrivileges=true
- Resource limits (CPU, memory)
""",
        examples=[
            "lematt systemd install              # Install with defaults",
            "lematt systemd install --preset aggressive",
            "lematt systemd status              # Check timer status",
            "lematt systemd uninstall           # Remove timer",
            "systemctl list-timers              # View all timers",
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

lematt supports multiple monitoring system integrations.

## Prometheus Metrics

Export metrics in Prometheus format:

```bash
lematt health -f prometheus -o /var/lib/lematt/metrics.prom
```

### Available Metrics

- `lematt_certificate_expiry_days` - Days until expiry (gauge)
- `lematt_certificate_status` - Health status code (gauge)
- `lematt_health_check_timestamp_seconds` - Last check time
- `lematt_certificates_total` - Certificate counts by status

### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'lematt'
    static_configs:
      - targets: ['localhost:9100']
    metrics_path: /var/lib/lematt/metrics.prom
```

## Nagios/Icinga Checks

Use the health check script:

```bash
/var/lib/lematt/healthcheck.sh
```

Exit codes:
- 0: OK (all healthy)
- 1: WARNING (warnings present)
- 2: CRITICAL (critical issues)
- 3: UNKNOWN (check failed)

## JSON API

For custom integrations:

```bash
lematt health -f json -o /var/lib/lematt/health.json
```
""",
        examples=[
            "lematt health -f prometheus -o /metrics/lematt.prom",
            "# Prometheus node_exporter textfile collector",
            "mv /metrics/lematt.prom /var/lib/node_exporter/textfile/",
        ],
        see_also=["health", "prometheus", "notifications"],
        keywords=["monitoring", "prometheus", "nagios", "metrics"],
    ),
    "notifications": HelpTopic(
        name="notifications",
        title="Notification System",
        category=HelpCategory.MONITORING,
        summary="Configure alerts and notifications",
        content="""
# Notification System

lematt supports multiple notification channels for alerts.

## Supported Channels

1. **Email** - SMTP email notifications
2. **Webhook** - Slack, Discord, custom webhooks
3. **PagerDuty** - Incident management
4. **Ntfy** - Self-hosted push notifications
5. **Custom** - Run any shell command

## Configuration

Edit `/etc/lematt/notify.conf`:

```bash
# Email
NOTIFY_EMAIL="admin@example.com"

# Slack/Discord webhook
NOTIFY_WEBHOOK="https://hooks.slack.com/services/XXX"

# PagerDuty (failures only)
PAGERDUTY_KEY="your-integration-key"

# Ntfy
NTFY_TOPIC="cert-alerts"
NTFY_SERVER="https://ntfy.sh"

# Custom command
NOTIFY_CUSTOM_CMD="/usr/local/bin/my-notify.sh"
```

## Event Types

- **success**: Certificate renewed successfully
- **failure**: Renewal failed
- **warning**: Certificate expiring soon (configurable days)

## Testing

```bash
/usr/local/bin/lematt-notify.sh success "Test notification"
/usr/local/bin/lematt-notify.sh failure "Test failure"
```
""",
        examples=[
            '# /etc/lematt/notify.conf',
            'NOTIFY_EMAIL="ops@example.com"',
            'NOTIFY_WEBHOOK="https://hooks.slack.com/..."',
            'NTFY_TOPIC="infra-alerts"',
        ],
        see_also=["systemd", "monitoring", "health"],
        keywords=["notify", "alert", "slack", "email", "webhook"],
    ),
    # Troubleshooting
    "troubleshooting": HelpTopic(
        name="troubleshooting",
        title="Troubleshooting Guide",
        category=HelpCategory.TROUBLESHOOTING,
        summary="Common issues and solutions",
        content="""
# Troubleshooting Guide

## Common Issues

### Challenge Verification Failed

**Symptoms**: ACME challenge fails, certificate not issued

**Causes & Solutions**:
1. **Firewall blocking port 80**: Ensure HTTP is accessible
2. **Webroot not configured**: Check nginx/apache configuration
3. **DNS not propagated**: Wait for DNS changes to propagate

```bash
# Test challenge file accessibility
echo "test" > /var/www/.well-known/acme-challenge/test
curl -v http://yourdomain.com/.well-known/acme-challenge/test
```

### Permission Denied

**Symptoms**: Cannot write certificates, access denied errors

**Solutions**:
1. Run as root or with sudo
2. Check directory permissions: `ls -la /etc/lematt/`
3. Verify SELinux context if applicable

### Rate Limit Exceeded

**Symptoms**: "Too many requests" error from Let's Encrypt

**Solutions**:
1. Use `--test` flag for testing (staging server)
2. Wait for rate limit reset (weekly)
3. Consolidate domains into fewer certificates

### Certificate Not Updating on Server

**Symptoms**: Server still shows old certificate

**Solutions**:
1. Check action commands completed successfully
2. Verify nginx/apache reload: `systemctl status nginx`
3. Check certificate path in server config

## Debug Mode

Enable verbose logging:
```bash
lematt run --verbose --debug
```

## Log Files

- Systemd logs: `journalctl -u lematt-renew`
- Health status: `/var/lib/lematt/health.json`
""",
        examples=[
            "# Debug renewal",
            "lematt run --verbose --debug --dry-run",
            "",
            "# Check challenge accessibility",
            "curl http://domain.com/.well-known/acme-challenge/test",
            "",
            "# View service logs",
            "journalctl -u lematt-renew -f",
        ],
        see_also=["run", "health", "config"],
        keywords=["debug", "error", "fix", "problem", "issue"],
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
        """Search for topics matching a query."""
        query_lower = query.lower()
        results = []

        for topic in self.topics.values():
            # Check name, title, summary, and keywords
            if (
                query_lower in topic.name.lower()
                or query_lower in topic.title.lower()
                or query_lower in topic.summary.lower()
                or any(query_lower in kw for kw in topic.keywords)
            ):
                results.append(topic)

        return results

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
        content_parts = []

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
                see_also_text.append(f"lematt help {ref}", style="cyan")
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
                "Try `lematt help` to see all available topics.",
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
        console.print("[dim]Use 'lematt help <topic>' for detailed help[/dim]")


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
