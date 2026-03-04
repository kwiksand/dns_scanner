# DNS Latency Tester & Dashboard

A comprehensive tool to monitor and analyze the latency of various public DNS servers. It supports standard DNS (UDP), DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ) protocols. Features include a persistent SQLite database for historical trends and a modern web dashboard for management.

## Features

- **Multi-Protocol Support**: Test DNS, DoT, DoH, and DoQ.
- **Persistent Storage**: All test results are stored in an SQLite database.
- **Web Dashboard**: View historical statistics, manage server lists, and trigger manual scans.
- **Automated Management**: Automatically disables failing servers with a 48-hour retry expiry.
- **Slack Notifications**: Send test results and recommendations to a Slack channel.

## Prerequisites

- Python 3.11+
- [Docker](https://docs.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) (recommended)
- Or install local dependencies: `pip install -r app/requirements.txt`

## Web Dashboard

The web interface provides a central point for monitoring and configuration.

- **Historical Stats**: View cumulative average, min, and max latencies, along with total runs and failure counts.
- **Server Management**: Enable/disable providers or individual endpoints, and add new servers to the tracking list.
- **Manual Scan**: Trigger a fresh latency test across all enabled servers at any time.

By default, the dashboard is accessible at `http://localhost:5000`.

## Docker Usage (Recommended)

The easiest way to run the DNS Scanner is via Docker Compose.

### Quick Start
```bash
docker-compose up --build
```

### Persistence
The `docker-compose.yml` is configured to persist your configuration and database:
- `app/config.yml`: Stores your server list and preferences.
- `app/dns_scanner.db`: Stores all historical latency data.

## CLI Usage

You can also run the scanner directly via the command line for one-off tests or statistics.

### Run a Latency Test
```bash
python3 app/dns_latency_tester.py --verbose
```

### View Historical Stats
```bash
python3 app/dns_latency_tester.py --stats
```

### Command-Line Arguments
- `--format [table|json]`: Specify output format (default: `table`).
- `-v, --verbose`: Show detailed progress of each test run.
- `-r, --refresh-server-list`: Check availability of all servers and update their `enabled` status in `config.yml`.
- `-a, --test-all`: Force a test of all servers, including those currently disabled.
- `-s, --slack-webhook [url]`: Send results to a specific Slack webhook.

## Configuration (`config.yml`)

The `config.yml` file defines the servers and notification settings.

### Server Structure
```yaml
servers:
  providers:
    Cloudflare:
    - protocol: DNS
      endpoint: 1.1.1.1
      enabled: true
    - protocol: DoH
      endpoint: https://cloudflare-dns.com/dns-query
      enabled: true
```

### Notification Settings
```yaml
notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
```

## Database Schema

The SQLite database (`dns_scanner.db`) contains a `server_stats` table with the following fields:
- `provider`, `protocol`, `endpoint`: Identifiers for the server.
- `total_runs`: Number of times the server has been included in a scan.
- `total_queries`: Total individual DNS queries attempted.
- `failed_queries`: Number of queries that timed out or failed.
- `min_latency`, `max_latency`: All-time minimum and maximum response times.
- `avg_latency`: A moving average of successful query response times.

---
*Note: This project is intended for monitoring and optimization of DNS performance. Please ensure you comply with the terms of service of any public DNS providers you test.*
