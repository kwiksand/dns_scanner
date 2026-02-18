# DNS Latency Tester

A simple Python script to test the latency of various public DNS servers. It supports standard DNS (UDP), DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ) protocols.

## Prerequisites

*   Python 3
*   The `dig` command-line tool. (Usually part of `dnsutils` or `bind-utils` package)
*   The PyYAML Python library: `pip install pyyaml`

## Configuration (`config.yml`)

The `config.yml` file contains the list of DNS servers to be tested. You can add, remove, or modify providers and their endpoints.

### Structure
The configuration is structured as follows:
```yaml
servers:
  providers:
    ProviderName:
    - protocol: <protocol>
      endpoint: <ip_or_hostname>
      enabled: <true_or_false>
    - ...
    AnotherProvider:
    - ...
```
### Fields
*   **ProviderName:** The name of the DNS provider (e.g., Cloudflare, Google).
*   **protocol:** The query protocol. Supported values are:
    *   `DNS`: Standard DNS over UDP port 53.
    *   `IPv6`: Standard DNS using an IPv6 address.
    *   `DoT`: DNS-over-TLS.
    *   `DoH`: DNS-over-HTTPS.
    *   `DoQ`: DNS-over-QUIC.
*   **endpoint:** The IP address or hostname of the DNS server.
*   **enabled:** Set to `true` to include the server in the latency tests, or `false` to exclude it.

## Usage

The script is executed from the command line.

### Basic Test
To run the latency test on all enabled servers in `config.yml`:
```bash
python3 dns_latency_tester.py
```
This will display a summary table sorted by average latency.

### Command-Line Arguments

*   **`--format [table|json]`**: Specify the output format.
    *   `table` (default): A human-readable table.
    *   `json`: A machine-readable JSON output.
    ```bash
    python3 dns_latency_tester.py --format json
    ```

*   **`-v, --verbose`**: Enable verbose output.
    Shows the progress of each individual test run.
    ```bash
    python3 dns_latency_tester.py --verbose
    ```

*   **`-r, --refresh-server-list`**: Refresh the server list.
    This command checks the availability of *all* servers listed in `config.yml` (both enabled and disabled). It then updates the `enabled` status for each server in the file based on whether a successful response can be received. This is useful for finding which servers are currently reachable from your network.
    ```bash
    python3 dns_latency_tester.py --refresh-server-list
    ```

*   **`-a, --test-all`**: Override disabled tests.
    Re-tests all servers regardless of their enabled status or expiry.
    ```bash
    python3 dns_latency_tester.py --test-all
    ```

*   **`-s, --slack-webhook [url]`**: Send results to Slack.
    Overrides the webhook URL in `config.yml`.
    ```bash
    python3 dns_latency_tester.py --slack-webhook https://hooks.slack.com/services/...
    ```

## Docker Usage

A `Dockerfile` and `docker-compose.yml` are provided for containerized execution.

### Build and Run
```bash
docker-compose build
docker-compose run dns-scanner
```

### Configuration
Mount your `config.yml` into the container:
```yaml
volumes:
  - ./config.yml:/app/config.yml
```

### Scheduling
To run the scanner on a schedule (e.g., daily), you can use the host's cron:
```bash
# Run daily at 3 AM
0 3 * * * cd /path/to/dns_scanner && docker-compose run --rm dns-scanner
```

## Example Output

### Table Format
```
--- Top 5 DNS results ---
Provider                  Min (ms)   Avg (ms)   Max (ms)   Endpoint
------------------------- ---------- ---------- ---------- ---------------------------------------------
Cloudflare                15         18         25         1.1.1.1
...

--- All Successful Tests (sorted by avg, min, max latency) ---
Provider                  Protocol   Min (ms)   Avg (ms)   Max (ms)   Endpoint
------------------------- ---------- ---------- ---------- ---------- ---------------------------------------------
Cloudflare                DoQ        15         18         25         cloudflare-dns.com
Google                    DoT        18         22         30         dns.google
...

--- Failed or Timed Out (0 successful tests) ---
Provider                  Protocol   Endpoint
------------------------- ---------- ---------------------------------------------
SomeProvider              DNS        1.2.3.4
...
```

### JSON Format
```json
{
  "results": [
    {
      "info": {
        "provider": "Cloudflare",
        "protocol": "DoQ",
        "endpoint": "cloudflare-dns.com"
      },
      "stats": {
        "min": 15,
        "avg": 18,
        "max": 25,
        "successful_tests": 20
      }
    }
  ],
  "failed": [
    {
      "provider": "SomeProvider",
      "protocol": "DNS",
      "endpoint": "1.2.3.4"
    }
  ]
}
```
