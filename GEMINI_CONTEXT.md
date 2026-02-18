# Gemini Context: DNS Latency Tester

This document provides a summary of the current state of the DNS Latency Tester project and outlines potential future improvements.

## Project Overview

The DNS Latency Tester is a Python-based utility designed to measure the response times of various public DNS servers across different protocols. It helps users identify the fastest and most reliable DNS providers for their network.

### Key Features

*   **Multi-Protocol Support:** Currently supports standard DNS (UDP), IPv6, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ).
*   **Configurable Providers:** DNS providers and their endpoints are managed through a `config.yml` file.
*   **Concurrent Testing:** Uses Python's `threading` and `queue` modules to perform latency tests in parallel.
*   **Automated Config Management:** Fails tests are automatically disabled in `config.yml` with a 48-hour `expiry`. Servers are re-enabled automatically once the expiry passes.
*   **Availability Refresh:** Includes a `-r` or `--refresh-server-list` flag to check all configured servers.
*   **Test All Override:** Includes a `-a` or `--test-all` flag to re-test all servers regardless of their `enabled` status.
*   **Slack Notifications:** Can send test results and recommendations to a Slack webhook configured in `config.yml` or passed via `--slack-webhook`.
*   **Enhanced Reporting:**
    *   Results sorted by average, then minimum, then maximum latency.
    *   Displays the top 5 results for each protocol (DNS, DoT, DoH, DoQ, etc.).
    *   Supports human-readable table output and machine-readable JSON format.

### Current Implementation Details

*   **Language:** Python 3.
*   **Core Libraries:** `dnspython` (with `aioquic`, `h2`, `httpx` for advanced protocols) and `PyYAML`.
*   **Logic:**
    *   Loads configuration from `config.yml`.
    *   For each enabled server, it spawns a thread to perform a series of queries (currently 20 tests across 4 domains).
    *   Calculates min, average, and max latency.
    *   Reports results sorted by average latency.
    *   Sends Slack notification if configured.

## Further Implementation Steps

The following steps are identified to enhance the tool's capabilities and reliability:

1.  **Expanded Configuration:** Move hardcoded values like `TEST_DOMAINS`, `TEST_COUNT`, and `TIMEOUT` into the `config.yml` file.
2.  **Improved Protocol Detection:** Enhance the `-r` (refresh) functionality to more accurately detect supported protocols and handle transient network issues.
3.  **Unit and Integration Testing:** Implement a test suite using `pytest` to ensure core functionality remains robust.

## Ongoing Improvement & Maintenance

*   **Provider List Maintenance:** Regularly update `config.yml` with new or updated DNS endpoints from popular providers.
*   **Performance Optimization:** Explore asynchronous I/O (`asyncio`) as an alternative to threading.
*   **CI/CD Integration:** Set up a simple CI pipeline.
*   **Documentation:** Keep the README up-to-date.
