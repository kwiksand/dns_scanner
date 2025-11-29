#!/usr/bin/env python3
import subprocess
import re
import threading
from queue import Queue
import argparse
import json
import statistics
import sys
import yaml

# Domains to use for testing
TEST_DOMAINS = ["google.com", "facebook.com", "amazon.com", "apple.com"]
# Number of tests per service
TEST_COUNT = 20
# dig command timeout in seconds
TIMEOUT = 5
# A lock for thread-safe printing
print_lock = threading.Lock()

CONFIG_FILE = "config.yml"


def load_config():
    """Loads servers from the YAML config file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: '{CONFIG_FILE}' not found. Please create it.", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file '{CONFIG_FILE}': {e}", file=sys.stderr)
        sys.exit(1)


def save_config(config):
    """Saves the configuration to the YAML file."""
    try:
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(config, f, sort_keys=False)
    except IOError as e:
        print(f"Error saving config file '{CONFIG_FILE}': {e}", file=sys.stderr)
        sys.exit(1)


def get_servers_from_config(config, include_disabled=False):
    """Returns a flat list of servers from the config."""
    servers = []
    providers = config.get("servers", {}).get("providers", {})
    for provider_name, endpoints in providers.items():
        for endpoint in endpoints:
            if include_disabled or endpoint.get("enabled", False):
                server_info = {
                    "provider": provider_name,
                    "protocol": endpoint["protocol"],
                    "endpoint": endpoint["endpoint"],
                }
                servers.append(server_info)
    return servers


def get_latency(server_info, domain):
    """
    Performs a single DNS query and returns the latency in ms.
    Returns None on failure.
    """
    protocol = server_info["protocol"]
    endpoint = server_info["endpoint"]
    cmd = ["dig", domain, "A", f"+time={TIMEOUT}", "+tries=1", "+stats"]

    if protocol in ["DNS", "IPv6"]:
        cmd.insert(1, f"@{endpoint}")
    elif protocol == "DoH":
        cmd.insert(1, f"@{endpoint}")
    elif protocol == "DoT":
        cmd.insert(1, f"@{endpoint}")
        cmd.append("+tls")
    elif protocol == "DoQ":
        cmd.insert(1, f"@{endpoint}")
        cmd.append("+quic")
    else:
        return None

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TIMEOUT + 1
        )

        if result.returncode == 0:
            match = re.search(r"Query time: (\d+)", result.stdout)
            if match:
                return int(match.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    except Exception:
        pass
    return None


def refresh_server_list(config):
    """Refreshes the enabled status of all servers in the config."""
    print("Refreshing server list... This may take a moment.")
    all_servers = get_servers_from_config(config, include_disabled=True)
    total_servers = len(all_servers)

    for i, server in enumerate(all_servers):
        print(
            f"Checking {server['provider']} ({server['endpoint']}) [{i + 1}/{total_servers}]..."
        )
        # Try twice before disabling
        latency1 = get_latency(server, TEST_DOMAINS[0])
        latency2 = get_latency(server, TEST_DOMAINS[1])

        server_enabled = latency1 is not None or latency2 is not None

        # Find the server in the original config to update it
        for provider_name, endpoints in config["servers"]["providers"].items():
            if provider_name == server["provider"]:
                for endpoint in endpoints:
                    if endpoint["endpoint"] == server["endpoint"]:
                        endpoint["enabled"] = server_enabled
                        break

    save_config(config)
    print("Server list refresh complete. Config file updated.")


def run_tests_for_service(server_info, verbose, result_queue):
    """
    Runs a series of tests for a single DNS service and puts the stats in a queue.
    """
    latencies = []
    for i in range(TEST_COUNT):
        domain = TEST_DOMAINS[(i // 5) % len(TEST_DOMAINS)]
        if verbose:
            with print_lock:
                print(
                    f"Testing {server_info['provider']} ({server_info['protocol']}) - Run {i + 1}/{TEST_COUNT} on {domain}..."
                )

        latency = get_latency(server_info, domain)
        if latency is not None:
            latencies.append(latency)

    if latencies:
        stats = {
            "min": min(latencies),
            "avg": round(statistics.mean(latencies)),
            "max": max(latencies),
            "successful_tests": len(latencies),
        }
        result_queue.put({"info": server_info, "stats": stats})
    else:
        result_queue.put({"info": server_info, "stats": None, "successful_tests": 0})


def print_table(results, failed_servers):
    """Prints the results in a formatted table."""
    print(f"\n--- Successful Tests (sorted by average latency) ---")
    print(
        f"{('Provider'):<25} {('Protocol'):<10} {('Min (ms)'):<10} {('Avg (ms)'):<10} {('Max (ms)'):<10} {('Endpoint'):<45}"
    )
    print(f"{'-' * 25} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 45}")

    for res in results:
        info = res["info"]
        stats = res["stats"]
        print(
            f"{info['provider']:<25} {info['protocol']:<10} {stats['min']:<10} {stats['avg']:<10} {stats['max']:<10} {info['endpoint']:<45}"
        )

    if failed_servers:
        print(f"\n--- Failed or Timed Out (0 successful tests) ---")
        print(f"{('Provider'):<25} {('Protocol'):<10} {('Endpoint'):<45}")
        print(f"{'-' * 25} {'-' * 10} {'-' * 45}")
        for info in failed_servers:
            print(
                f"{info['provider']:<25} {info['protocol']:<10} {info['endpoint']:<45}"
            )


def print_json_output(results, failed_servers):
    """Prints the results as a JSON object."""
    output = {"results": results, "failed": failed_servers}
    print(json.dumps(output, indent=2))


def main():
    """Main function to orchestrate the DNS latency test."""
    parser = argparse.ArgumentParser(
        description="Test DNS server latency with detailed stats."
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="The output format for the results (default: table).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output to show test progress.",
    )
    parser.add_argument(
        "-r",
        "--refresh-server-list",
        action="store_true",
        help="Refresh the server list by checking all servers and updating their enabled status.",
    )
    args = parser.parse_args()

    config = load_config()

    if args.refresh_server_list:
        refresh_server_list(config)
        sys.exit(0)

    dns_providers_to_test = get_servers_from_config(config)

    if not dns_providers_to_test:
        print(
            "No enabled servers found in the config file. Run with -r to refresh the server list.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.verbose:
        print("Testing DNS server latency... This may take a while.")
        print(
            f"(Running {TEST_COUNT} tests for each of the {len(dns_providers_to_test)} services)"
        )

    results_queue = Queue()
    threads = []

    for server_info in dns_providers_to_test:
        thread = threading.Thread(
            target=run_tests_for_service,
            args=(server_info, args.verbose, results_queue),
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    all_results = []
    while not results_queue.empty():
        all_results.append(results_queue.get())

    successful_results = sorted(
        [res for res in all_results if res["stats"] is not None],
        key=lambda item: item["stats"]["avg"],
    )
    failed_servers = [res["info"] for res in all_results if res["stats"] is None]

    if args.format == "json":
        print_json_output(successful_results, failed_servers)
    else:
        print_table(successful_results, failed_servers)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user.", file=sys.stderr)
        sys.exit(1)

