#!/usr/bin/env python3
import threading
from queue import Queue
import argparse
import json
import os
import statistics
import sys
import yaml
import time
from datetime import datetime, timedelta
import dns.message
import dns.query
import dns.inet
import dns.resolver
import httpx


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


def get_servers_from_config(config, include_disabled=False, test_all=False):
    """Returns a flat list of servers from the config, checking expiry if disabled."""
    servers = []
    now = datetime.now()
    providers = config.get("servers", {}).get("providers", {})
    for provider_name, endpoints in providers.items():
        for endpoint in endpoints:
            enabled = endpoint.get("enabled", False)
            expiry_str = endpoint.get("expiry")
            
            should_test = enabled or include_disabled or test_all
            
            if not should_test and expiry_str:
                try:
                    expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
                    if now >= expiry:
                        should_test = True
                except ValueError:
                    pass # Ignore invalid expiry formats
            
            if should_test:
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
    q = dns.message.make_query(domain, "A")
    query_map = {
        "DNS": dns.query.udp,
        "IPv6": dns.query.udp,
        "DoT": dns.query.tls,
        "DoH": dns.query.https,
        "DoQ": dns.query.quic,
    }

    query_func = query_map.get(protocol)
    if not query_func:
        return None

    # Handle DoQ hostname resolution if needed
    target_where = endpoint
    server_hostname = None
    if protocol == "DoQ":
        # If it's a URL-like string or just a hostname, we need the IP for 'where'
        # but the hostname for 'server_hostname'
        if endpoint.startswith("quic://"):
            endpoint = endpoint[7:]
        
        # Check if it's already an IP
        try:
            dns.inet.af_for_address(endpoint)
        except ValueError:
            # It's a hostname, resolve it
            try:
                # We use the system resolver or a default one to find the IP of the DoQ server
                answers = dns.resolver.resolve(endpoint, 'A')
                target_where = str(answers[0])
                server_hostname = endpoint
            except Exception:
                return None
        
    kwargs = {"where": target_where, "timeout": TIMEOUT}
    if protocol == "DoQ" and server_hostname:
        kwargs["server_hostname"] = server_hostname

    try:
        start_time = time.monotonic()
        query_func(q, **kwargs)
        latency = (time.monotonic() - start_time) * 1000
        return int(latency)
    except dns.exception.Timeout:
        return None
    except OSError:
        return None
    except Exception:
        return None


def refresh_server_list(config):
    """Refreshes the enabled status of all servers in the config."""
    print("Refreshing server list... This may take a moment.")
    all_servers = get_servers_from_config(config, include_disabled=True, test_all=True)
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

        start_t = time.monotonic()
        latency = get_latency(server_info, domain)
        if latency is not None:
            latencies.append(latency)
        else:
            duration = time.monotonic() - start_t
            if verbose:
                with print_lock:
                    print(f"FAILED {server_info['provider']} ({server_info['protocol']}) - Run {i + 1}/{TEST_COUNT} after {duration:.2f}s")

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


def send_slack_notification(results, failed_servers, webhook_url):
    """Sends the test results to Slack."""
    if not webhook_url:
        return

    # 1. Recommendation Logic
    recommendation = "No successful tests."
    if results:
        # Filter for encrypted protocols if available
        encrypted_results = [r for r in results if r["info"]["protocol"] in ["DoT", "DoH", "DoQ"]]
        best_result = None
        
        if encrypted_results:
             # Sort by avg latency
            encrypted_results.sort(key=lambda item: item["stats"]["avg"])
            best_result = encrypted_results[0]
            recommendation = (
                f"Based on latency and security, the recommended upstream DNS for Pi-hole/Technitium is "
                f"*{best_result['info']['provider']}* using *{best_result['info']['protocol']}* "
                f"(Endpoint: `{best_result['info']['endpoint']}`, Avg Latency: {best_result['stats']['avg']}ms)."
            )
        else:
             # Fallback to any protocol
            results.sort(key=lambda item: item["stats"]["avg"])
            best_result = results[0]
            recommendation = (
                f"No encrypted protocols available. The fastest provider is "
                f"*{best_result['info']['provider']}* using *{best_result['info']['protocol']}* "
                f"(Endpoint: `{best_result['info']['endpoint']}`, Avg Latency: {best_result['stats']['avg']}ms)."
            )

    # 2. Format Output for Slack
    message_blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "DNS Latency Test Results",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Running {TEST_COUNT} tests per server.\n\n:trophy: *Recommendation:*\n{recommendation}"
            }
        },
        {
             "type": "divider"
        }
    ]

    # Top 5 per protocol
    all_protos = sorted(list(set(res["info"]["protocol"] for res in results)))
    for proto in all_protos:
        proto_results = [res for res in results if res["info"]["protocol"] == proto][:5]
        if proto_results:
            header = f"{'Provider':<15} | {'Min':>4} | {'Avg':>4} | {'Max':>4} | {'Endpoint'}"
            sep = f"{'-'*15}-|-{'-'*4}-|-{'-'*4}-|-{'-'*4}-|---"
            table_lines = [header, sep]
            for res in proto_results:
                 info = res["info"]
                 stats = res["stats"]
                 provider = (info['provider'][:13] + '..') if len(info['provider']) > 15 else info['provider']
                 table_lines.append(f"{provider:<15} | {stats['min']:>4} | {stats['avg']:>4} | {stats['max']:>4} | {info['endpoint']}")
            
            table_str = "\n".join(table_lines)
            message_blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Top 5 {proto} Results:*\n```{table_str}```"
                }
            })

    # Summary of all successful
    top_10_all = results[:10]
    header_all = f"{'Provider':<12} | {'Proto':<5} | {'Min':>3} | {'Avg':>3} | {'Max':>3} | {'Endpoint'}"
    sep_all = f"{'-'*12}-|-{'-'*5}-|-{'-'*3}-|-{'-'*3}-|-{'-'*3}-|---"
    table_lines_all = [header_all, sep_all]
    for res in top_10_all:
         info = res["info"]
         stats = res["stats"]
         provider = (info['provider'][:10] + '..') if len(info['provider']) > 12 else info['provider']
         table_lines_all.append(f"{provider:<12} | {info['protocol']:<5} | {stats['min']:>3} | {stats['avg']:>3} | {stats['max']:>3} | {info['endpoint']}")
    
    if len(results) > 10:
         table_lines_all.append(f"... and {len(results) - 10} more.")

    table_str_all = "\n".join(table_lines_all)
    message_blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Top 10 Overall:*\n```{table_str_all}```"
        }
    })
    
    payload = {"blocks": message_blocks}

    try:
        response = httpx.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print("Slack notification sent successfully.")
    except Exception as e:
        print(f"Failed to send Slack notification: {e}", file=sys.stderr)


def print_table(results, failed_servers):
    """Prints the results in a formatted table."""
    # Sorting by avg, then min, then max
    results.sort(key=lambda item: (item["stats"]["avg"], item["stats"]["min"], item["stats"]["max"]))

    # Print Top 5 for each protocol
    all_protos = sorted(list(set(res["info"]["protocol"] for res in results)))
    for proto in all_protos:
        proto_results = [res for res in results if res["info"]["protocol"] == proto][:5]
        if proto_results:
            print(f"\n--- Top 5 {proto} results ---")
            print(
                f"{('Provider'):<25} {('Min (ms)'):<10} {('Avg (ms)'):<10} {('Max (ms)'):<10} {('Endpoint'):<45}"
            )
            print(f"{'-' * 25} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 45}")
            for res in proto_results:
                info = res["info"]
                stats = res["stats"]
                print(
                    f"{info['provider']:<25} {stats['min']:<10} {stats['avg']:<10} {stats['max']:<10} {info['endpoint']:<45}"
                )

    print(f"\n--- All Successful Tests (sorted by avg, min, max latency) ---")
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
    parser.add_argument(
        "-a",
        "--test-all",
        action="store_true",
        help="Override disabled tests and re-test everything.",
    )
    parser.add_argument(
        "-s",
        "--slack-webhook",
        help="Slack Webhook URL for sending results (overrides config).",
    )
    args = parser.parse_args()

    config = load_config()
    
    # Check env, then config, then arg
    slack_webhook = args.slack_webhook or os.environ.get("SLACK_WEBHOOK_URL") or config.get("notifications", {}).get("slack", {}).get("webhook_url")
    
    if args.refresh_server_list:
        refresh_server_list(config)
        sys.exit(0)

    dns_providers_to_test = get_servers_from_config(config, test_all=args.test_all)

    if not dns_providers_to_test:
        print(
            "No enabled servers found in the config file. Run with -r to refresh or -a to test all.",
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

    successful_results = [res for res in all_results if res["stats"] is not None]
    failed_servers = [res["info"] for res in all_results if res["stats"] is None]

    # Update config based on results
    now = datetime.now()
    expiry_time = now + timedelta(hours=48)
    expiry_str = expiry_time.strftime("%Y-%m-%d %H:%M:%S")
    
    config_changed = False
    providers = config.get("servers", {}).get("providers", {})
    
    # Track tested ones to update their status
    tested_keys = set((s["provider"], s["endpoint"]) for s in dns_providers_to_test)
    successful_keys = set((res["info"]["provider"], res["info"]["endpoint"]) for res in successful_results)

    for provider_name, endpoints in providers.items():
        for endpoint in endpoints:
            key = (provider_name, endpoint["endpoint"])
            if key in successful_keys:
                if not endpoint.get("enabled", False) or "expiry" in endpoint:
                    endpoint["enabled"] = True
                    endpoint.pop("expiry", None)
                    config_changed = True
            elif key in tested_keys:
                # It was tested but not in successful results -> failed
                if endpoint.get("enabled", True) or "expiry" not in endpoint:
                    endpoint["enabled"] = False
                    endpoint["expiry"] = expiry_str
                    config_changed = True

    if config_changed:
        save_config(config)

    if args.format == "json":
        # Note: successful_results already filtered above
        # Need to sort it for JSON output too if desired, though JSON is less about presentation
        successful_results.sort(key=lambda item: (item["stats"]["avg"], item["stats"]["min"], item["stats"]["max"]))
        print_json_output(successful_results, failed_servers)
    else:
        print_table(successful_results, failed_servers)
    
    if slack_webhook:
        send_slack_notification(successful_results, failed_servers, slack_webhook)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user.", file=sys.stderr)
        sys.exit(1)

