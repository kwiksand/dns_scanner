#!/usr/bin/env python3
import subprocess
import re
import threading
from queue import Queue

# A list of public DNS servers to test
# (Provider, IP Address)
DNS_SERVERS = [
    ("Cloudflare", "1.1.1.1"),
    ("Cloudflare", "1.0.0.1"),
    ("Google", "8.8.8.8"),
    ("Google", "8.8.4.4"),
    ("Quad9", "9.9.9.9"),
    ("Quad9", "149.112.112.112"),
    ("OpenDNS", "208.67.222.222"),
    ("OpenDNS", "208.67.220.220"),
    ("Comodo Secure", "8.26.56.26"),
    ("Comodo Secure", "8.20.247.20"),
    ("CleanBrowsing", "185.228.168.9"),
    ("CleanBrowsing", "185.228.169.9"),
    ("Control D", "76.76.2.0"),
    ("Control D", "76.76.10.0"),
    # Australian Servers
    ("DNS Australia (SYD)", "43.229.60.176"),
    ("DNS Australia (SYD)", "43.229.62.192"),
    ("DNS Australia (MEL)", "45.124.52.17"),
    ("DNS Australia (MEL)", "45.124.53.159"),
    ("DNS Australia (BNE)", "103.16.128.53"),
    ("DNS Australia (BNE)", "103.230.156.88"),
    ("Cloudflare (BNE)", "1.0.0.19"),
    ("Cloudflare (MEL)", "1.0.0.2"),
    ("Telstra (SYD)", "139.134.5.51"),
    ("Telstra (MEL)", "203.50.2.71"),
    # Perth Servers
    ("Getflix (PER)", "45.248.78.99"),
    ("Node1 (PER)", "103.117.63.67"),
    ("Telstra (PER)", "1.159.239.33"),
    ("AussieBB (PER)", "180.150.123.16"),
    ("AussieBB (PER)", "180.150.92.196"),
    ("Dodo (PER)", "116.240.114.185"),
    # Other Global Providers
    ("AdGuard DNS", "94.140.14.14"),
    ("AdGuard DNS", "94.140.15.15"),
    ("Verisign", "64.6.64.6"),
    ("Verisign", "64.6.65.6"),
    ("Level3/Lumen", "209.244.0.3"),
    ("Level3/Lumen", "209.244.0.4"),
    ("Yandex", "77.88.8.8"),
    ("Yandex", "77.88.8.1"),
    ("Neustar", "156.154.70.1"),
    ("Neustar", "156.154.71.1"),
    ("OpenNIC", "134.195.4.2"),
]

# Domain to use for testing
TEST_DOMAIN = "google.com"
# dig command timeout in seconds
TIMEOUT = 2

def test_dns_server(server_ip, result_queue):
    """
    Tests a single DNS server and puts the result in a queue.
    Result is a tuple (server_ip, latency_ms) or (server_ip, None) on failure.
    """
    try:
        # Command to test DNS query time. +tries=1 and +time ensure it doesn't hang.
        cmd = ["dig", f"@{server_ip}", TEST_DOMAIN, "A", f"+time={TIMEOUT}", "+tries=1"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT + 1
        )

        if result.returncode == 0:
            # Use regex to find the query time in the output
            match = re.search(r"Query time: (\d+)", result.stdout)
            if match:
                latency = int(match.group(1))
                result_queue.put((server_ip, latency))
                return

    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Handle cases where dig isn't installed or the server times out
        pass
    except Exception:
        # Catch any other unexpected errors
        pass

    # If any error occurs or latency isn't found, report failure
    result_queue.put((server_ip, None))

def main():
    """
    Main function to orchestrate the DNS latency test.
    """
    print(f"Testing DNS server latency from your location...")
    print("-" * 50)

    results_queue = Queue()
    threads = []

    # Create and start a thread for each DNS server test
    for _, server_ip in DNS_SERVERS:
        thread = threading.Thread(target=test_dns_server, args=(server_ip, results_queue))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Collect results from the queue
    results = {}
    while not results_queue.empty():
        server_ip, latency = results_queue.get()
        results[server_ip] = latency

    # Sort servers by latency (fastest first)
    # We filter out None values and sort the rest
    sorted_results = sorted(
        [(ip, lat) for ip, lat in results.items() if lat is not None],
        key=lambda item: item[1]
    )

    # Print the results in a formatted table
    print(f"{'Provider':<15} {'IP Address':<18} {'Latency (ms)':<12}")
    print(f"{'-'*15} {'-'*18} {'-'*12}")

    for server_ip, latency in sorted_results:
        # Find the provider name for the current IP
        provider_name = "Unknown"
        for name, ip in DNS_SERVERS:
            if ip == server_ip:
                provider_name = name
                break
        print(f"{provider_name:<15} {server_ip:<18} {latency:<12}")

    # Print servers that failed
    failed_servers = [ip for ip, lat in results.items() if lat is None]
    if failed_servers:
        print("\n--- Failed or Timed Out ---")
        for server_ip in failed_servers:
            provider_name = "Unknown"
            for name, ip in DNS_SERVERS:
                if ip == server_ip:
                    provider_name = name
                    break
            print(f"{provider_name:<15} {server_ip:<18}")

if __name__ == "__main__":
    main()
