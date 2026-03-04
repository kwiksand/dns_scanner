from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import yaml
import threading
from database import init_db, get_all_stats, update_server_stats
import dns_latency_tester
import time
from queue import Queue

app = Flask(__name__)
app.secret_key = "dns-scanner-secret"

# Ensure DB is initialized
init_db()

@app.route("/")
def index():
    stats = get_all_stats()
    # Convert sqlite3.Row to dict for easier template handling if needed, 
    # but Jinja2 handles sqlite3.Row fine.
    return render_template("index.html", stats=stats)

@app.route("/servers")
def servers():
    config = dns_latency_tester.load_config()
    providers = config.get("servers", {}).get("providers", {})
    return render_template("servers.html", providers=providers)

@app.route("/servers/toggle", methods=["POST"])
def toggle_server():
    provider_name = request.form.get("provider")
    endpoint_val = request.form.get("endpoint")
    enabled = request.form.get("enabled") == "true"
    
    config = dns_latency_tester.load_config()
    providers = config.get("servers", {}).get("providers", {})
    
    if provider_name in providers:
        for endpoint in providers[provider_name]:
            if endpoint["endpoint"] == endpoint_val:
                endpoint["enabled"] = enabled
                if enabled:
                    endpoint.pop("expiry", None)
                break
    
    dns_latency_tester.save_config(config)
    return redirect(url_for("servers"))

@app.route("/servers/add", methods=["POST"])
def add_server():
    provider_name = request.form.get("provider")
    protocol = request.form.get("protocol")
    endpoint_val = request.form.get("endpoint")
    enabled = request.form.get("enabled") == "on"
    
    if not provider_name or not protocol or not endpoint_val:
        flash("All fields are required.", "error")
        return redirect(url_for("servers"))
    
    config = dns_latency_tester.load_config()
    providers = config.get("servers", {}).get("providers", {})
    
    if provider_name not in providers:
        providers[provider_name] = []
        
    providers[provider_name].append({
        "protocol": protocol,
        "endpoint": endpoint_val,
        "enabled": enabled
    })
    
    dns_latency_tester.save_config(config)
    flash(f"Added {provider_name} ({protocol}) {endpoint_val}", "success")
    return redirect(url_for("servers"))

@app.route("/scan", methods=["POST"])
def run_scan():
    # Run scan in background thread
    def background_scan():
        config = dns_latency_tester.load_config()
        dns_providers_to_test = dns_latency_tester.get_servers_from_config(config)
        
        results_queue = Queue()
        threads = []
        for server_info in dns_providers_to_test:
            thread = threading.Thread(
                target=dns_latency_tester.run_tests_for_service,
                args=(server_info, False, results_queue),
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
            
        while not results_queue.empty():
            res = results_queue.get()
            info = res["info"]
            latencies = res.get("latencies", [])
            update_server_stats(
                info["provider"], 
                info["protocol"], 
                info["endpoint"], 
                latencies, 
                dns_latency_tester.TEST_COUNT
            )
            
    threading.Thread(target=background_scan).start()
    flash("Scan started in background.", "info")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
