import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "dns_scanner.db")

def get_db_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database with the required tables."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS server_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT,
                protocol TEXT,
                endpoint TEXT,
                total_runs INTEGER DEFAULT 0,
                total_queries INTEGER DEFAULT 0,
                failed_queries INTEGER DEFAULT 0,
                min_latency FLOAT,
                max_latency FLOAT,
                avg_latency FLOAT,
                UNIQUE(provider, protocol, endpoint)
            )
        """)
        conn.commit()

def update_server_stats(provider, protocol, endpoint, latencies, total_attempted):
    """
    Updates the statistics for a server.
    latencies: list of successful latency measurements.
    total_attempted: total number of individual DNS queries attempted.
    """
    successful_count = len(latencies)
    failed_count = total_attempted - successful_count
    
    with get_db_connection() as conn:
        # Get existing stats
        row = conn.execute(
            "SELECT * FROM server_stats WHERE provider = ? AND protocol = ? AND endpoint = ?",
            (provider, protocol, endpoint)
        ).fetchone()
        
        if row:
            new_total_runs = row["total_runs"] + 1
            new_total_queries = row["total_queries"] + total_attempted
            new_failed_queries = row["failed_queries"] + failed_count
            
            # Successful queries so far
            old_successful_total = row["total_queries"] - row["failed_queries"]
            new_successful_total = old_successful_total + successful_count
            
            # Latency stats
            if successful_count > 0:
                current_min = min(latencies)
                current_max = max(latencies)
                current_sum = sum(latencies)
                
                new_min = min(row["min_latency"], current_min) if row["min_latency"] is not None else current_min
                new_max = max(row["max_latency"], current_max) if row["max_latency"] is not None else current_max
                
                # New moving (cumulative) average
                old_avg = row["avg_latency"] or 0
                new_avg = ((old_avg * old_successful_total) + current_sum) / new_successful_total
            else:
                new_min = row["min_latency"]
                new_max = row["max_latency"]
                new_avg = row["avg_latency"]
                
            conn.execute("""
                UPDATE server_stats
                SET total_runs = ?, total_queries = ?, failed_queries = ?, 
                    min_latency = ?, max_latency = ?, avg_latency = ?
                WHERE id = ?
            """, (new_total_runs, new_total_queries, new_failed_queries, 
                  new_min, new_max, new_avg, row["id"]))
        else:
            # First time for this server
            if successful_count > 0:
                new_min = min(latencies)
                new_max = max(latencies)
                new_avg = sum(latencies) / successful_count
            else:
                new_min = None
                new_max = None
                new_avg = None
                
            conn.execute("""
                INSERT INTO server_stats 
                (provider, protocol, endpoint, total_runs, total_queries, failed_queries, min_latency, max_latency, avg_latency)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
            """, (provider, protocol, endpoint, total_attempted, failed_count, new_min, new_max, new_avg))
        
        conn.commit()

def get_all_stats():
    """Returns all server statistics."""
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM server_stats ORDER BY avg_latency ASC").fetchall()
