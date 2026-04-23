import sqlite3
import os
from pathlib import Path

# Try to find the db path as the app does
backend_dir = Path("backend")
db_path = backend_dir / "omniwatch.db"

if not db_path.exists():
    db_path = Path("omniwatch.db")

print(f"Checking database at: {db_path.absolute()}")

if not db_path.exists():
    print("Database file not found!")
else:
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    
    tables = [
        "cicids_events",
        "cicids_playbook_logs",
        "alerts",
        "scan_runs",
        "playbook_log",
        "raw_events",
        "firewall_status",
        "spent_receipts"
    ]
    
    print(f"{'Table':<25} | {'Row Count':<10}")
    print("-" * 40)
    for table in tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = cur.fetchone()[0]
            print(f"{table:<25} | {count:<10}")
        except sqlite3.OperationalError:
            print(f"{table:<25} | (Table missing)")
            
    conn.close()
