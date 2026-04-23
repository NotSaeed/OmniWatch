import sqlite3
import os
from pathlib import Path

# Try to find the db path
db_path = Path("backend/omniwatch.db")
if not db_path.exists():
    db_path = Path("omniwatch.db")

print(f"Checking database at: {db_path.absolute()}")

if not db_path.exists():
    print("Database file not found!")
else:
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    
    # Check raw_events (BOTSv3)
    try:
        cur.execute("SELECT COUNT(*) FROM raw_events")
        bots_count = cur.fetchone()[0]
        print(f"raw_events (BOTSv3): {bots_count} rows")
        
        if bots_count > 0:
            cur.execute("SELECT sourcetype, count(*) FROM raw_events GROUP BY sourcetype")
            print("Sourcetypes:")
            for row in cur.fetchall():
                print(f"  - {row[0]}: {row[1]}")
    except sqlite3.OperationalError:
        print("raw_events table missing!")

    # Check cicids_events
    try:
        cur.execute("SELECT COUNT(*) FROM cicids_events")
        cicids_count = cur.fetchone()[0]
        print(f"cicids_events: {cicids_count} rows")
    except sqlite3.OperationalError:
        print("cicids_events table missing!")
            
    conn.close()
