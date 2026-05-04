#!/usr/bin/env python3
import sqlite3
import os
import sys

def main():
    db_path = os.path.join(os.path.dirname(__file__), 'omniwatch.db')
    if not os.path.exists(db_path):
        print(f"Error: Database not found at {db_path}")
        sys.exit(1)

    print("Connecting to database...")
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        
        # Ensure the column exists before updating
        try:
            conn.execute("ALTER TABLE telemetry_alerts ADD COLUMN zk_status TEXT DEFAULT 'pending'")
            print("Added zk_status column to telemetry_alerts.")
        except sqlite3.OperationalError:
            pass # Column already exists
            
        print("Clearing ZK backlog (marking all alerts as verified)...")
        # Instantly apply mock verification to all alerts
        cursor = conn.execute(
            "UPDATE telemetry_alerts "
            "SET zk_status = 'verified', chain_hash = 'MOCK_DEV_RECEIPT_12345' "
            "WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM') AND zk_status != 'verified'"
        )
        conn.commit()
        
        print(f"Success! Mock verification applied to {cursor.rowcount} alerts.")
        
    except Exception as e:
        print(f"Failed to update queue: {e}")
        sys.exit(1)
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    main()
