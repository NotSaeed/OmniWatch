"""
OmniWatch Modbus Telemetry Simulator
Generates realistic Zeek-like JSON logs for Modbus TCP traffic.
"""

import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
OUT_FILE = DATA_DIR / "modbus_telemetry.json"

INTERNAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
PLC_IP = "192.168.1.100"

def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()

def generate_benign(count: int = 50) -> list[dict]:
    """Generate normal Read Holding Registers (FC 03)."""
    logs = []
    for _ in range(count):
        logs.append({
            "timestamp": _now(),
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": PLC_IP,
            "transaction_id": random.randint(1, 65000),
            "protocol_id": 0,
            "length": 6,
            "unit_id": 1,
            "function_code": 3, # Read Holding Registers
            "data_hex": "006B0003"
        })
    return logs

def generate_attack(count: int = 5) -> list[dict]:
    """Generate malicious Write Single Coil (FC 05)."""
    logs = []
    for _ in range(count):
        logs.append({
            "timestamp": _now(),
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": PLC_IP,
            "transaction_id": random.randint(1, 65000),
            "protocol_id": 0,
            "length": 6,
            "unit_id": 1,
            "function_code": 5, # Write Single Coil (CRITICAL THREAT)
            "data_hex": "00ACFF00"
        })
    return logs

def generate_buffer_anomaly(count: int = 2) -> list[dict]:
    """Generate mismatching length fields."""
    logs = []
    for _ in range(count):
        logs.append({
            "timestamp": _now(),
            "src_ip": random.choice(INTERNAL_IPS),
            "dst_ip": PLC_IP,
            "transaction_id": random.randint(1, 65000),
            "protocol_id": 0,
            "length": 250, # Simulated large length to trigger the validation invariant
            "unit_id": 1,
            "function_code": 3,
            "data_hex": "0001" # Actual short length (Buffer Anomaly)
        })
    return logs

if __name__ == "__main__":
    entries = generate_benign(50) + generate_attack(5) + generate_buffer_anomaly(2)
    random.shuffle(entries)
    
    with open(OUT_FILE, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
            
    print(f"Generated {len(entries)} Modbus telemetry events to {OUT_FILE}")
