#!/usr/bin/env python3
"""
Sprint 4 — Edge Bincode Serializer

Runs on the Raspberry Pi 4 edge node.  Reads Zeek JSON log lines (from
icsnpp-modbus) on stdin and writes raw bincode NetworkTelemetry records
to stdout (or POSTs them directly to the OmniWatch backend).

Usage (piped from Zeek):
    tail -F /opt/zeek/logs/current/modbus.log | python3 serialize_bincode.py --post

Usage (stdout for debugging):
    echo '{"id.orig_h":"10.0.1.5",...}' | python3 serialize_bincode.py > out.bin
"""

import argparse
import json
import struct
import sys
import time

# Must match the Rust NetworkTelemetry struct EXACTLY (Sprint 4 layout)
_FMT = "<4s4sHBQQIBBBB18sQ"
RECORD_SIZE = struct.calcsize(_FMT)

# Epoch nonce — fixed for the lifetime of this process
_EPOCH_NONCE = int(time.time())


def ip_to_bytes(ip: str) -> bytes:
    """Convert dotted-decimal IPv4 to 4 big-endian bytes."""
    try:
        parts = ip.split(".")
        return bytes(int(p) for p in parts)
    except Exception:
        return b"\x00\x00\x00\x00"


def uid_to_bytes(uid: str) -> bytes:
    """Convert a Zeek conn_uid string to 18 zero-padded bytes."""
    return uid.encode("ascii")[:18].ljust(18, b"\x00")


def zeek_json_to_bincode(line: str) -> bytes | None:
    """
    Parse one Zeek ICSNPP Modbus JSON log line and encode it as bincode.

    Expected Zeek fields (icsnpp-modbus):
      id.orig_h, id.resp_h, id.resp_p, proto, duration,
      orig_bytes, resp_bytes, orig_pkts, resp_pkts,
      uid, modbus.func, modbus.unit_id
    """
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Skip header lines or empty objects
    if "id.orig_h" not in obj and "id_orig_h" not in obj:
        return None

    src_ip     = ip_to_bytes(obj.get("id.orig_h") or obj.get("id_orig_h", "0.0.0.0"))
    dst_ip     = ip_to_bytes(obj.get("id.resp_h") or obj.get("id_resp_h", "0.0.0.0"))
    dst_port   = int(obj.get("id.resp_p") or obj.get("id_resp_p", 502))
    proto_str  = str(obj.get("proto", "tcp")).lower()
    protocol   = 6 if proto_str == "tcp" else (17 if proto_str == "udp" else 0)

    # Duration in seconds → microseconds
    duration_s = float(obj.get("duration", 0) or 0)
    flow_dur   = int(duration_s * 1_000_000)

    # Approximate bytes/s from total bytes and duration
    orig_bytes = int(obj.get("orig_bytes", 0) or 0)
    resp_bytes = int(obj.get("resp_bytes", 0) or 0)
    total_bytes = orig_bytes + resp_bytes
    bps = total_bytes / max(duration_s, 0.001)
    flow_bytes_s_milli = int(bps * 1000)

    pkt_count  = int(obj.get("orig_pkts", 0) or 0) + int(obj.get("resp_pkts", 0) or 0)
    direction  = 0  #  Pi 4 is passive — always inbound from its perspective
    sourcetype = 4  #  4 = zeek

    modbus_fc  = int(obj.get("modbus.func") or obj.get("modbus_func", 0) or 0)
    modbus_uid = int(obj.get("modbus.unit_id") or obj.get("modbus_unit_id", 0) or 0)
    zeek_uid   = uid_to_bytes(obj.get("uid", ""))

    return struct.pack(
        _FMT,
        src_ip, dst_ip, dst_port, protocol,
        flow_dur, flow_bytes_s_milli, pkt_count,
        direction, sourcetype,
        modbus_fc, modbus_uid,
        zeek_uid, _EPOCH_NONCE,
    )


def main():
    parser = argparse.ArgumentParser(description="Zeek JSON → bincode serializer for OmniWatch edge")
    parser.add_argument("--post", action="store_true",
                        help="POST each record to the OmniWatch backend instead of writing to stdout")
    parser.add_argument("--url", default="https://omniwatch.local:8443/api/edge/ingest",
                        help="Backend URL for --post mode")
    args = parser.parse_args()

    session = None
    if args.post:
        import requests
        session = requests.Session()
        session.verify = False  # mkcert local cert — trusted on workstation, not on Pi
        sys.stderr.write(f"[edge] POSTing bincode to {args.url}\n")

    count = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        record = zeek_json_to_bincode(line)
        if record is None:
            continue

        if args.post and session:
            try:
                resp = session.post(
                    args.url,
                    data=record,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=5,
                )
                count += 1
                if resp.status_code == 200:
                    sys.stderr.write(f"[edge] #{count} → {resp.json().get('severity', '?')}\n")
                else:
                    sys.stderr.write(f"[edge] #{count} HTTP {resp.status_code}\n")
            except Exception as exc:
                sys.stderr.write(f"[edge] POST failed: {exc}\n")
        else:
            sys.stdout.buffer.write(record)
            sys.stdout.buffer.flush()
            count += 1

    sys.stderr.write(f"[edge] Done — {count} records serialized\n")


if __name__ == "__main__":
    main()
