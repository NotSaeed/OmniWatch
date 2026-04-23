#!/usr/bin/env python3
"""
Sprint 4 — Deterministic PCAP Replay Fallback

Reads a pre-recorded PCAP file containing Modbus TCP transactions, converts
each packet into the bincode NetworkTelemetry format, and POSTs them to the
OmniWatch backend.  This is the exhibition safety net — when the live Pi 4
edge node is unavailable, this script replays the exact same data locally.

Usage:
    python pcap_replay.py                              # replay sample_modbus.pcap at 1x
    python pcap_replay.py --pcap attack.pcap --speed 5 # custom file at 5x speed
    python pcap_replay.py --instant                    # no delay between packets
"""

import argparse
import os
import struct
import sys
import time

# Add parent dir to path so we can import serialize_bincode
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from serialize_bincode import _FMT, RECORD_SIZE, _EPOCH_NONCE, ip_to_bytes, uid_to_bytes

# PCAP constants
PCAP_GLOBAL_HDR_SIZE = 24
PCAP_PKT_HDR_SIZE    = 16


def read_pcap_packets(path: str):
    """
    Yield (timestamp_float, raw_packet_bytes) for every packet in a pcap file.
    Handles only standard pcap (not pcapng).
    """
    with open(path, "rb") as f:
        ghdr = f.read(PCAP_GLOBAL_HDR_SIZE)
        if len(ghdr) < PCAP_GLOBAL_HDR_SIZE:
            raise ValueError("File too short for pcap global header")

        magic = struct.unpack("<I", ghdr[:4])[0]
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            raise ValueError(f"Not a pcap file (magic: 0x{magic:08x})")

        while True:
            phdr = f.read(PCAP_PKT_HDR_SIZE)
            if len(phdr) < PCAP_PKT_HDR_SIZE:
                break

            ts_sec, ts_usec, caplen, _origlen = struct.unpack(f"{endian}IIII", phdr)
            ts = ts_sec + ts_usec / 1_000_000.0

            data = f.read(caplen)
            if len(data) < caplen:
                break

            yield ts, data


def extract_modbus_from_packet(raw: bytes) -> dict | None:
    """
    Extract Modbus TCP fields from a raw Ethernet/IPv4/TCP packet.
    Returns None if the packet is not Modbus TCP (dst_port != 502).
    """
    if len(raw) < 14 + 20 + 20 + 7:  # eth + ip + tcp + mbap minimum
        return None

    # Ethernet header
    eth_type = struct.unpack(">H", raw[12:14])[0]
    if eth_type != 0x0800:  # Not IPv4
        return None

    # IPv4 header
    ip_start = 14
    ihl = (raw[ip_start] & 0x0F) * 4
    protocol = raw[ip_start + 9]
    if protocol != 6:  # Not TCP
        return None

    src_ip = ".".join(str(b) for b in raw[ip_start + 12:ip_start + 16])
    dst_ip = ".".join(str(b) for b in raw[ip_start + 16:ip_start + 20])

    # TCP header
    tcp_start = ip_start + ihl
    src_port = struct.unpack(">H", raw[tcp_start:tcp_start + 2])[0]
    dst_port = struct.unpack(">H", raw[tcp_start + 2:tcp_start + 4])[0]
    tcp_doff = ((raw[tcp_start + 12] >> 4) & 0x0F) * 4

    # Only process Modbus TCP (port 502)
    if dst_port != 502 and src_port != 502:
        return None

    # Modbus TCP payload starts after TCP header
    payload_start = tcp_start + tcp_doff
    payload = raw[payload_start:]

    if len(payload) < 8:  # MBAP header (7) + at least 1 byte PDU
        return None

    # MBAP Header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
    _txn_id, _proto_id, _length, unit_id = struct.unpack(">HHHB", payload[:7])

    # PDU: Function Code is the first byte after MBAP
    func_code = payload[7] if len(payload) > 7 else 0

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": 6,
        "func_code": func_code,
        "unit_id": unit_id,
        "payload_size": len(payload),
    }


def modbus_to_bincode(info: dict, ts: float, pkt_index: int) -> bytes:
    """Convert extracted Modbus info into the bincode NetworkTelemetry format."""
    src_ip = ip_to_bytes(info["src_ip"])
    dst_ip = ip_to_bytes(info["dst_ip"])
    dst_port = info["dst_port"] if info["dst_port"] == 502 else info["src_port"]

    # Synthetic flow metrics for single-packet extraction
    flow_dur_us = 1_000_000        # 1 second default
    flow_bytes_milli = info["payload_size"] * 1000  # bytes/s × 1000
    pkt_count = 1
    direction = 0   # inbound (from attacker's perspective)
    sourcetype = 4  # zeek

    zeek_uid = uid_to_bytes(f"PCAP-{pkt_index:06d}")

    return struct.pack(
        _FMT,
        src_ip, dst_ip, dst_port, info["protocol"],
        flow_dur_us, flow_bytes_milli, pkt_count,
        direction, sourcetype,
        info["func_code"], info["unit_id"],
        zeek_uid, _EPOCH_NONCE,
    )


def main():
    parser = argparse.ArgumentParser(description="OmniWatch PCAP Replay Fallback")
    parser.add_argument("--pcap", default=os.path.join(os.path.dirname(__file__), "sample_modbus.pcap"),
                        help="Path to the PCAP file")
    parser.add_argument("--url", default="https://omniwatch.local:8443/api/edge/ingest",
                        help="Backend ingest URL")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="Replay speed multiplier (e.g., 10 = 10x faster)")
    parser.add_argument("--instant", action="store_true",
                        help="Replay all packets instantly (no delay)")
    parser.add_argument("--batch", action="store_true",
                        help="Send all records in one batch POST instead of individually")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and print but don't POST")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"[!] PCAP file not found: {args.pcap}")
        print("    Run generate_sample_pcap.py first to create it.")
        sys.exit(1)

    print(f"[replay] PCAP     : {args.pcap}")
    print(f"[replay] Backend  : {args.url}")
    print(f"[replay] Speed    : {'instant' if args.instant else f'{args.speed}x'}")

    # Read and extract Modbus packets
    records = []
    timestamps = []
    pkt_index = 0

    for ts, raw in read_pcap_packets(args.pcap):
        info = extract_modbus_from_packet(raw)
        if info is None:
            continue

        bincode = modbus_to_bincode(info, ts, pkt_index)
        records.append((ts, bincode, info))
        timestamps.append(ts)
        pkt_index += 1

    print(f"[replay] Extracted {len(records)} Modbus transactions from PCAP")

    if not records:
        print("[replay] No Modbus packets found in the PCAP")
        sys.exit(0)

    if args.dry_run:
        for i, (ts, _bincode, info) in enumerate(records):
            fc_type = "WRITE" if info["func_code"] in (5, 6, 15, 16) else "READ"
            print(f"  [{i+1}] {info['src_ip']} → {info['dst_ip']}:{info['dst_port']} "
                  f"FC={info['func_code']:02d} ({fc_type}) unit={info['unit_id']}")
        sys.exit(0)

    # Setup HTTP session
    import requests
    session = requests.Session()
    session.verify = False  # mkcert local cert

    if args.batch:
        # Batch mode — concatenate all records and POST once
        batch_payload = b"".join(bincode for _, bincode, _ in records)
        batch_url = args.url.replace("/ingest", "/ingest-batch")
        print(f"[replay] Sending batch of {len(records)} records ({len(batch_payload)} bytes)...")
        resp = session.post(batch_url, data=batch_payload,
                           headers={"Content-Type": "application/octet-stream"}, timeout=30)
        print(f"[replay] Response: {resp.status_code} — {resp.text[:200]}")
    else:
        # Sequential mode — respect packet timing
        prev_ts = timestamps[0] if timestamps else 0

        for i, (ts, bincode, info) in enumerate(records):
            # Respect inter-packet timing
            if not args.instant and i > 0:
                delay = (ts - prev_ts) / args.speed
                if delay > 0:
                    time.sleep(delay)
            prev_ts = ts

            fc_type = "WRITE" if info["func_code"] in (5, 6, 15, 16) else "READ"
            try:
                resp = session.post(
                    args.url, data=bincode,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=5,
                )
                severity = resp.json().get("severity", "?") if resp.status_code == 200 else f"HTTP {resp.status_code}"
                print(f"  [{i+1}/{len(records)}] {info['src_ip']} → {info['dst_ip']}:{info['dst_port']} "
                      f"FC={info['func_code']:02d} ({fc_type}) → {severity}")
            except Exception as exc:
                print(f"  [{i+1}/{len(records)}] POST failed: {exc}")

    print(f"[replay] Done — {len(records)} Modbus transactions replayed")


if __name__ == "__main__":
    main()
