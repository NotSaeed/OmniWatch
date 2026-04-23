#!/usr/bin/env python3
"""
Sprint 4 — Generate Sample Modbus PCAP

Creates a deterministic PCAP file containing a mix of benign and malicious
Modbus TCP transactions.  Used for the Deterministic Replay Fallback mode
so exhibitions can run without live hardware.

Output: sample_modbus.pcap (10 Modbus TCP transactions)
  - 5 benign  FC 03  (Read Holding Registers)
  - 3 malicious FC 05 (Write Single Coil — unauthorized)
  - 2 malicious FC 16 (Write Multiple Registers — unauthorized)

Requires: dpkt (pip install dpkt)
"""

import struct
import time
import os

# We use raw pcap writing to avoid heavy dependencies
# PCAP file format: global header + packets

PCAP_MAGIC  = 0xa1b2c3d4
PCAP_MAJOR  = 2
PCAP_MINOR  = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE = 1  # LINKTYPE_ETHERNET


def pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII",
        PCAP_MAGIC, PCAP_MAJOR, PCAP_MINOR,
        0,  # timezone offset
        0,  # timestamp accuracy
        PCAP_SNAPLEN,
        PCAP_LINKTYPE,
    )


def pcap_packet(ts: float, data: bytes) -> bytes:
    """Wrap an Ethernet frame as a pcap packet record."""
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    caplen = len(data)
    return struct.pack("<IIII", ts_sec, ts_usec, caplen, caplen) + data


def eth_ipv4_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 payload: bytes, seq: int = 1) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP frame carrying the given payload."""
    # Ethernet header (14 bytes)
    eth = (
        b"\x00\x11\x22\x33\x44\x55"   # dst MAC
        b"\xaa\xbb\xcc\xdd\xee\xff"   # src MAC
        b"\x08\x00"                     # EtherType: IPv4
    )

    # IPv4 header (20 bytes, no options)
    def ip_bytes(ip: str) -> bytes:
        return bytes(int(o) for o in ip.split("."))

    tcp_len = 20 + len(payload)  # TCP header + payload
    ip_total = 20 + tcp_len
    ip_header = struct.pack(">BBHHHBBH4s4s",
        0x45,           # Version + IHL
        0x00,           # DSCP/ECN
        ip_total,       # Total length
        seq & 0xFFFF,   # Identification
        0x4000,         # Flags (Don't Fragment) + Fragment Offset
        64,             # TTL
        6,              # Protocol: TCP
        0,              # Checksum (0 = let OS calculate)
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )

    # TCP header (20 bytes, no options)
    tcp_header = struct.pack(">HHIIBBHHH",
        src_port,
        dst_port,
        seq * 1000,     # Sequence number
        0,              # Ack number
        0x50,           # Data offset (5 words = 20 bytes)
        0x18,           # Flags: PSH + ACK
        65535,          # Window size
        0,              # Checksum (0 = placeholder)
        0,              # Urgent pointer
    )

    return eth + ip_header + tcp_header + payload


def modbus_read_holding_registers(unit_id: int, start_addr: int, count: int,
                                   transaction_id: int = 1) -> bytes:
    """Modbus TCP request: FC 03 — Read Holding Registers."""
    # MBAP Header (7 bytes) + PDU
    pdu = struct.pack(">BHH", 3, start_addr, count)  # FC 03
    mbap = struct.pack(">HHHB",
        transaction_id,  # Transaction ID
        0,               # Protocol ID (Modbus)
        1 + len(pdu),    # Length (unit_id + PDU)
        unit_id,
    )
    return mbap + pdu


def modbus_write_single_coil(unit_id: int, coil_addr: int, value: bool,
                              transaction_id: int = 1) -> bytes:
    """Modbus TCP request: FC 05 — Write Single Coil (UNAUTHORIZED)."""
    coil_value = 0xFF00 if value else 0x0000
    pdu = struct.pack(">BHH", 5, coil_addr, coil_value)  # FC 05
    mbap = struct.pack(">HHHB",
        transaction_id, 0, 1 + len(pdu), unit_id,
    )
    return mbap + pdu


def modbus_write_multiple_registers(unit_id: int, start_addr: int,
                                     values: list[int],
                                     transaction_id: int = 1) -> bytes:
    """Modbus TCP request: FC 16 — Write Multiple Registers (UNAUTHORIZED)."""
    count = len(values)
    byte_count = count * 2
    pdu = struct.pack(">BHHB", 16, start_addr, count, byte_count)
    for v in values:
        pdu += struct.pack(">H", v)
    mbap = struct.pack(">HHHB",
        transaction_id, 0, 1 + len(pdu), unit_id,
    )
    return mbap + pdu


def main():
    out_path = os.path.join(os.path.dirname(__file__), "sample_modbus.pcap")

    # Deterministic base timestamp
    base_ts = 1714000000.0  # 2024-04-25T00:00:00Z (fixed for reproducibility)

    packets = []
    txn_id = 1

    # ── 5 Benign: FC 03 Read Holding Registers ────────────────────────────
    for i in range(5):
        payload = modbus_read_holding_registers(
            unit_id=1, start_addr=100 + i * 10, count=5,
            transaction_id=txn_id,
        )
        frame = eth_ipv4_tcp(
            src_ip="192.168.1.50", dst_ip="192.168.1.100",
            src_port=49152 + i, dst_port=502,
            payload=payload, seq=txn_id,
        )
        packets.append(pcap_packet(base_ts + i * 2.0, frame))
        txn_id += 1

    # ── 3 Malicious: FC 05 Write Single Coil ──────────────────────────────
    for i in range(3):
        payload = modbus_write_single_coil(
            unit_id=1, coil_addr=i, value=True,
            transaction_id=txn_id,
        )
        frame = eth_ipv4_tcp(
            src_ip="10.0.0.66", dst_ip="192.168.1.100",    # attacker IP
            src_port=55000 + i, dst_port=502,
            payload=payload, seq=txn_id,
        )
        packets.append(pcap_packet(base_ts + 10.0 + i * 0.5, frame))
        txn_id += 1

    # ── 2 Malicious: FC 16 Write Multiple Registers ───────────────────────
    for i in range(2):
        payload = modbus_write_multiple_registers(
            unit_id=1, start_addr=200 + i * 10,
            values=[0xDEAD, 0xBEEF, 0x1337],
            transaction_id=txn_id,
        )
        frame = eth_ipv4_tcp(
            src_ip="10.0.0.66", dst_ip="192.168.1.100",
            src_port=56000 + i, dst_port=502,
            payload=payload, seq=txn_id,
        )
        packets.append(pcap_packet(base_ts + 12.0 + i * 1.0, frame))
        txn_id += 1

    # ── Write the PCAP file ───────────────────────────────────────────────
    with open(out_path, "wb") as f:
        f.write(pcap_global_header())
        for pkt in packets:
            f.write(pkt)

    print(f"[+] Generated {out_path}")
    print(f"    {len(packets)} packets ({5} benign FC03, {3} malicious FC05, {2} malicious FC16)")
    print(f"    Size: {os.path.getsize(out_path)} bytes")


if __name__ == "__main__":
    main()
