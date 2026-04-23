"""
Sprint 4 — Bincode Receiver

Decodes / encodes the exact same binary layout as the Rust `NetworkTelemetry`
struct in `verifier/core/src/lib.rs`.  Uses Python's built-in `struct` module
so the Pi 4 edge node and the backend share a zero-dependency wire format.

Field order and sizes MUST match the Rust struct exactly (bincode serialises
struct fields in declaration order with little-endian encoding).

Layout (total = 60 bytes):
  src_ip             4 × u8     =  4
  dst_ip             4 × u8     =  4
  dst_port           u16  LE    =  2
  protocol           u8         =  1
  flow_duration_us   u64  LE    =  8
  flow_bytes_s_milli u64  LE    =  8
  packet_count       u32  LE    =  4
  direction          u8         =  1
  sourcetype         u8         =  1
  modbus_func_code   u8         =  1
  modbus_unit_id     u8         =  1
  zeek_uid           18 × u8    = 18
  epoch_nonce        u64  LE    =  8
                          total = 61 bytes
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import List

# bincode uses little-endian by default; struct format mirrors Rust field order.
# 4B src_ip + 4B dst_ip + H dst_port + B protocol + Q flow_dur + Q flow_bytes
# + I pkt_count + B direction + B sourcetype + B modbus_fc + B modbus_uid
# + 18s zeek_uid + Q epoch_nonce
_FMT = "<4s4sHBQQIBBBB18sQ"
RECORD_SIZE = struct.calcsize(_FMT)  # should be 61


@dataclass
class ModbusTelemetry:
    """Python mirror of Rust NetworkTelemetry — field order is wire-format."""
    src_ip: bytes             # 4 bytes, big-endian IPv4
    dst_ip: bytes             # 4 bytes, big-endian IPv4
    dst_port: int             # u16
    protocol: int             # u8 (6=TCP, 17=UDP)
    flow_duration_us: int     # u64
    flow_bytes_s_milli: int   # u64 (bytes/s × 1000)
    packet_count: int         # u32
    direction: int            # u8 (0=inbound, 1=outbound)
    sourcetype: int           # u8 (0=sim, 1=suricata, 2=sysmon, 3=pan, 4=zeek)
    modbus_func_code: int     # u8 (0=N/A, 5=Write Coil, 16=Write Regs, …)
    modbus_unit_id: int       # u8
    zeek_uid: bytes           # 18 bytes, zero-padded
    epoch_nonce: int          # u64

    # ── Convenience accessors ─────────────────────────────────────────────

    @property
    def src_ip_str(self) -> str:
        return ".".join(str(b) for b in self.src_ip)

    @property
    def dst_ip_str(self) -> str:
        return ".".join(str(b) for b in self.dst_ip)

    @property
    def bytes_per_sec(self) -> float:
        return self.flow_bytes_s_milli / 1000.0

    @property
    def duration_ms(self) -> float:
        return self.flow_duration_us / 1000.0

    @property
    def modbus_fc_name(self) -> str:
        _FC_NAMES = {
            0: "N/A", 1: "Read Coils", 2: "Read Discrete Inputs",
            3: "Read Holding Registers", 4: "Read Input Registers",
            5: "Write Single Coil", 6: "Write Single Register",
            15: "Write Multiple Coils", 16: "Write Multiple Registers",
        }
        return _FC_NAMES.get(self.modbus_func_code, f"FC {self.modbus_func_code}")

    @property
    def is_modbus_write(self) -> bool:
        """Returns True if the function code is a write operation (FC 5, 6, 15, 16)."""
        return self.modbus_func_code in (5, 6, 15, 16)


def decode_bincode(raw: bytes) -> ModbusTelemetry:
    """Decode a single bincode NetworkTelemetry record (RECORD_SIZE bytes)."""
    if len(raw) < RECORD_SIZE:
        raise ValueError(
            f"Expected {RECORD_SIZE} bytes, got {len(raw)} — "
            "ensure the edge node and backend share the same struct version"
        )
    fields = struct.unpack(_FMT, raw[:RECORD_SIZE])
    return ModbusTelemetry(
        src_ip=fields[0],
        dst_ip=fields[1],
        dst_port=fields[2],
        protocol=fields[3],
        flow_duration_us=fields[4],
        flow_bytes_s_milli=fields[5],
        packet_count=fields[6],
        direction=fields[7],
        sourcetype=fields[8],
        modbus_func_code=fields[9],
        modbus_unit_id=fields[10],
        zeek_uid=fields[11],
        epoch_nonce=fields[12],
    )


def decode_bincode_batch(raw: bytes) -> List[ModbusTelemetry]:
    """Decode multiple concatenated bincode records."""
    results = []
    offset = 0
    while offset + RECORD_SIZE <= len(raw):
        results.append(decode_bincode(raw[offset:offset + RECORD_SIZE]))
        offset += RECORD_SIZE
    return results


def encode_bincode(t: ModbusTelemetry) -> bytes:
    """Encode a ModbusTelemetry into the exact bincode wire format."""
    return struct.pack(
        _FMT,
        t.src_ip[:4].ljust(4, b"\x00"),
        t.dst_ip[:4].ljust(4, b"\x00"),
        t.dst_port,
        t.protocol,
        t.flow_duration_us,
        t.flow_bytes_s_milli,
        t.packet_count,
        t.direction,
        t.sourcetype,
        t.modbus_func_code,
        t.modbus_unit_id,
        t.zeek_uid[:18].ljust(18, b"\x00"),
        t.epoch_nonce,
    )


def make_telemetry(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.100",
    dst_port: int = 502,
    protocol: int = 6,
    flow_duration_us: int = 1_000_000,
    flow_bytes_s_milli: int = 5_000_000,
    packet_count: int = 10,
    direction: int = 0,
    sourcetype: int = 4,
    modbus_func_code: int = 0,
    modbus_unit_id: int = 1,
    zeek_uid: str = "",
    epoch_nonce: int = 0,
) -> ModbusTelemetry:
    """Helper to create a ModbusTelemetry from human-friendly params."""
    def _ip_bytes(ip: str) -> bytes:
        return bytes(int(o) for o in ip.split("."))

    uid_bytes = zeek_uid.encode("ascii")[:18].ljust(18, b"\x00") if zeek_uid else b"\x00" * 18
    nonce = epoch_nonce or int(time.time())

    return ModbusTelemetry(
        src_ip=_ip_bytes(src_ip),
        dst_ip=_ip_bytes(dst_ip),
        dst_port=dst_port,
        protocol=protocol,
        flow_duration_us=flow_duration_us,
        flow_bytes_s_milli=flow_bytes_s_milli,
        packet_count=packet_count,
        direction=direction,
        sourcetype=sourcetype,
        modbus_func_code=modbus_func_code,
        modbus_unit_id=modbus_unit_id,
        zeek_uid=uid_bytes,
        epoch_nonce=nonce,
    )
