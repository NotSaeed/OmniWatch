"""
Sprint 4 — Edge Bincode Ingestion API

Endpoints for receiving raw bincode telemetry from the Raspberry Pi 4 edge
node and for the Deterministic Replay Fallback (PCAP replay).
"""

import asyncio
import logging
import os
import sqlite3
import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException, Request

from ingestion.bincode_receiver import (
    RECORD_SIZE,
    ModbusTelemetry,
    decode_bincode,
    decode_bincode_batch,
    encode_bincode,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# ── In-memory edge state ──────────────────────────────────────────────────────

_edge_state = {
    "last_heartbeat": None,
    "records_received": 0,
    "last_record": None,
}


def _db_path() -> str:
    from db.database import get_db_path
    return get_db_path()


def _ensure_edge_table(db: str) -> None:
    """Create the edge_telemetry table if it doesn't exist."""
    conn = sqlite3.connect(db)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS edge_telemetry (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ingested_at     TEXT    NOT NULL DEFAULT (datetime('now')),
            src_ip          TEXT,
            dst_ip          TEXT,
            dst_port        INTEGER,
            protocol        INTEGER,
            flow_duration_us INTEGER,
            flow_bytes_s    REAL,
            packet_count    INTEGER,
            direction       INTEGER,
            sourcetype      INTEGER,
            modbus_func_code INTEGER DEFAULT 0,
            modbus_unit_id   INTEGER DEFAULT 0,
            zeek_uid        TEXT,
            epoch_nonce     INTEGER,
            severity        TEXT    DEFAULT 'INFO',
            bincode_raw     BLOB
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_edge_severity ON edge_telemetry(severity)
    """)
    conn.commit()
    conn.close()


def _classify_severity(t: ModbusTelemetry) -> str:
    """Quick severity classification for the dashboard — mirrors guest logic."""
    bps = t.flow_bytes_s_milli / 1000
    dur_ms = t.flow_duration_us / 1000

    # Unauthorized Modbus writes → always CRITICAL
    if t.is_modbus_write:
        return "CRITICAL"
    # Volumetric DoS
    if bps > 1_000_000:
        return "CRITICAL"
    # Brute force on SSH/FTP/RDP
    if t.dst_port in (21, 22, 3389) and t.packet_count >= 30:
        return "HIGH"
    # Stealth probe
    if dur_ms < 100 and t.packet_count <= 2:
        return "MEDIUM"
    # Exfiltration
    if t.direction == 1 and bps > 500_000 and dur_ms > 5000:
        return "HIGH"
    return "INFO"


def _store_record(db: str, t: ModbusTelemetry, raw: bytes) -> dict:
    """Insert one telemetry record into the edge_telemetry table."""
    severity = _classify_severity(t)
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO edge_telemetry
            (src_ip, dst_ip, dst_port, protocol, flow_duration_us,
             flow_bytes_s, packet_count, direction, sourcetype,
             modbus_func_code, modbus_unit_id, zeek_uid, epoch_nonce,
             severity, bincode_raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        t.src_ip_str, t.dst_ip_str, t.dst_port, t.protocol,
        t.flow_duration_us, t.bytes_per_sec, t.packet_count,
        t.direction, t.sourcetype,
        t.modbus_func_code, t.modbus_unit_id,
        t.zeek_uid.rstrip(b"\x00").decode("ascii", errors="replace"),
        t.epoch_nonce, severity, raw,
    ))
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return {
        "id": row_id,
        "severity": severity,
        "src_ip": t.src_ip_str,
        "dst_ip": t.dst_ip_str,
        "dst_port": t.dst_port,
        "modbus_fc": t.modbus_func_code,
        "modbus_fc_name": t.modbus_fc_name,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/api/edge/ingest")
async def edge_ingest(request: Request):
    """
    Accept a single raw bincode NetworkTelemetry record from the Pi 4 edge node.
    Content-Type should be application/octet-stream.
    """
    raw = await request.body()
    if len(raw) < RECORD_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Payload too small: expected {RECORD_SIZE} bytes, got {len(raw)}"
        )

    try:
        t = decode_bincode(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Bincode decode failed: {exc}")

    db = _db_path()
    _ensure_edge_table(db)
    result = _store_record(db, t, raw[:RECORD_SIZE])

    _edge_state["last_heartbeat"] = time.time()
    _edge_state["records_received"] += 1
    _edge_state["last_record"] = result

    # Broadcast to WebSocket clients
    try:
        from api.websocket import manager
        await manager.broadcast({
            "type": "edge_telemetry",
            "data": result,
        })
    except Exception:
        pass

    logger.info(
        "Edge ingest: %s → %s:%d FC=%d [%s]",
        t.src_ip_str, t.dst_ip_str, t.dst_port,
        t.modbus_func_code, result["severity"],
    )
    return result


@router.post("/api/edge/ingest-batch")
async def edge_ingest_batch(request: Request):
    """
    Accept multiple concatenated bincode records in a single request.
    Used by the PCAP replay fallback for efficient batch ingestion.
    """
    raw = await request.body()
    if len(raw) < RECORD_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Payload too small for even one record ({RECORD_SIZE} bytes needed)"
        )

    try:
        records = decode_bincode_batch(raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Batch decode failed: {exc}")

    db = _db_path()
    _ensure_edge_table(db)

    results = []
    for i, t in enumerate(records):
        offset = i * RECORD_SIZE
        result = _store_record(db, t, raw[offset:offset + RECORD_SIZE])
        results.append(result)

    _edge_state["last_heartbeat"] = time.time()
    _edge_state["records_received"] += len(records)
    if results:
        _edge_state["last_record"] = results[-1]

    logger.info("Edge batch ingest: %d records stored", len(results))
    return {"stored": len(results), "records": results}


@router.get("/api/edge/status")
async def edge_status():
    """Returns the edge node connection state for the dashboard."""
    return {
        "connected": _edge_state["last_heartbeat"] is not None
                     and (time.time() - _edge_state["last_heartbeat"]) < 60,
        "last_heartbeat": _edge_state["last_heartbeat"],
        "records_received": _edge_state["records_received"],
        "last_record": _edge_state["last_record"],
    }


@router.get("/api/edge/logs")
async def edge_logs(limit: int = 100, offset: int = 0, severity: str = ""):
    """Query the edge_telemetry table for the dashboard."""
    db = _db_path()
    _ensure_edge_table(db)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row

    where = ""
    params: list = []
    if severity:
        where = "WHERE severity = ?"
        params.append(severity.upper())

    rows = conn.execute(
        f"""SELECT id, ingested_at, src_ip, dst_ip, dst_port, protocol,
                   flow_duration_us, flow_bytes_s, packet_count, direction,
                   sourcetype, modbus_func_code, modbus_unit_id, zeek_uid,
                   epoch_nonce, severity
            FROM edge_telemetry {where}
            ORDER BY id DESC LIMIT ? OFFSET ?""",
        params + [min(limit, 500), offset],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── STARK proof generation ─────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_VERIFIER_BIN = _PROJECT_ROOT / "verifier" / "target" / "release" / "omniwatch-verifier.exe"
if not _VERIFIER_BIN.exists():
    _VERIFIER_BIN = _PROJECT_ROOT / "verifier" / "target" / "debug" / "omniwatch-verifier.exe"


@router.post("/api/edge/prove/{record_id}")
async def edge_prove(record_id: int):
    """
    Generate a STARK proof for a stored edge_telemetry record.

    Fetches the raw bincode bytes from the DB, writes them to a temp file,
    spawns the compiled verifier binary in --prove-file mode (~8 s in release),
    and returns the base64-encoded STARK receipt for submission to
    /api/verify-remediation.
    """
    db = _db_path()
    _ensure_edge_table(db)

    conn = sqlite3.connect(db)
    row = conn.execute(
        "SELECT bincode_raw FROM edge_telemetry WHERE id = ?", (record_id,)
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(404, f"Edge telemetry record {record_id} not found")
    bincode_raw: bytes = row[0]
    if not bincode_raw:
        raise HTTPException(400, "Record has no bincode_raw — re-ingest with the replay script")

    if not _VERIFIER_BIN.exists():
        raise HTTPException(
            500,
            f"Verifier binary not found at {_VERIFIER_BIN}. "
            "Run: cd verifier && cargo build --release",
        )

    # Write bincode to a temp file so the Rust binary can read it
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".bin", prefix="omniwatch_edge_")
    try:
        os.write(tmp_fd, bincode_raw)
        os.close(tmp_fd)

        proc = await asyncio.create_subprocess_exec(
            str(_VERIFIER_BIN), "--prove-file", tmp_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        except asyncio.TimeoutError:
            proc.kill()
            raise HTTPException(500, "STARK prover timed out after 120 s")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if proc.returncode != 0:
        err = stderr.decode(errors="replace").strip()
        raise HTTPException(500, f"Prover exit {proc.returncode}: {err}")

    # prove_scenario emits "[RECEIPT] <base64>" — extract it
    receipt_b64: str | None = None
    for line in stdout.decode(errors="replace").splitlines():
        if line.startswith("[RECEIPT] "):
            receipt_b64 = line[len("[RECEIPT] "):].strip()
            break

    if receipt_b64 is None:
        raise HTTPException(500, "Prover did not emit a [RECEIPT] line — binary may be stale")

    logger.info("STARK proof generated for edge record %d (%d receipt bytes)", record_id, len(receipt_b64))
    return {"success": True, "receipt_b64": receipt_b64}
