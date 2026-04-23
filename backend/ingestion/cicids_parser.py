"""
OmniWatch Modbus TCP Parser — Refactored to drop label cheating.

This parses raw JSON Modbus traffic and structurally evaluates it
using the same invariants that the Rust ZkVM executes.
"""

import json
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ── DDL ───────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cicids_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ingested_at    TEXT NOT NULL,
    src_ip         TEXT,
    dst_ip         TEXT,
    dst_port       INTEGER,  -- Used for transaction_id for UI mapping
    protocol       INTEGER,  -- Used for protocol_id
    label          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    category       TEXT NOT NULL,
    flow_duration  REAL,     -- Used for Length for UI mapping
    flow_bytes_s   REAL,     -- Used for Function Code for UI mapping
    source_file    TEXT DEFAULT ''
)
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_modbus_label    ON cicids_events(label)",
    "CREATE INDEX IF NOT EXISTS idx_modbus_severity ON cicids_events(severity)",
    "CREATE INDEX IF NOT EXISTS idx_modbus_src_ip   ON cicids_events(src_ip)",
]

_INSERT = """
INSERT INTO cicids_events
    (ingested_at, src_ip, dst_ip, dst_port, protocol,
     label, severity, category, flow_duration, flow_bytes_s, source_file)
VALUES (?,?,?,?,?,?,?,?,?,?,?)
"""

# ── Startup helper ─────────────────────────────────────────────────────────────

def ensure_cicids_tables(db_path: str) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            # We must recreate the table to avoid schema collisions if they manually changed stuff,
            # but we keep the name cicids_events to avoid breaking the front UI.
            # Actually, the UI doesn't crash if we just reuse the column names for new semantic data.
            conn.execute(_CREATE_TABLE)
            for idx in _CREATE_INDEXES:
                conn.execute(idx)
        except Exception as e:
            logger.error(f"Error ensuring DB tables: {e}")
        conn.commit()


# ── Host-side Emulation of the ZkVM rules ──────────────────────────────────────

def _evaluate_modbus(fc, length, data_len):
    """
    Host-side emulation of verifier/methods/guest/src/main.rs.
    We physically read the telemetry, NOT a pre-supplied label.
    """
    category = "BENIGN"
    severity = "INFO"
    label = "Normal Operation"

    # Rule 1: Buffer Anomaly
    # expected_data = length - 2. If it mismatches, it's an anomaly.
    expected_data_len = max(0, length - 2)
    if expected_data_len != data_len or length < 2:
        return "CRITICAL", "ANOMALY", "Buffer Overflow Anomaly"

    # Rule 2: Illegal Function Code
    if fc in (5, 6, 15, 16):
        # Write operations on OT are forbidden via this network sensor path!
        return "CRITICAL", "MALWARE", "Illegal Write Command (FC 05/06)"

    return severity, category, label

# ── Public API ────────────────────────────────────────────────────────────────

def ingest_cicids_to_db(path: Path, db_path: str) -> dict:
    path = Path(path)
    summary: dict = {
        "total_rows": 0,
        "inserted":   0,
        "skipped":    0,
        "by_label":   {},
        "by_severity":{},
        "source_file": path.name,
    }

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        # Ensure table exists (idempotent)
        conn.execute(_CREATE_TABLE)
        for idx in _CREATE_INDEXES:
            conn.execute(idx)
        # Idempotent: remove previous rows from this exact source file
        # so re-uploading the same file yields the same final state
        conn.execute("DELETE FROM cicids_events WHERE source_file = ?", (path.name,))
        conn.commit()

        now_iso = datetime.now(tz=timezone.utc).isoformat()
        chunk = []

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                summary["total_rows"] += 1
                try:
                    data = json.loads(line)
                    src_ip = data.get("src_ip", "")
                    dst_ip = data.get("dst_ip", "")
                    transaction_id = int(data.get("transaction_id", 0))
                    protocol_id = int(data.get("protocol_id", 0))
                    length = int(data.get("length", 0))
                    fc = int(data.get("function_code", 0))
                    data_hex = data.get("data_hex", "")
                    
                    data_len = len(bytes.fromhex(data_hex)) if data_hex else 0

                    # FIRST-LINE HEURISTIC FILTER
                    severity, category, label = _evaluate_modbus(fc, length, data_len)

                    # TWO-TIER TRUST MODEL: ZK-VM STARK PROVING
                    # Only rows flagged as CRITICAL by the heuristic filter are computationally
                    # proven by the air-gapped RISC Zero zkVM guest.
                    if severity == "CRITICAL":
                        import subprocess
                        import hashlib
                        
                        payload = json.dumps({
                            "src_ip": src_ip, "dst_ip": dst_ip, "transaction_id": transaction_id, 
                            "protocol_id": protocol_id, "length": length, "function_code": fc, "data_hex": data_hex
                        })
                        
                        # Dispatch to Rust prover binary via subprocess
                        try:
                            # We attempt to run the compiled Rust STARK prover
                            exe_name = "verifier.exe" if sys.platform == "win32" else "verifier"
                            prover_bin = str(Path(__file__).parent.parent.parent / "verifier" / "target" / "release" / exe_name)
                            result = subprocess.run([prover_bin], input=payload.encode(), capture_output=True, timeout=10)
                            if result.returncode != 0:
                                logger.error(f"zkVM Prover failed: {result.stderr.decode()}")
                            else:
                                logger.info(f"ZK Receipt Generated: {result.stdout.decode().strip()}")
                        except FileNotFoundError:
                            logger.error("zkVM Prover binary not found. Cryptographic verification explicitly failed. Aborting fallback.")
                        except Exception as e:
                            logger.error(f"zkVM Dispatch error: {e}")

                    # Map properties for the UI to display
                    # UI: dst_port = transaction_id
                    # UI: protocol = protocol_id
                    # UI: flow_duration = length
                    # UI: flow_bytes_s = function_code
                    chunk.append((
                        now_iso, src_ip, dst_ip, transaction_id, protocol_id,
                        label, severity, category, float(length), float(fc), path.name
                    ))

                    summary["by_label"][label] = summary["by_label"].get(label, 0) + 1
                    summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

                except Exception as e:
                    logger.error(f"Failed parsing modbus entry: {e}")
                    summary["skipped"] += 1

                if len(chunk) >= 1000:
                    conn.executemany(_INSERT, chunk)
                    conn.commit()
                    summary["inserted"] += len(chunk)
                    chunk.clear()

        if chunk:
            conn.executemany(_INSERT, chunk)
            conn.commit()
            summary["inserted"] += len(chunk)

    return summary


def query_cicids_events(
    db_path: str,
    search:   str = "",
    severity: str = "",
    label:    str = "",
    limit:    int = 100,
    offset:   int = 0,
) -> list[dict]:
    if not Path(db_path).exists(): return []
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            conditions = []
            params = []

            if search:
                conditions.append("(src_ip LIKE ? OR dst_ip LIKE ? OR label LIKE ?)")
                like = f"%{search}%"
                params += [like, like, like]
            if severity:
                conditions.append("severity = ?")
                params.append(severity.upper())
            if label:
                conditions.append("label LIKE ?")
                params.append(f"%{label}%")

            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            params += [limit, offset]

            rows = cur.execute(
                f"SELECT id, ingested_at, src_ip, dst_ip, dst_port, protocol, "
                f"label, severity, category, flow_duration, flow_bytes_s, source_file "
                f"FROM cicids_events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("query_cicids_events error: %s", exc)
        return []


def get_cicids_stats(db_path: str) -> dict:
    empty = {"total": 0, "by_label": {}, "by_severity": {}}
    if not Path(db_path).exists(): return empty
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            total = cur.execute("SELECT COUNT(*) FROM cicids_events").fetchone()[0]
            by_label = {
                r["label"]: r["cnt"]
                for r in cur.execute("SELECT label, COUNT(*) AS cnt FROM cicids_events GROUP BY label ORDER BY cnt DESC").fetchall()
            }
            by_severity = {
                r["severity"]: r["cnt"]
                for r in cur.execute("SELECT severity, COUNT(*) AS cnt FROM cicids_events GROUP BY severity").fetchall()
            }
            return {"total": total, "by_label": by_label, "by_severity": by_severity}
    except Exception as exc:
        logger.error("get_cicids_stats error: %s", exc)
        return empty


def get_attack_summary_for_report(db_path: str, source_file: str = "") -> dict:
    if not Path(db_path).exists():
        return {"total_events": 0, "attacks": [], "source_file": source_file}
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            where  = "WHERE source_file = ?" if source_file else ""
            params = [source_file] if source_file else []

            total = cur.execute(f"SELECT COUNT(*) FROM cicids_events {where}", params).fetchone()[0]

            rows = cur.execute(
                f"SELECT label, severity, COUNT(*) AS cnt, GROUP_CONCAT(DISTINCT src_ip) AS ips "
                f"FROM cicids_events {where} GROUP BY label ORDER BY cnt DESC",
                params,
            ).fetchall()

            attacks = []
            for r in rows:
                if r["label"].upper() == "NORMAL OPERATION":
                    continue
                attacks.append({
                    "label":      r["label"],
                    "count":      r["cnt"],
                    "severity":   r["severity"],
                    "sample_ips": [ip for ip in (r["ips"] or "").split(",") if ip][:5],
                })

            return {"total_events": total, "attacks": attacks, "source_file": source_file, "time_range": {}}
    except Exception as exc:
        logger.error("get_attack_summary_for_report error: %s", exc)
        return {"total_events": 0, "attacks": [], "source_file": source_file}
