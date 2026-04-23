"""
STARK proof generation for Edge Telemetry records.
Canonical handler for POST /api/edge/prove/{record_id}.
"""

import asyncio
import logging
import os
import sqlite3
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter(tags=["prove"])

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_VERIFIER_BIN = _PROJECT_ROOT / "verifier" / "target" / "release" / "omniwatch-verifier.exe"
if not _VERIFIER_BIN.exists():
    _VERIFIER_BIN = _PROJECT_ROOT / "verifier" / "target" / "debug" / "omniwatch-verifier.exe"


def _db_path() -> str:
    from db.database import get_db_path
    return get_db_path()


@router.post("/api/edge/prove/{record_id}")
async def generate_proof(record_id: int):
    """
    Generate a STARK receipt for an edge telemetry record.

    Fetches the raw 61-byte bincode blob from SQLite, writes it to a temp
    file, and invokes the omniwatch-verifier in --prove-file mode (~8-17 s
    in release build). Returns the base64-encoded receipt for submission to
    /api/verify-remediation.
    """
    if not _VERIFIER_BIN.exists():
        raise HTTPException(
            500,
            f"Verifier binary not found at {_VERIFIER_BIN}. "
            "Run: cd verifier && cargo build --release",
        )

    # Fetch bincode blob from DB
    try:
        conn = sqlite3.connect(_db_path(), timeout=10.0)
        row = conn.execute(
            "SELECT bincode_raw FROM edge_telemetry WHERE id = ?", (record_id,)
        ).fetchone()
        conn.close()
    except Exception as exc:
        raise HTTPException(500, f"Database error fetching record {record_id}: {exc}")

    if row is None:
        raise HTTPException(404, f"Edge telemetry record {record_id} not found")
    bincode_data: bytes = row[0]
    if not bincode_data:
        raise HTTPException(400, "Record has no bincode_raw — re-ingest with the replay script")

    # Write to temp file, pass to verifier, always clean up
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".bin", prefix="omniwatch_edge_")
    proc = None
    try:
        os.write(tmp_fd, bincode_data)
        os.close(tmp_fd)

        logger.info(
            "Generating STARK proof for record %d (%d bytes)", record_id, len(bincode_data)
        )
        proc = await asyncio.create_subprocess_exec(
            str(_VERIFIER_BIN), "--prove-file", tmp_path,
            cwd=str(_PROJECT_ROOT / "verifier"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()           # reap the zombie — prevents fd leaks
            raise HTTPException(504, "STARK prover timed out after 120 s")

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise HTTPException(500, f"Prover exit {proc.returncode}: {err}")

        receipt_b64: str | None = None
        for line in stdout.decode(errors="replace").splitlines():
            if line.startswith("[RECEIPT] "):
                receipt_b64 = line[len("[RECEIPT] "):].strip()
                break

        if not receipt_b64:
            raise HTTPException(500, "Prover output valid but [RECEIPT] tag not found")

        logger.info(
            "STARK proof generated for record %d (%d receipt bytes)",
            record_id, len(receipt_b64),
        )
        return {"success": True, "receipt_b64": receipt_b64}

    finally:
        Path(tmp_path).unlink(missing_ok=True)
