"""
Background task: runs a full triage cycle, persists results, triggers SOAR, broadcasts via WS.
Also hosts the Autonomous Breach Containment (ABC) scheduler cycle.
Imported by api/routes.py and main.py to avoid circular imports.
"""

import asyncio
import logging
import os
import sqlite3
import tempfile

from db.crud import complete_scan_run, create_scan_run, insert_alerts, insert_playbook_log
from db.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

# ── Autonomous Breach Containment state ───────────────────────────────────────

_abc_enabled: bool = False
_abc_processed: set[int] = set()   # edge_telemetry IDs already queued or completed
_ABC_CONFIDENCE_THRESHOLD = 98.0   # minimum STARK confidence_pct to auto-block


def set_abc_mode(enabled: bool) -> None:
    global _abc_enabled
    _abc_enabled = enabled
    logger.info("ABC mode %s", "ENABLED" if enabled else "DISABLED")


def get_abc_status() -> dict:
    return {
        "enabled":              _abc_enabled,
        "processed_count":      len(_abc_processed),
        "confidence_threshold": _ABC_CONFIDENCE_THRESHOLD,
    }


async def run_scan_task(dataset: str = "simulated") -> None:
    """End-to-end scan: triage → store → SOAR → broadcast."""
    from api.websocket import manager
    from soar.engine import evaluate_batch
    from triage.engine import run_full_triage_cycle

    async with AsyncSessionLocal() as session:
        scan_run = await create_scan_run(session, dataset=dataset)

    await manager.broadcast({"type": "scan_started", "scan_run_id": scan_run.id, "dataset": dataset})
    logger.info("Scan started: %s (dataset=%s)", scan_run.id, dataset)

    try:
        results = await run_full_triage_cycle(dataset=dataset)
    except Exception as exc:
        logger.error("Triage cycle failed: %s", exc)
        await manager.broadcast({"type": "scan_error", "scan_run_id": scan_run.id, "error": str(exc)})
        return

    async with AsyncSessionLocal() as session:
        stored_alerts = await insert_alerts(session, results, scan_run_id=scan_run.id)

    # Broadcast each alert as it's stored
    for alert in stored_alerts:
        await manager.broadcast({
            "type": "new_alert",
            "data": {
                "alert_id":   alert.alert_id,
                "severity":   alert.severity,
                "category":   alert.category,
                "confidence": alert.confidence,
                "source_ip":  alert.source_ip,
                "timestamp":  alert.timestamp.isoformat() if alert.timestamp else None,
            },
        })

    # Run SOAR playbooks
    playbook_results = await evaluate_batch(results)
    async with AsyncSessionLocal() as session:
        for pr in playbook_results:
            await insert_playbook_log(session, pr)
            await manager.broadcast({"type": "playbook_executed", "data": pr.model_dump(mode="json")})

    # Complete the scan run record
    sourcetypes = list({r.source_type for r in results})
    async with AsyncSessionLocal() as session:
        await complete_scan_run(session, scan_run, len(results), sourcetypes)

    await manager.broadcast({
        "type": "scan_complete",
        "scan_run_id": scan_run.id,
        "alerts_generated": len(results),
        "playbooks_fired": len(playbook_results),
    })
    logger.info("Scan complete: %d alerts, %d playbooks fired", len(results), len(playbook_results))


# ── Autonomous Breach Containment cycle ──────────────────────────────────────

async def run_abc_cycle() -> None:
    """
    Scheduled every 15 s. When ABC mode is enabled, scans edge_telemetry for
    CRITICAL Modbus write records that haven't been processed yet and spawns
    an auto-prove coroutine for each (capped at 3 per cycle to bound load).
    """
    if not _abc_enabled:
        return

    from api.bincode_route import _db_path, _ensure_edge_table

    db = _db_path()
    _ensure_edge_table(db)
    conn = sqlite3.connect(db, timeout=10.0)

    if _abc_processed:
        placeholders = ",".join("?" * len(_abc_processed))
        rows = conn.execute(
            f"SELECT id, src_ip, modbus_func_code, bincode_raw FROM edge_telemetry "
            f"WHERE severity='CRITICAL' AND modbus_func_code IN (5,6,15,16) "
            f"AND id NOT IN ({placeholders}) "
            f"ORDER BY id DESC LIMIT 3",
            list(_abc_processed),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, src_ip, modbus_func_code, bincode_raw FROM edge_telemetry "
            "WHERE severity='CRITICAL' AND modbus_func_code IN (5,6,15,16) "
            "ORDER BY id DESC LIMIT 3",
        ).fetchall()
    conn.close()

    for row in rows:
        record_id, src_ip, fc, bincode_raw = row
        _abc_processed.add(record_id)
        asyncio.create_task(_abc_auto_prove(record_id, src_ip, fc, bincode_raw))


async def _abc_auto_prove(
    record_id: int,
    src_ip: str,
    fc: int,
    bincode_raw: bytes,
) -> None:
    """
    Full automated STARK-prove → verify → firewall-block pipeline.
    Runs entirely in the backend — no user interaction required.
    Only commits the block if STARK confidence meets _ABC_CONFIDENCE_THRESHOLD.
    """
    from api.bincode_route import _VERIFIER_BIN
    from api.verify_route import _verify_stark, _spend_nonce, enforce_active_block
    from api.websocket import manager

    logger.info("ABC: proving record %d (src=%s FC=%d)", record_id, src_ip, fc)
    await manager.broadcast({"type": "abc_proving", "data": {"record_id": record_id, "src_ip": src_ip}})

    if not bincode_raw:
        logger.warning("ABC: record %d has no bincode_raw — skipping", record_id)
        return

    # 1. Generate STARK proof
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".bin", prefix="omniwatch_abc_")
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
            await proc.wait()   # reap zombie — prevents fd/PID leaks
            logger.error("ABC: prover timed out for record %d", record_id)
            return
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if proc.returncode != 0:
        logger.error("ABC: prover failed for record %d: %s", record_id,
                     stderr.decode(errors="replace").strip())
        return

    receipt_b64: str | None = None
    for line in stdout.decode(errors="replace").splitlines():
        if line.startswith("[RECEIPT] "):
            receipt_b64 = line[len("[RECEIPT] "):].strip()
            break

    if not receipt_b64:
        logger.error("ABC: no [RECEIPT] line for record %d", record_id)
        return

    # 2. Verify STARK proof + confidence gate
    try:
        stark_result = await _verify_stark(receipt_b64)
    except Exception as exc:
        logger.error("ABC: STARK verify failed for record %d: %s", record_id, exc)
        return

    confidence_pct = stark_result.get("confidence_pct", 0.0)
    if confidence_pct < _ABC_CONFIDENCE_THRESHOLD:
        logger.info(
            "ABC: record %d confidence %.1f%% < threshold %.1f%% — skipping block",
            record_id, confidence_pct, _ABC_CONFIDENCE_THRESHOLD,
        )
        await manager.broadcast({
            "type": "abc_low_confidence",
            "data": {"record_id": record_id, "confidence_pct": confidence_pct},
        })
        return

    nonce = stark_result["input_hash"]

    # 3. Spend nonce + persist firewall rule
    async with AsyncSessionLocal() as session:
        if not await _spend_nonce(session, nonce):
            logger.info("ABC: record %d nonce already spent — skipping", record_id)
            return

        block = await enforce_active_block(
            src_ip=src_ip,
            nonce=nonce,
            category=stark_result.get("category_name", "CRITICAL_MODBUS_WRITE"),
            confidence_pct=confidence_pct,
            session=session,
            verdict_json=stark_result,
            edge_record_id=record_id,
            auto_blocked=True,
        )

    await manager.broadcast({
        "type": "abc_auto_block",
        "data": {
            "record_id":       record_id,
            "src_ip":          src_ip,
            "fc":              fc,
            "firewall_rule_id": block["id"],
            "category":        block["category"],
            "confidence_pct":  block["confidence_pct"],
        },
    })
    logger.info("ABC: auto-blocked %s (record %d FC %d, %.1f%%)", src_ip, record_id, fc, confidence_pct)
