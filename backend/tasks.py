"""
Background task: runs a full triage cycle, persists results, triggers SOAR, broadcasts via WS.
Imported by api/routes.py to avoid circular imports with main.py.
"""

import logging
import uuid
from datetime import datetime, timezone

from db.crud import complete_scan_run, create_scan_run, insert_alerts, insert_playbook_log
from db.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


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
