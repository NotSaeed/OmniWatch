"""FastAPI router — all HTTP and WebSocket endpoints."""

import asyncio
import json
import logging
from pathlib import Path

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from api.websocket import manager
from db.crud import (
    get_alert_by_id,
    get_alerts,
    get_dashboard_stats,
    get_playbook_log,
)
from db.database import AsyncSessionLocal

logger = logging.getLogger(__name__)
router = APIRouter()

# Resolve paths relative to project root
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_UPLOAD_DIR   = _PROJECT_ROOT / "data" / "uploads"


# ── DB session dependency ──────────────────────────────────────────────────────

async def get_session():
    async with AsyncSessionLocal() as session:
        yield session


def _db_path() -> str:
    from db.database import get_db_path
    return get_db_path()


# ── Alert endpoints ────────────────────────────────────────────────────────────

@router.get("/api/alerts")
async def list_alerts(
    limit:       int  = 50,
    offset:      int  = 0,
    severity:    str  = None,
    category:    str  = None,
    source_type: str  = None,
    session:     AsyncSession = Depends(get_session),
):
    alerts = await get_alerts(
        session,
        limit=min(limit, 200),
        offset=offset,
        severity=severity,
        category=category,
        source_type=source_type,
    )
    return [_serialise_alert(a) for a in alerts]


@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str, session: AsyncSession = Depends(get_session)):
    alert = await get_alert_by_id(session, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialise_alert(alert)


@router.get("/api/stats")
async def dashboard_stats(session: AsyncSession = Depends(get_session)):
    """
    Combined stats: AI-triage alert counts (alerts table) +
    raw CIC-IDS-2017 event counts (cicids_events table).
    All queries hit indexed columns so this resolves in <10ms.
    """
    from ingestion.cicids_parser import get_cicids_stats

    ai_stats   = await get_dashboard_stats(session)
    cicids     = get_cicids_stats(_db_path())
    by_sev     = cicids.get("by_severity", {})

    # ROI metrics — each detected CRITICAL threat saves ~45 min of manual triage
    # Calculated from raw CIC-IDS event count so the figure is non-zero as soon
    # as a CSV is uploaded, regardless of whether the AI scan has run yet.
    # (0.75 h × $50/h average SOC analyst rate)
    cicids_critical = by_sev.get("CRITICAL", 0)
    hours_saved     = round(cicids_critical * 0.75, 1)
    cost_saved      = round(hours_saved * 50, 2)

    return {
        **ai_stats,
        # Raw ingested event counts (cicids_events table)
        "total_events":       cicids.get("total", 0),
        "critical_events":    by_sev.get("CRITICAL", 0),
        "suspicious_events":  by_sev.get("HIGH", 0) + by_sev.get("MEDIUM", 0),
        "benign_events":      by_sev.get("INFO", 0),
        # Business ROI
        "hours_saved":        hours_saved,
        "cost_saved":         cost_saved,
    }


# ── Scan trigger ───────────────────────────────────────────────────────────────

@router.post("/api/trigger-scan")
async def trigger_scan(dataset: str = "simulated"):
    """Kick off a full triage cycle in the background."""
    from tasks import run_scan_task
    asyncio.create_task(run_scan_task(dataset=dataset))
    return {"status": "scan_started", "dataset": dataset}


# ── BOTSv3 ingestion ───────────────────────────────────────────────────────────

@router.post("/api/ingest")
async def ingest_dataset(file_path: str):
    """Ingest a BOTSv3 JSON export file by absolute server path."""
    path = Path(file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
    if path.suffix.lower() != ".json":
        raise HTTPException(status_code=400, detail="File must be a .json NDJSON export")

    from ingestion.botsv3_parser import ingest_botsv3_to_db

    summary = await asyncio.get_running_loop().run_in_executor(
        None, ingest_botsv3_to_db, path, _db_path()
    )
    await manager.broadcast({"type": "ingest_complete", "data": summary.model_dump()})
    return summary.model_dump()


@router.get("/api/dataset-stats")
async def dataset_stats():
    from mcp_server import get_dataset_stats
    return get_dataset_stats()


# ── CIC-IDS-2017: CSV upload ───────────────────────────────────────────────────

@router.post("/api/upload")
async def upload_csv(file: UploadFile = File(...)):
    """
    Upload a CIC-IDS-2017 CSV file (supports 200MB+).
    Streams the file to disk in 1 MB chunks to avoid memory pressure,
    then triggers ingestion in the background.
    """
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted")

    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = _UPLOAD_DIR / file.filename

    # Stream-write — never loads the full file into memory
    with dest.open("wb") as fh:
        while True:
            chunk = await file.read(1024 * 1024)   # 1 MB read window
            if not chunk:
                break
            fh.write(chunk)

    asyncio.create_task(_cicids_ingest_task(dest))
    return {"status": "ingestion_started", "filename": file.filename, "path": str(dest)}


async def _cicids_ingest_task(path: Path) -> None:
    """
    Background task pipeline:
      1. Parse CSV → cicids_events table
      2. Fire SOAR playbooks on critical rows (deduplicated by attacker IP)
      3. Run CTI enrichment (AbuseIPDB + VirusTotal + MITRE) on unique malicious IPs
         — uses real API keys when present, deterministic mock otherwise
    """
    from ingestion.cicids_parser import ingest_cicids_to_db
    from services.soar_engine import run_soar_on_ingest
    from services.cti_enrichment import enrich_ip_batch, get_mitre_techniques

    await manager.broadcast({"type": "cicids_ingest_started", "filename": path.name, "source": "upload"})
    try:
        loop    = asyncio.get_running_loop()
        db      = _db_path()

        # ── Step 1: Ingest CSV ────────────────────────────────────────────────
        summary = await loop.run_in_executor(None, ingest_cicids_to_db, path, db)
        await manager.broadcast({"type": "cicids_ingest_complete", "filename": path.name, "data": summary})
        logger.info("CSV ingestion complete: %s — %d rows", path.name, summary.get("inserted", 0))

        # ── Step 2: SOAR playbooks ────────────────────────────────────────────
        fired = await loop.run_in_executor(None, run_soar_on_ingest, db, path.name)
        for entry in fired:
            await manager.broadcast({"type": "cicids_playbook_fired", "data": entry})

        # ── Step 3: CTI enrichment on unique malicious IPs ────────────────────
        # Collect IPs that had a playbook fired (already filtered to critical)
        malicious_ips = list({
            e["target_ip"] for e in fired
            if e.get("target_ip") and e["target_ip"] not in ("N/A", "0.0.0.0", None)
        })

        if malicious_ips:
            logger.info("Running CTI enrichment on %d unique IPs from %s",
                        len(malicious_ips), path.name)
            await manager.broadcast({
                "type":    "cti_enrichment_started",
                "filename": path.name,
                "ip_count": len(malicious_ips),
            })
            cti_results = await enrich_ip_batch(malicious_ips)
            # Attach MITRE techniques from attack labels in SOAR entries
            for entry in fired:
                ip = entry.get("target_ip")
                if ip and ip in cti_results:
                    label = entry.get("label", "")
                    cti_results[ip]["mitre"] = get_mitre_techniques(label)

            await manager.broadcast({
                "type":    "cti_enrichment_complete",
                "filename": path.name,
                "results":  cti_results,
            })
            logger.info("CTI enrichment complete for %s — %d IPs processed",
                        path.name, len(cti_results))

    except Exception as exc:
        logger.error("CSV ingestion failed for %s: %s", path.name, exc)
        await manager.broadcast({"type": "cicids_ingest_error", "filename": path.name, "error": str(exc)})


# ── CIC-IDS-2017: Log Explorer query ──────────────────────────────────────────
# Both /api/logs and /api/cicids/logs resolve to the same handler.

@router.get("/api/logs")
@router.get("/api/cicids/logs")
async def cicids_logs(
    search:   str = "",
    severity: str = "",
    label:    str = "",
    limit:    int = 100,
    offset:   int = 0,
):
    """
    Search and paginate CIC-IDS-2017 events for the Log Explorer UI.

    Query params:
      search   — substring match on src_ip, dst_ip, or label
      severity — exact match: CRITICAL | HIGH | MEDIUM | LOW | INFO
      label    — substring match on attack label
      limit    — max rows (capped at 500)
      offset   — pagination offset
    """
    from ingestion.cicids_parser import query_cicids_events

    return query_cicids_events(
        _db_path(),
        search=search,
        severity=severity,
        label=label,
        limit=min(limit, 500),
        offset=offset,
    )


@router.get("/api/cicids/stats")
async def cicids_stats():
    """Aggregate counts by label and severity for the CIC-IDS dashboard widgets."""
    from ingestion.cicids_parser import get_cicids_stats
    return get_cicids_stats(_db_path())


# ── Tier 2 per-alert AI analysis ──────────────────────────────────────────────

@router.post("/api/analyze-incident")
async def analyze_incident(event: dict = Body(...)):
    """
    Enrich a CIC-IDS-2017 alert with CTI (AbuseIPDB, VirusTotal, MITRE) then
    generate a markdown Incident Response Report via Claude.

    Returns:
        {
          "report":       "<markdown string>",
          "generated_at": "<ISO timestamp>",
          "cti":          { ip, abuseipdb, virustotal, mitre }
        }
    """
    from datetime import datetime, timezone
    from services.ai_analyst import generate_incident_report
    from services.cti_enrichment import enrich_event

    cti       = await enrich_event(event)
    report_md = await generate_incident_report(event, cti=cti)
    return {
        "report":       report_md,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "cti":          cti,
    }


# ── CIC-IDS-2017: Tier 2 batch IR report ──────────────────────────────────────

@router.post("/api/cicids/analyze")
async def cicids_analyze(source_file: str = ""):
    """
    Generate a Tier 2 Incident Response Report for CIC-IDS-2017 events.
    Optionally scoped to a specific ingested source_file filename.
    """
    from cicids.analyzer import generate_ir_report
    from ingestion.cicids_parser import get_attack_summary_for_report

    summary = get_attack_summary_for_report(_db_path(), source_file=source_file)
    report  = await generate_ir_report(summary)
    return report


# ── Folder monitor status ──────────────────────────────────────────────────────

@router.get("/api/monitor/status")
async def monitor_status():
    from monitor.watchdog_monitor import get_status
    return get_status()


# ── Playbook log ───────────────────────────────────────────────────────────────

@router.get("/api/playbook-log")
async def playbook_log(limit: int = 50, session: AsyncSession = Depends(get_session)):
    rows = await get_playbook_log(session, limit=min(limit, 200))
    return [_serialise_playbook_log(r) for r in rows]


# ── CIC-IDS-2017 SOAR log ──────────────────────────────────────────────────────

@router.get("/api/cicids/playbook-logs")
async def cicids_playbook_logs(limit: int = 100, offset: int = 0):
    """Recent SOAR actions fired against CIC-IDS-2017 critical events."""
    from services.soar_engine import query_playbook_logs
    return query_playbook_logs(_db_path(), limit=min(limit, 500), offset=offset)


@router.get("/api/cicids/actioned-ips")
async def cicids_actioned_ips():
    """All attacker IPs that have had at least one playbook action executed."""
    from services.soar_engine import get_actioned_ips
    return get_actioned_ips(_db_path())


# ── System reset ──────────────────────────────────────────────────────────────

@router.delete("/api/system/reset")
async def system_reset():
    """
    Wipe all ingested telemetry and SOAR logs so the system is ready for a
    fresh CSV upload.  Clears:
      • cicids_events        — raw ingested network flows
      • cicids_playbook_logs — SOAR execution audit trail
      • alerts               — AI-triage alert feed
      • scan_runs            — triage scan history
      • playbook_log         — BOTSv3 playbook log
    Leaves API-key config and the database file itself intact.
    """
    import sqlite3

    db   = _db_path()
    rows = 0
    try:
        conn = sqlite3.connect(db)
        cur  = conn.cursor()
        for table in (
            "cicids_events",
            "cicids_playbook_logs",
            "alerts",
            "scan_runs",
            "playbook_log",
        ):
            try:
                cur.execute(f"DELETE FROM {table}")   # noqa: S608 — table names are hardcoded
                rows += cur.rowcount
            except sqlite3.OperationalError:
                # Table may not yet exist on a fresh DB — skip silently
                pass
        conn.commit()
        conn.close()
        logger.info("System reset: %d rows deleted across all tables", rows)
        return {"status": "success", "message": "System reset complete", "rows_deleted": rows}
    except Exception as exc:
        logger.error("System reset failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Reset failed: {exc}")


# ── Config / API key status ───────────────────────────────────────────────────

@router.get("/api/config/status")
async def config_status():
    """Returns which API keys are configured (values never exposed)."""
    import os
    def _set(key: str) -> bool:
        val = os.getenv(key, "")
        return bool(val and not val.startswith("your_"))
    return {
        "anthropic":   _set("ANTHROPIC_API_KEY"),
        "abuseipdb":   _set("ABUSEIPDB_API_KEY"),
        "virustotal":  _set("VIRUSTOTAL_API_KEY"),
        "soar_live":   os.getenv("SOAR_LIVE_MODE", "false").lower() == "true",
        "claude_model": os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"),
    }


# ── Kill Chain Narrative ───────────────────────────────────────────────────────

@router.get("/api/scan/{scan_run_id}/narrative")
async def get_narrative(scan_run_id: str, session: AsyncSession = Depends(get_session)):
    from narrative.narrator import generate_kill_chain_narrative

    alerts = await get_alerts(session, limit=200, offset=0)
    scan_alerts = [a for a in alerts if a.scan_run_id == scan_run_id]
    if not scan_alerts:
        raise HTTPException(status_code=404, detail="No alerts found for this scan run")
    narrative = await generate_kill_chain_narrative(scan_run_id, scan_alerts)
    return narrative.model_dump()


# ── WebSocket ──────────────────────────────────────────────────────────────────

@router.websocket("/ws/alerts")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Serialisation helpers ──────────────────────────────────────────────────────

def _serialise_alert(alert) -> dict:
    return {
        "alert_id":            alert.alert_id,
        "timestamp":           alert.timestamp.isoformat() if alert.timestamp else None,
        "severity":            alert.severity,
        "category":            alert.category,
        "confidence":          alert.confidence,
        "source_ip":           alert.source_ip,
        "affected_asset":      alert.affected_asset,
        "mitre_techniques":    _safe_json(alert.mitre_techniques),
        "raw_log_excerpt":     alert.raw_log_excerpt,
        "ai_reasoning":        alert.ai_reasoning,
        "recommendations":     _safe_json(alert.recommendations),
        "false_positive_risk": alert.false_positive_risk,
        "log_type":            alert.log_type,
        "source_type":         alert.source_type,
        "playbook_triggered":  alert.playbook_triggered,
        "scan_run_id":         alert.scan_run_id,
    }


def _serialise_playbook_log(row) -> dict:
    return {
        "id":               row.id,
        "executed_at":      row.executed_at.isoformat() if row.executed_at else None,
        "playbook_name":    row.playbook_name,
        "alert_id":         row.alert_id,
        "trigger_category": row.trigger_category,
        "confidence":       row.confidence,
        "simulated_action": row.simulated_action,
        "action_detail":    row.action_detail,
        "status":           row.status,
        "execution_time_ms":row.execution_time_ms,
        "affected_asset":   row.affected_asset,
        "notes":            row.notes,
    }


def _safe_json(value: str | list) -> list:
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
