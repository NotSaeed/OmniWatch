"""All database read/write operations."""

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Alert, PlaybookLog, ScanRun
from triage.models import TriageResult


# ── Alerts ────────────────────────────────────────────────────────────────────

async def insert_alerts(
    session: AsyncSession,
    alerts: list[TriageResult],
    scan_run_id: str,
) -> list[Alert]:
    rows = []
    for r in alerts:
        row = Alert(
            alert_id=r.alert_id,
            timestamp=r.timestamp,
            severity=r.severity.value,
            category=r.category.value,
            confidence=r.confidence,
            source_ip=r.source_ip,
            affected_asset=r.affected_asset,
            mitre_techniques=json.dumps(r.mitre_techniques),
            raw_log_excerpt=r.raw_log_excerpt,
            ai_reasoning=r.ai_reasoning,
            recommendations=json.dumps([rec.model_dump() for rec in r.recommendations]),
            false_positive_risk=r.false_positive_risk.value,
            log_type=r.log_type,
            source_type=r.source_type,
            playbook_triggered=r.playbook_triggered,
            scan_run_id=scan_run_id,
            grounding_available=1 if r.grounding_available else 0,
            grounding_score=r.grounding_score,
        )
        session.add(row)
        rows.append(row)
    await session.commit()
    return rows


async def get_alerts(
    session: AsyncSession,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    category: str | None = None,
    source_type: str | None = None,
) -> list[Alert]:
    q = select(Alert).order_by(Alert.timestamp.desc())
    if severity:
        q = q.where(Alert.severity == severity.upper())
    if category:
        q = q.where(Alert.category == category.upper())
    if source_type:
        q = q.where(Alert.source_type == source_type)
    q = q.offset(offset).limit(limit)
    result = await session.execute(q)
    return list(result.scalars().all())


async def get_alert_by_id(session: AsyncSession, alert_id: str) -> Alert | None:
    result = await session.execute(select(Alert).where(Alert.alert_id == alert_id))
    return result.scalar_one_or_none()


async def get_dashboard_stats(session: AsyncSession) -> dict:
    """Return summary counts for the dashboard header."""
    total_result = await session.execute(select(func.count()).select_from(Alert))
    total = total_result.scalar_one()

    severity_result = await session.execute(
        select(Alert.severity, func.count()).group_by(Alert.severity)
    )
    by_severity = {row[0]: row[1] for row in severity_result.all()}

    category_result = await session.execute(
        select(Alert.category, func.count()).group_by(Alert.category)
    )
    by_category = {row[0]: row[1] for row in category_result.all()}

    scan_result = await session.execute(
        select(func.count()).select_from(ScanRun)
    )
    total_scans = scan_result.scalar_one()

    last_scan_result = await session.execute(
        select(ScanRun.completed_at).order_by(ScanRun.started_at.desc()).limit(1)
    )
    last_scan_row = last_scan_result.scalar_one_or_none()

    return {
        "total_alerts":  total,
        "by_severity":   by_severity,
        "by_category":   by_category,
        "total_scans":   total_scans,
        "last_scan_at":  last_scan_row.isoformat() if last_scan_row else None,
    }


# ── Scan runs ─────────────────────────────────────────────────────────────────

async def create_scan_run(
    session: AsyncSession, dataset: str = "simulated"
) -> ScanRun:
    run = ScanRun(
        id=str(uuid.uuid4()),
        started_at=datetime.now(tz=timezone.utc),
        dataset_name=dataset,
        status="running",
    )
    session.add(run)
    await session.commit()
    return run


async def complete_scan_run(
    session: AsyncSession,
    run: ScanRun,
    alerts_generated: int,
    sourcetypes: list[str],
) -> ScanRun:
    run.completed_at     = datetime.now(tz=timezone.utc)
    run.alerts_generated = alerts_generated
    run.sourcetypes_scanned = json.dumps(sourcetypes)
    run.status           = "completed"
    await session.commit()
    return run


# ── Playbook log ──────────────────────────────────────────────────────────────

async def insert_playbook_log(
    session: AsyncSession,
    playbook_result,   # soar.models.PlaybookResult
) -> PlaybookLog:
    row = PlaybookLog(
        executed_at=playbook_result.executed_at,
        playbook_name=playbook_result.playbook_name,
        alert_id=playbook_result.alert_id,
        trigger_category=playbook_result.trigger_category,
        confidence=playbook_result.confidence,
        simulated_action=playbook_result.simulated_action,
        action_detail=playbook_result.action_detail,
        status=playbook_result.status,
        execution_time_ms=playbook_result.execution_time_ms,
        affected_asset=playbook_result.affected_asset,
        notes=playbook_result.notes,
    )
    session.add(row)
    await session.commit()
    return row


async def get_playbook_log(
    session: AsyncSession, limit: int = 50
) -> list[PlaybookLog]:
    result = await session.execute(
        select(PlaybookLog).order_by(PlaybookLog.executed_at.desc()).limit(limit)
    )
    return list(result.scalars().all())
