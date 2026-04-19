"""SQLAlchemy ORM table models."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class RawEvent(Base):
    __tablename__ = "raw_events"

    event_id:      Mapped[str]           = mapped_column(String, primary_key=True)
    timestamp:     Mapped[datetime]      = mapped_column(DateTime(timezone=True), index=True)
    sourcetype:    Mapped[str]           = mapped_column(String, index=True)
    source_family: Mapped[str]           = mapped_column(String)
    src_ip:        Mapped[str | None]    = mapped_column(String, nullable=True, index=True)
    dst_ip:        Mapped[str | None]    = mapped_column(String, nullable=True, index=True)
    dst_port:      Mapped[int | None]    = mapped_column(Integer, nullable=True)
    hostname:      Mapped[str | None]    = mapped_column(String, nullable=True)
    username:      Mapped[str | None]    = mapped_column(String, nullable=True)
    process_name:  Mapped[str | None]    = mapped_column(String, nullable=True)
    action:        Mapped[str | None]    = mapped_column(String, nullable=True)
    severity_hint: Mapped[str | None]    = mapped_column(String, nullable=True)
    raw_text:      Mapped[str]           = mapped_column(Text)
    extra_json:    Mapped[str]           = mapped_column(Text, default="{}")


class Alert(Base):
    __tablename__ = "alerts"

    alert_id:            Mapped[str]        = mapped_column(String, primary_key=True)
    timestamp:           Mapped[datetime]   = mapped_column(DateTime(timezone=True), index=True)
    severity:            Mapped[str]        = mapped_column(String, index=True)
    category:            Mapped[str]        = mapped_column(String, index=True)
    confidence:          Mapped[float]      = mapped_column(Float)
    source_ip:           Mapped[str | None] = mapped_column(String, nullable=True)
    affected_asset:      Mapped[str | None] = mapped_column(String, nullable=True)
    mitre_techniques:    Mapped[str]        = mapped_column(Text, default="[]")   # JSON list
    raw_log_excerpt:     Mapped[str]        = mapped_column(Text)
    ai_reasoning:        Mapped[str]        = mapped_column(Text)
    recommendations:     Mapped[str]        = mapped_column(Text, default="[]")   # JSON list
    false_positive_risk: Mapped[str]        = mapped_column(String, default="MEDIUM")
    log_type:            Mapped[str]        = mapped_column(String, default="unknown")
    source_type:         Mapped[str]        = mapped_column(String, default="simulated")
    playbook_triggered:  Mapped[str | None] = mapped_column(String, nullable=True)
    scan_run_id:         Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    grounding_available: Mapped[int]        = mapped_column(Integer, default=1)   # 1=True, 0=False
    grounding_score:     Mapped[float | None] = mapped_column(Float, nullable=True)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id:                  Mapped[str]        = mapped_column(String, primary_key=True)
    started_at:          Mapped[datetime]   = mapped_column(DateTime(timezone=True))
    completed_at:        Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    alerts_generated:    Mapped[int]        = mapped_column(Integer, default=0)
    sourcetypes_scanned: Mapped[str]        = mapped_column(Text, default="[]")  # JSON list
    dataset_name:        Mapped[str]        = mapped_column(String, default="simulated")
    status:              Mapped[str]        = mapped_column(String, default="running")


class PlaybookLog(Base):
    __tablename__ = "playbook_log"

    id:               Mapped[int]        = mapped_column(Integer, primary_key=True, autoincrement=True)
    executed_at:      Mapped[datetime]   = mapped_column(DateTime(timezone=True))
    playbook_name:    Mapped[str]        = mapped_column(String)
    alert_id:         Mapped[str]        = mapped_column(String, index=True)
    trigger_category: Mapped[str]        = mapped_column(String)
    confidence:       Mapped[float]      = mapped_column(Float)
    simulated_action: Mapped[str]        = mapped_column(Text)
    action_detail:    Mapped[str]        = mapped_column(Text)
    status:           Mapped[str]        = mapped_column(String, default="SIMULATED")
    execution_time_ms:Mapped[int]        = mapped_column(Integer, default=0)
    affected_asset:   Mapped[str | None] = mapped_column(String, nullable=True)
    notes:            Mapped[str]        = mapped_column(Text, default="")
