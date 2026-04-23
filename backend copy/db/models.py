"""SQLAlchemy ORM table models."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, LargeBinary, String, Text
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


class WebAuthnCredential(Base):
    """Stores enrolled FIDO2 authenticator credentials (one row per hardware key)."""
    __tablename__ = "webauthn_credentials"

    credential_id:        Mapped[str]      = mapped_column(String,      primary_key=True)  # base64-encoded
    user_id:              Mapped[str]      = mapped_column(String,      index=True)
    user_name:            Mapped[str]      = mapped_column(String)
    attested_cred_cbor:   Mapped[bytes]    = mapped_column(LargeBinary)  # raw AttestedCredentialData bytes
    sign_count:           Mapped[int]      = mapped_column(Integer,     default=0)
    registered_at:        Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SpentReceipt(Base):
    """
    Spent-Receipt Registry — prevents TOCTOU / replay attacks on STARK proofs.
    The nonce is the hex-encoded input_hash from the ThreatVerdict journal.
    INSERT OR IGNORE on nonce makes the check-and-mark operation atomic.
    """
    __tablename__ = "spent_receipts"

    nonce:    Mapped[str] = mapped_column(String, primary_key=True)  # ThreatVerdict.input_hash as hex
    spent_at: Mapped[str] = mapped_column(String)                    # ISO-8601 UTC timestamp


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


class FirewallRule(Base):
    """
    Active Remediation Bridge — persists every STARK+FIDO2 authorised block action.
    The nonce unique constraint prevents duplicate rules for the same STARK receipt.
    """
    __tablename__ = "firewall_status"

    id:             Mapped[int]         = mapped_column(Integer, primary_key=True, autoincrement=True)
    src_ip:         Mapped[str]         = mapped_column(String, index=True)
    action:         Mapped[str]         = mapped_column(String, default="BLOCK")
    reason:         Mapped[str]         = mapped_column(String, default="Unauthorized Modbus Write")
    nonce:          Mapped[str]         = mapped_column(String, unique=True)
    category:       Mapped[str]         = mapped_column(String, default="UNKNOWN")
    confidence:     Mapped[float]       = mapped_column(Float, default=0.0)
    blocked_at:     Mapped[datetime]    = mapped_column(DateTime(timezone=True), default=_utcnow)
    verdict_json:   Mapped[str | None]  = mapped_column(Text, nullable=True)
    edge_record_id: Mapped[int | None]  = mapped_column(Integer, nullable=True, index=True)
    auto_blocked:   Mapped[int]         = mapped_column(Integer, default=0)  # 1 = ABC autonomous, 0 = manual
