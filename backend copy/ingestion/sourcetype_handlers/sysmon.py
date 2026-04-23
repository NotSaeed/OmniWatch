"""Parser for Windows Sysmon events."""

from datetime import datetime, timezone
from typing import Any

from ingestion.models import NormalizedEvent


def parse(raw: dict[str, Any]) -> NormalizedEvent | None:
    try:
        raw_text  = raw.get("_raw", str(raw))
        ts_str    = raw.get("UtcTime") or raw.get("_time")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        event_id = str(raw.get("EventID", ""))
        # Sysmon EventIDs that indicate suspicious activity
        HIGH_RISK_IDS = {"1", "3", "7", "8", "10", "11", "12", "13", "25"}
        severity_hint = "HIGH" if event_id in HIGH_RISK_IDS else None

        return NormalizedEvent(
            timestamp=ts,
            sourcetype="sysmon",
            source_family="endpoint",
            src_ip=raw.get("SourceIp") or raw.get("SourceAddress"),
            dst_ip=raw.get("DestinationIp") or raw.get("DestinationAddress"),
            dst_port=_int(raw.get("DestinationPort")),
            hostname=raw.get("Computer") or raw.get("host"),
            username=raw.get("User"),
            process_name=raw.get("Image") or raw.get("ProcessName"),
            action=f"EventID-{event_id}",
            severity_hint=severity_hint,
            raw_text=raw_text,
            extra={
                "event_id":      event_id,
                "parent_image":  raw.get("ParentImage"),
                "command_line":  raw.get("CommandLine"),
                "hash":          raw.get("Hashes"),
            },
        )
    except Exception:
        return None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
