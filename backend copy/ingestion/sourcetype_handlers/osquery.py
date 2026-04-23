"""Parser for osquery result events."""

from datetime import datetime, timezone
from typing import Any

from ingestion.models import NormalizedEvent

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe",
    "pwdump.exe",   "nc.exe",       "ncat.exe", "psexec.exe",
    "mshta.exe",    "wscript.exe",  "cscript.exe",
}


def parse(raw: dict[str, Any]) -> NormalizedEvent | None:
    try:
        raw_text   = raw.get("_raw", str(raw))
        ts_str     = raw.get("unixTime") or raw.get("_time")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        columns      = raw.get("columns", {})
        process_name = columns.get("name") or columns.get("process_name") or raw.get("process_name")
        severity_hint = (
            "HIGH" if process_name and process_name.lower() in SUSPICIOUS_PROCESSES else None
        )

        return NormalizedEvent(
            timestamp=ts,
            sourcetype="osquery",
            source_family="endpoint",
            hostname=raw.get("hostIdentifier") or raw.get("host"),
            process_name=process_name,
            action=raw.get("action") or raw.get("name"),
            severity_hint=severity_hint,
            raw_text=raw_text,
            extra={
                "query_name": raw.get("name"),
                "columns":    columns,
            },
        )
    except Exception:
        return None
