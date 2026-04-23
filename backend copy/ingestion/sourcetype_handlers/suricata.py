"""Parser for Suricata IDS events."""

from datetime import datetime, timezone
from typing import Any

from ingestion.models import NormalizedEvent


def parse(raw: dict[str, Any]) -> NormalizedEvent | None:
    try:
        raw_text = raw.get("_raw", str(raw))
        ts_str   = raw.get("timestamp") or raw.get("_time")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        severity = raw.get("alert", {}).get("severity") if isinstance(raw.get("alert"), dict) else None
        severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
        severity_hint = severity_map.get(int(severity), None) if severity else None

        return NormalizedEvent(
            timestamp=ts,
            sourcetype="suricata",
            source_family="network_ids",
            src_ip=raw.get("src_ip"),
            dst_ip=raw.get("dest_ip"),
            dst_port=_int(raw.get("dest_port")),
            hostname=raw.get("host"),
            action=raw.get("event_type"),
            severity_hint=severity_hint,
            raw_text=raw_text,
            extra={
                "signature": raw.get("alert", {}).get("signature") if isinstance(raw.get("alert"), dict) else None,
                "proto":     raw.get("proto"),
                "category":  raw.get("alert", {}).get("category") if isinstance(raw.get("alert"), dict) else None,
            },
        )
    except Exception:
        return None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
