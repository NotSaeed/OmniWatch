"""Parser for Palo Alto Networks pan:traffic and pan:threat events."""

from datetime import datetime, timezone
from typing import Any

from ingestion.models import NormalizedEvent


def parse(raw: dict[str, Any]) -> NormalizedEvent | None:
    try:
        raw_text   = raw.get("_raw", str(raw))
        sourcetype = raw.get("sourcetype", "pan:traffic")
        ts_str     = raw.get("receive_time") or raw.get("_time")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        action       = raw.get("action", "").lower()
        threat_id    = raw.get("threatid") or raw.get("threat_id")
        severity_raw = str(raw.get("severity", "")).lower()

        severity_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                        "low": "LOW", "informational": "INFO"}
        severity_hint = severity_map.get(severity_raw) or ("HIGH" if action == "deny" and threat_id else None)

        return NormalizedEvent(
            timestamp=ts,
            sourcetype=sourcetype,
            source_family="firewall",
            src_ip=raw.get("src") or raw.get("src_ip"),
            dst_ip=raw.get("dst") or raw.get("dst_ip"),
            dst_port=_int(raw.get("dport") or raw.get("dst_port")),
            hostname=raw.get("dvc") or raw.get("host"),
            action=action or None,
            severity_hint=severity_hint,
            raw_text=raw_text,
            extra={
                "app":       raw.get("app"),
                "rule":      raw.get("rule"),
                "threat_id": threat_id,
                "category":  raw.get("category"),
                "bytes":     raw.get("bytes"),
            },
        )
    except Exception:
        return None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
