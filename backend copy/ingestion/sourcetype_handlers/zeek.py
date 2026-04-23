"""Parser for Zeek/Bro connection logs (bro:conn, zeek:conn)."""

from datetime import datetime, timezone
from typing import Any

from ingestion.models import NormalizedEvent

# Bytes thresholds for exfiltration detection
EXFIL_BYTES_THRESHOLD = 50_000_000   # 50 MB outbound


def parse(raw: dict[str, Any]) -> NormalizedEvent | None:
    try:
        raw_text   = raw.get("_raw", str(raw))
        sourcetype = raw.get("sourcetype", "bro:conn")
        ts_str     = raw.get("ts") or raw.get("_time")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        bytes_out = _int(raw.get("orig_bytes")) or 0
        duration  = _float(raw.get("duration")) or 0.0
        severity_hint = _classify_zeek(bytes_out, duration, raw.get("conn_state", ""))

        return NormalizedEvent(
            timestamp=ts,
            sourcetype=sourcetype,
            source_family="network_ids",
            src_ip=raw.get("id.orig_h") or raw.get("src_ip"),
            dst_ip=raw.get("id.resp_h") or raw.get("dest_ip"),
            dst_port=_int(raw.get("id.resp_p") or raw.get("dest_port")),
            action=raw.get("conn_state"),
            severity_hint=severity_hint,
            raw_text=raw_text,
            extra={
                "proto":      raw.get("proto"),
                "service":    raw.get("service"),
                "bytes_orig": bytes_out,
                "bytes_resp": _int(raw.get("resp_bytes")),
                "duration":   duration,
            },
        )
    except Exception:
        return None


def _classify_zeek(bytes_out: int, duration: float, conn_state: str) -> str | None:
    if bytes_out > EXFIL_BYTES_THRESHOLD:
        return "HIGH"
    # Regular short-duration outbound connections to same dest = beaconing
    if 25 < duration < 35 and conn_state == "SF":
        return "MEDIUM"
    return None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
