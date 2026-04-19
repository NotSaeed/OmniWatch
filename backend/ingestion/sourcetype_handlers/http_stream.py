"""Parser for stream:http events (Splunk Stream)."""

import re
from datetime import datetime, timezone
from typing import Any

from ingestion.models import NormalizedEvent

# Patterns that indicate web attacks in URIs
_SQLI_RE  = re.compile(r"(union\s+select|'--|\bor\b\s+1=1|drop\s+table)", re.IGNORECASE)
_XSS_RE   = re.compile(r"(<script|javascript:|onerror=|onload=)", re.IGNORECASE)
_TRAV_RE  = re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.IGNORECASE)
_CMD_RE   = re.compile(r"(;ls|;id|;cat\s|&&whoami|\|bash)", re.IGNORECASE)


def parse(raw: dict[str, Any]) -> NormalizedEvent | None:
    try:
        raw_text = raw.get("_raw", str(raw))
        ts_str   = raw.get("_time") or raw.get("timestamp")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        uri    = raw.get("uri_path", "") or raw.get("url", "") or ""
        method = raw.get("http_method", "GET")
        status = str(raw.get("status", ""))

        severity_hint = _classify_http_threat(uri, method, status)

        return NormalizedEvent(
            timestamp=ts,
            sourcetype="stream:http",
            source_family="web",
            src_ip=raw.get("src_ip") or raw.get("c_ip"),
            dst_ip=raw.get("dest_ip") or raw.get("s_ip"),
            dst_port=_int(raw.get("dest_port", 80)),
            action=f"{method} {status}",
            severity_hint=severity_hint,
            raw_text=raw_text,
            extra={
                "uri":        uri,
                "method":     method,
                "status":     status,
                "user_agent": raw.get("http_user_agent"),
                "bytes":      raw.get("bytes_in"),
            },
        )
    except Exception:
        return None


def _classify_http_threat(uri: str, method: str, status: str) -> str | None:
    if _SQLI_RE.search(uri):
        return "HIGH"
    if _XSS_RE.search(uri):
        return "MEDIUM"
    if _TRAV_RE.search(uri):
        return "HIGH"
    if _CMD_RE.search(uri):
        return "CRITICAL"
    # Many 4xx/5xx from the same source suggests scanning
    if status.startswith("4") and method in ("GET", "POST"):
        return "LOW"
    return None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
