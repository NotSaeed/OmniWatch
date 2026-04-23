"""Parser for Windows Event Log (xmlwineventlog / wineventlog)."""

from datetime import datetime, timezone
from typing import Any

from ingestion.models import NormalizedEvent

# EventIDs that indicate authentication/authorization events worth flagging
AUTH_EVENT_IDS = {
    "4624": ("logon_success",  None),
    "4625": ("logon_failure",  "MEDIUM"),
    "4648": ("explicit_creds", "MEDIUM"),
    "4672": ("special_logon",  "LOW"),
    "4720": ("account_created","HIGH"),
    "4722": ("account_enabled","LOW"),
    "4723": ("pw_change",      "LOW"),
    "4740": ("account_lockout","HIGH"),
    "4768": ("kerberos_tgt",   None),
    "4769": ("kerberos_svc",   None),
    "4776": ("ntlm_auth",      None),
}


def parse(raw: dict[str, Any]) -> NormalizedEvent | None:
    try:
        raw_text = raw.get("_raw", str(raw))
        ts_str   = raw.get("TimeCreated") or raw.get("_time")
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        event_id = str(raw.get("EventID", ""))
        action, severity_hint = AUTH_EVENT_IDS.get(event_id, (f"event-{event_id}", None))

        return NormalizedEvent(
            timestamp=ts,
            sourcetype=raw.get("sourcetype", "wineventlog"),
            source_family="auth",
            src_ip=raw.get("IpAddress") or raw.get("src_ip"),
            hostname=raw.get("Computer") or raw.get("host"),
            username=raw.get("TargetUserName") or raw.get("SubjectUserName"),
            action=action,
            severity_hint=severity_hint,
            raw_text=raw_text,
            extra={
                "event_id":    event_id,
                "logon_type":  raw.get("LogonType"),
                "domain":      raw.get("TargetDomainName"),
                "process":     raw.get("ProcessName"),
            },
        )
    except Exception:
        return None
