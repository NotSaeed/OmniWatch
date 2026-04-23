"""
CIC-IDS-2017 SOAR rule engine.

Fires immediately after a CIC-IDS-2017 ingestion batch completes.
Queries unique critical attacking IPs, matches against rule-based playbooks,
and persists simulated response actions.

Design principles
-----------------
* Works on plain dicts from cicids_events — no dependency on TriageResult.
* All actions are SIMULATED — zero subprocess/socket calls.
* One action per unique (label-family, target_ip) pair — prevents log explosion
  when 10 000 rows share the same attacker IP.
* Runs synchronously (called via run_in_executor from the async ingest task).
"""

import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Table DDL ─────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS cicids_playbook_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    executed_at   TEXT    NOT NULL,
    playbook_name TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'SIMULATED',
    target_ip     TEXT,
    target_port   INTEGER,
    label         TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    source_file   TEXT    DEFAULT '',
    action_detail TEXT    DEFAULT ''
)
"""
_CREATE_IDX = (
    "CREATE INDEX IF NOT EXISTS idx_cpl_target   ON cicids_playbook_logs(target_ip)",
    "CREATE INDEX IF NOT EXISTS idx_cpl_executed ON cicids_playbook_logs(executed_at)",
)
_INSERT = """
INSERT INTO cicids_playbook_logs
    (executed_at, playbook_name, action, status,
     target_ip, target_port, label, severity, source_file, action_detail)
VALUES (?,?,?,?,?,?,?,?,?,?)
"""

# ── Playbook rules ────────────────────────────────────────────────────────────
# Each rule defines:
#   match        — predicate on the CIC-IDS-2017 label string
#   name         — display name shown in the UI
#   action       — human-readable summary (may contain {ip})
#   detail       — technical command string (always ends with [SIMULATED])
#   target_field — "src_ip" or "dst_ip"

_PLAYBOOKS = [
    {
        "name":         "Block_IP_Playbook",
        "match":        lambda lbl: any(x in lbl for x in ("DoS", "DDoS", "Heartbleed")),
        "action":       "Block {ip} on PA-220 Edge Firewall",
        "detail":       "set security policy src={ip} action=deny zone=untrust [SIMULATED]",
        "target_field": "src_ip",
    },
    {
        "name":         "Isolate_Host_Playbook",
        "match":        lambda lbl: "Web Attack" in lbl or "Infiltration" in lbl,
        "action":       "Quarantine {ip} → isolation VLAN-999",
        "detail":       "NAC: move dst={ip} to VLAN-999 quarantine segment [SIMULATED]",
        "target_field": "dst_ip",
    },
    {
        "name":         "C2_Containment_Playbook",
        "match":        lambda lbl: "Bot" in lbl,
        "action":       "Block C2 beacon from {ip}",
        "detail":       "Firewall: deny outbound src={ip} dst=any port=any [SIMULATED]",
        "target_field": "src_ip",
    },
    {
        "name":         "Rate_Limit_Playbook",
        "match":        lambda lbl: "PortScan" in lbl,
        "action":       "Rate-limit {ip} to 10 pps",
        "detail":       "tc qdisc add dev eth0 root tbf rate 10kbit src={ip} [SIMULATED]",
        "target_field": "src_ip",
    },
    {
        "name":         "Lock_Account_Playbook",
        "match":        lambda lbl: "Patator" in lbl or "Brute Force" in lbl,
        "action":       "Block {ip} on authentication gateway",
        "detail":       "IdP: deny login attempts from src={ip} for 24h [SIMULATED]",
        "target_field": "src_ip",
    },
]


def _match_playbook(label: str) -> dict | None:
    for pb in _PLAYBOOKS:
        if pb["match"](label):
            return pb
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def run_soar_on_ingest(db_path: str, source_file: str = "") -> list[dict]:
    """
    Called (in a thread) after a CIC-IDS-2017 ingestion completes.

    Queries one representative row per unique (label, attacker-IP) pair
    where severity = CRITICAL, matches a playbook, and persists log entries.

    Returns the list of fired entries for WebSocket broadcast.
    """
    if not Path(db_path).exists():
        return []

    # ── ensure log table exists ───────────────────────────────────────────────
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(_DDL)
            for idx in _CREATE_IDX:
                conn.execute(idx)
            conn.commit()
    except Exception as exc:
        logger.error("SOAR: could not create log table: %s", exc)
        return []

    # ── query unique critical events ──────────────────────────────────────────
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            where  = "WHERE severity = 'CRITICAL'"
            params: list = []
            if source_file:
                where  += " AND source_file = ?"
                params.append(source_file)

            # One row per (label, src_ip) — avoids N actions for the same attacker
            critical_rows = conn.execute(
                f"""
                SELECT label, src_ip, dst_ip, dst_port, severity
                FROM   cicids_events
                {where}
                GROUP  BY label, src_ip
                ORDER  BY label
                """,
                params,
            ).fetchall()
    except Exception as exc:
        logger.error("SOAR: query failed: %s", exc)
        return []

    if not critical_rows:
        return []

    # ── match and persist ─────────────────────────────────────────────────────
    fired: list[dict] = []
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    
    import os
    soar_live_mode = os.getenv("SOAR_LIVE_MODE", "false").lower() == "true"

    rows_to_insert: list[tuple] = []
    for row in critical_rows:
        label = (row["label"] or "").strip()
        pb    = _match_playbook(label)
        if not pb:
            continue

        target_ip = row[pb["target_field"]]
        if not target_ip:
            continue

        t0     = time.monotonic()
        action = pb["action"].format(ip=target_ip)
        detail = pb["detail"].format(ip=target_ip)
        if soar_live_mode:
            status = "PENDING_AUTHORIZATION"
        else:
            status = "SIMULATED"

        _ = time.monotonic() - t0   # kept for logging parity

        entry = {
            "executed_at":  now_iso,
            "playbook_name":pb["name"],
            "action":       action,
            "status":       status,
            "target_ip":    target_ip,
            "target_port":  row["dst_port"],
            "label":        label,
            "severity":     row["severity"],
            "source_file":  source_file,
            "action_detail":detail,
        }
        rows_to_insert.append((
            entry["executed_at"], entry["playbook_name"], entry["action"],
            entry["status"],      entry["target_ip"],    entry["target_port"],
            entry["label"],       entry["severity"],     entry["source_file"],
            entry["action_detail"],
        ))
        fired.append(entry)

    if rows_to_insert:
        try:
            with sqlite3.connect(str(db_path)) as conn:
                conn.executemany(_INSERT, rows_to_insert)
                conn.commit()
        except Exception as exc:
            logger.error("SOAR: persist failed: %s", exc)
            return []

    if fired:
        logger.info("SOAR: %d playbook(s) fired for file '%s'", len(fired), source_file or "*")

    return fired


def execute_pending_playbook(db_path: str, target_ip: str, label: str) -> bool:
    """Invoked explicitly by the WebAuthn verification endpoint after FIDO2 signing.
    Dispatches the HTTP command to the local firewall and updates SQLite status."""
    import os
    soar_live_mode = os.getenv("SOAR_LIVE_MODE", "false").lower() == "true"
    if not soar_live_mode:
        return True

    # Find the pending playbook
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT id, action_detail FROM cicids_playbook_logs WHERE target_ip = ? AND label = ? AND status = 'PENDING_AUTHORIZATION' LIMIT 1",
                (target_ip, label)
            ).fetchone()
            
            if not row:
                logger.warning(f"No pending SOAR playbook found for IP {target_ip} and label {label}")
                return False
                
            playbook_id = row["id"]
            detail = row["action_detail"]
            
            # Execute it
            import httpx
            pan_os_url = os.getenv("PAN_OS_URL", "http://localhost:8080/api/mock-firewall")
            actual_cmd = detail.replace("[SIMULATED]", "").strip()
            res = httpx.post(pan_os_url, json={"command": actual_cmd}, timeout=2.0)
            
            new_status = "SUCCESS" if res.status_code == 200 else "FAILED"
            new_detail = actual_cmd if new_status == "SUCCESS" else detail.replace("[SIMULATED]", "[FAILED]").strip()
            
            conn.execute(
                "UPDATE cicids_playbook_logs SET status = ?, action_detail = ? WHERE id = ?",
                (new_status, new_detail, playbook_id)
            )
            conn.commit()
            
            logger.info(f"Live PAN-OS executed for {target_ip} ({new_status})")
            return new_status == "SUCCESS"
    except Exception as exc:
        logger.error(f"Failed to execute pending playbook for {target_ip}: {exc}")
        return False


def ensure_soar_tables(db_path: str) -> None:
    """Create cicids_playbook_logs table and indexes if they don't already exist.

    Called at application startup so every API endpoint has a valid table
    to query even before the first CSV is uploaded.
    """
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(_DDL)
            for idx in _CREATE_IDX:
                conn.execute(idx)
            conn.commit()
        logger.debug("cicids_playbook_logs table ensured at %s", db_path)
    except Exception as exc:
        logger.error("ensure_soar_tables failed: %s", exc)


def query_playbook_logs(
    db_path: str,
    limit:   int = 100,
    offset:  int = 0,
) -> list[dict]:
    """Paginated fetch of recent SOAR actions for the SOARActivity feed."""
    if not Path(db_path).exists():
        return []
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM cicids_playbook_logs "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            logger.debug("query_playbook_logs: table not yet created — returning []")
        else:
            logger.error("query_playbook_logs DB error: %s", exc)
        return []
    except Exception as exc:
        logger.error("query_playbook_logs: %s", exc)
        return []


def get_actioned_ips(db_path: str) -> list[str]:
    """Return all IPs that have had at least one playbook executed."""
    if not Path(db_path).exists():
        return []
    try:
        with sqlite3.connect(str(db_path)) as conn:
            rows = conn.execute(
                "SELECT DISTINCT target_ip FROM cicids_playbook_logs "
                "WHERE target_ip IS NOT NULL"
            ).fetchall()
            return [r[0] for r in rows]
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            logger.debug("get_actioned_ips: table not yet created — returning []")
        else:
            logger.error("get_actioned_ips DB error: %s", exc)
        return []
    except Exception as exc:
        logger.error("get_actioned_ips: %s", exc)
        return []
