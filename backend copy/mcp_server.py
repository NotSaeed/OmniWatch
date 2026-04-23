"""
OmniWatch Log Data Module
Exposes log file and database reader helpers used by the triage engine.
FastMCP dependency removed — Sprint 2 (air-gapped local pipeline).
"""

import sqlite3
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

DB_PATH = BASE_DIR.parent / "omniwatch.db"

LOG_FILES = {
    "syslog":  LOGS_DIR / "syslog.log",
    "network": LOGS_DIR / "network.log",
    "auth":    LOGS_DIR / "auth.log",
}

MAX_LINES   = 200
MAX_RESULTS = 200
MAX_SEARCH  = 100


# ── File helpers ──────────────────────────────────────────────────────────────

def _tail(path: Path, lines: int) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return [l.rstrip("\n") for l in deque(f, maxlen=lines)]
    except FileNotFoundError:
        return []


def _file_info(path: Path) -> dict:
    try:
        stat = path.stat()
        with path.open("r", encoding="utf-8", errors="replace") as f:
            line_count = sum(1 for _ in f)
        return {
            "lines": line_count,
            "size_bytes": stat.st_size,
            "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        }
    except FileNotFoundError:
        return {"lines": 0, "size_bytes": 0, "last_modified": "N/A"}


# ── Database helper ───────────────────────────────────────────────────────────

def _query_db(sql: str, params: tuple = ()) -> list[dict]:
    if not DB_PATH.exists():
        return []
    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        return [{"error": str(e)}]


# ── Log readers ───────────────────────────────────────────────────────────────

def read_syslog(lines: int = 50) -> list[str]:
    return _tail(LOG_FILES["syslog"], min(lines, MAX_LINES))


def read_network_log(lines: int = 50) -> list[str]:
    return _tail(LOG_FILES["network"], min(lines, MAX_LINES))


def read_auth_log(lines: int = 50) -> list[str]:
    return _tail(LOG_FILES["auth"], min(lines, MAX_LINES))


def get_log_stats() -> dict:
    stats = {name: _file_info(path) for name, path in LOG_FILES.items()}
    stats["retrieved_at"] = datetime.now(tz=timezone.utc).isoformat()
    return stats


def get_recent_events(severity: str = "all", minutes: int = 30) -> list[str]:
    keyword_map = {
        "critical": ["CRITICAL", "EMERG", "ALERT", "crit"],
        "error":    ["ERROR", "ERR", "failed", "FAILED", "failure"],
        "warning":  ["WARNING", "WARN", "warn", "invalid", "refused"],
        "all":      [],
    }
    keywords = keyword_map.get(severity.lower(), [])
    results: list[str] = []
    for name, path in LOG_FILES.items():
        for line in _tail(path, min(minutes * 10, 500)):
            if not keywords or any(k in line for k in keywords):
                results.append(f"[{name}] {line}")
    return results[:MAX_LINES]


# ── DB event readers ──────────────────────────────────────────────────────────

def query_events(sourcetype: str = "all", limit: int = 50) -> list[dict]:
    if sourcetype == "all":
        return _query_db(
            "SELECT * FROM raw_events ORDER BY timestamp DESC LIMIT ?",
            (min(limit, MAX_RESULTS),),
        )
    return _query_db(
        "SELECT * FROM raw_events WHERE sourcetype = ? ORDER BY timestamp DESC LIMIT ?",
        (sourcetype, min(limit, MAX_RESULTS)),
    )


def get_events_by_ip(ip: str, minutes: int = 30) -> list[dict]:
    cutoff = (datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)).isoformat()
    return _query_db(
        """
        SELECT * FROM raw_events
        WHERE (src_ip = ? OR dst_ip = ?)
          AND timestamp >= ?
        ORDER BY timestamp ASC
        LIMIT 100
        """,
        (ip, ip, cutoff),
    )


def search_events(keyword: str, limit: int = 30) -> list[dict]:
    return _query_db(
        "SELECT * FROM raw_events WHERE raw_text LIKE ? ORDER BY timestamp DESC LIMIT ?",
        (f"%{keyword}%", min(limit, MAX_SEARCH)),
    )


def get_dataset_stats() -> dict:
    if not DB_PATH.exists():
        return {"status": "no_database", "total_events": 0}
    try:
        with sqlite3.connect(str(DB_PATH)) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM raw_events")
            total = cur.fetchone()[0]
            cur.execute(
                "SELECT sourcetype, COUNT(*) FROM raw_events GROUP BY sourcetype ORDER BY 2 DESC"
            )
            by_sourcetype = dict(cur.fetchall())
            cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM raw_events")
            earliest, latest = cur.fetchone()
        return {
            "total_events": total,
            "by_sourcetype": by_sourcetype,
            "earliest_event": earliest,
            "latest_event": latest,
            "retrieved_at": datetime.now(tz=timezone.utc).isoformat(),
        }
    except Exception as e:
        return {"error": str(e)}


def get_high_severity_events(limit: int = 50) -> list[dict]:
    return _query_db(
        "SELECT * FROM raw_events WHERE severity_hint IS NOT NULL ORDER BY timestamp DESC LIMIT ?",
        (min(limit, MAX_RESULTS),),
    )
