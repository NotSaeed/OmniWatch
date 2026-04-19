"""
OmniWatch MCP Server
Exposes security log data to Claude via FastMCP tools.
Run standalone: python backend/mcp_server.py
"""

import sqlite3
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastmcp import FastMCP

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

MAX_LINES   = 200   # hard cap for log reads
MAX_RESULTS = 200   # hard cap for DB result sets
MAX_SEARCH  = 100   # hard cap for keyword search

# ── FastMCP server ────────────────────────────────────────────────────────────
mcp = FastMCP(
    name="omniwatch-log-server",
    instructions=(
        "You are connected to the OmniWatch security log server. "
        "Use the provided tools to read security event data from local log files "
        "and the normalized event database. Always base your analysis strictly on "
        "the data returned by these tools — do not infer events that are not present."
    ),
)


# ── File helpers ──────────────────────────────────────────────────────────────

def _tail(path: Path, lines: int) -> list[str]:
    """Return the last `lines` lines from a file using a bounded deque (memory-safe)."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return [l.rstrip("\n") for l in deque(f, maxlen=lines)]
    except FileNotFoundError:
        return []


def _file_info(path: Path) -> dict:
    """Return line count, size, and last-modified for a single file in one stat call."""
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
    """
    Execute a SELECT query against the OmniWatch SQLite database.
    Returns rows as dicts. Returns [] if the database does not exist yet.
    """
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


# ── MCP Tools — flat log files ────────────────────────────────────────────────

@mcp.tool()
def read_syslog(lines: int = 50) -> list[str]:
    """
    Read the last N lines from the system log (syslog).
    Contains general OS events, service starts/stops, kernel messages, and daemon errors.
    """
    return _tail(LOG_FILES["syslog"], min(lines, MAX_LINES))


@mcp.tool()
def read_network_log(lines: int = 50) -> list[str]:
    """
    Read the last N lines from the network traffic log.
    Contains connection records: source/dest IPs, ports, protocols, bytes transferred.
    """
    return _tail(LOG_FILES["network"], min(lines, MAX_LINES))


@mcp.tool()
def read_auth_log(lines: int = 50) -> list[str]:
    """
    Read the last N lines from the authentication log.
    Contains SSH login attempts, sudo usage, PAM events, and account changes.
    """
    return _tail(LOG_FILES["auth"], min(lines, MAX_LINES))


@mcp.tool()
def get_log_stats() -> dict:
    """
    Return metadata about all log files: line counts, last-modified timestamps,
    and file sizes. Use this to decide which logs to read first.
    """
    stats = {name: _file_info(path) for name, path in LOG_FILES.items()}
    stats["retrieved_at"] = datetime.now(tz=timezone.utc).isoformat()
    return stats


@mcp.tool()
def get_recent_events(severity: str = "all", minutes: int = 30) -> list[str]:
    """
    Return log lines from all sources that contain severity keywords.

    severity: "critical" | "error" | "warning" | "all"
    minutes:  how far back to look (max 120)
    """
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


# ── MCP Tools — BOTSv3 normalized event database ──────────────────────────────

@mcp.tool()
def query_events(sourcetype: str = "all", limit: int = 50) -> list[dict]:
    """
    Query normalized events from the BOTSv3 dataset stored in the database.
    sourcetype: "suricata" | "sysmon" | "wineventlog" | "pan_traffic" |
                "stream_http" | "zeek_conn" | "osquery" | "all"
    """
    if sourcetype == "all":
        return _query_db(
            "SELECT * FROM raw_events ORDER BY timestamp DESC LIMIT ?",
            (min(limit, MAX_RESULTS),),
        )
    return _query_db(
        "SELECT * FROM raw_events WHERE sourcetype = ? ORDER BY timestamp DESC LIMIT ?",
        (sourcetype, min(limit, MAX_RESULTS)),
    )


@mcp.tool()
def get_events_by_ip(ip: str, minutes: int = 30) -> list[dict]:
    """
    Return all normalized events involving a specific IP address (source or destination)
    within the last `minutes` minutes. Useful for building an attack timeline around an IP.
    """
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


@mcp.tool()
def search_events(keyword: str, limit: int = 30) -> list[dict]:
    """
    Full-text search across all normalized event raw_text fields.
    Useful for finding events related to a process name, username, or URL path.
    """
    return _query_db(
        "SELECT * FROM raw_events WHERE raw_text LIKE ? ORDER BY timestamp DESC LIMIT ?",
        (f"%{keyword}%", min(limit, MAX_SEARCH)),
    )


@mcp.tool()
def get_dataset_stats() -> dict:
    """
    Return statistics about the loaded dataset: total event count,
    breakdown by sourcetype, and time range of the data.
    """
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


@mcp.tool()
def get_high_severity_events(limit: int = 50) -> list[dict]:
    """
    Return events that the source system flagged with a severity hint.
    Prioritizes these for triage over events with no severity signal.
    """
    return _query_db(
        "SELECT * FROM raw_events WHERE severity_hint IS NOT NULL ORDER BY timestamp DESC LIMIT ?",
        (min(limit, MAX_RESULTS),),
    )


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting OmniWatch MCP Server...")
    print(f"Log directory: {LOGS_DIR}")
    mcp.run()
