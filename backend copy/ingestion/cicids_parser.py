"""
CIC-IDS-2017 CSV parser — chunked, memory-safe, handles 200MB+ files.

Usage:
    from ingestion.cicids_parser import ingest_cicids_to_db, query_cicids_events
    summary = ingest_cicids_to_db(Path("traffic.csv"), "omniwatch.db")
"""

import csv
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

CHUNK_SIZE = 5_000   # rows per DB batch — ~4 MB RAM peak per chunk

_ATTACK_SEVERITY: dict[str, tuple[str, str]] = {
    "BENIGN":                             ("INFO",     "BENIGN"),
    "DoS Hulk":                           ("CRITICAL", "MALWARE"),
    "DoS GoldenEye":                      ("CRITICAL", "MALWARE"),
    "DoS slowloris":                      ("HIGH",     "MALWARE"),
    "DoS Slowhttptest":                   ("HIGH",     "MALWARE"),
    "DDoS":                               ("CRITICAL", "MALWARE"),
    "PortScan":                           ("HIGH",     "PORT_SCAN"),
    "FTP-Patator":                        ("HIGH",     "BRUTE_FORCE"),
    "SSH-Patator":                        ("HIGH",     "BRUTE_FORCE"),
    "Bot":                                ("CRITICAL", "MALWARE"),
    "Web Attack - Brute Force":           ("HIGH",     "BRUTE_FORCE"),
    "Web Attack \u2013 Brute Force":      ("HIGH",     "BRUTE_FORCE"),
    "Web Attack - XSS":                   ("HIGH",     "ANOMALY"),
    "Web Attack \u2013 XSS":             ("HIGH",     "ANOMALY"),
    "Web Attack - Sql Injection":         ("CRITICAL", "MALWARE"),
    "Web Attack \u2013 Sql Injection":    ("CRITICAL", "MALWARE"),
    "Infiltration":                       ("CRITICAL", "EXFILTRATION"),
    "Heartbleed":                         ("CRITICAL", "MALWARE"),
}


def _norm_keys(row: dict) -> dict:
    """Strip BOM, whitespace, and lowercase all header keys. Values are left as-is."""
    return {k.strip().lstrip("\ufeff").lower(): v for k, v in row.items()}


def classify_label(label: str) -> tuple[str, str]:
    stripped = label.strip()
    if stripped in _ATTACK_SEVERITY:
        return _ATTACK_SEVERITY[stripped]
    if stripped.upper() == "BENIGN":
        return ("INFO", "BENIGN")
    return ("HIGH", "ANOMALY")   # unknown attack variant


def _safe_float(v: str) -> float | None:
    try:
        f = float(v)
        return None if f in (float("inf"), float("-inf")) else round(f, 4)
    except (ValueError, TypeError):
        return None


def _safe_int(v: str) -> int | None:
    try:
        return int(float(v))
    except (ValueError, TypeError):
        return None


def _build_ns_row(row: dict) -> dict:
    """Build a space/underscore-free key lookup for fallback column matching.

    Called once per row, shared across all _pick() calls for that row.
    Handles SourceIP, SrcIP, sourceip, and other compact naming variants.
    """
    ns: dict[str, str] = {}
    for k, v in row.items():
        ns_key = k.replace(" ", "").replace("_", "").replace("-", "")
        if ns_key not in ns:
            ns[ns_key] = v
    return ns


def _pick(row: dict, ns_row: dict, *keys: str) -> str:
    """Return the first non-whitespace value from candidate column names.

    Two-pass lookup:
      1. Exact match against normalised keys (strip + lower via _norm_keys).
      2. No-space / no-underscore / no-dash match via pre-built ns_row.
    """
    for k in keys:
        v = row.get(k, "")
        if isinstance(v, str):
            stripped = v.strip()
            if stripped:
                return stripped
        ns_k = k.replace(" ", "").replace("_", "").replace("-", "")
        v = ns_row.get(ns_k, "")
        if isinstance(v, str):
            stripped = v.strip()
            if stripped:
                return stripped
    return ""


# ── DDL ───────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cicids_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ingested_at   TEXT NOT NULL,
    src_ip        TEXT,
    dst_ip        TEXT,
    dst_port      INTEGER,
    protocol      INTEGER,
    label         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    category      TEXT NOT NULL,
    flow_duration REAL,
    flow_bytes_s  REAL,
    source_file   TEXT DEFAULT ''
)
"""
_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_cicids_label    ON cicids_events(label)",
    "CREATE INDEX IF NOT EXISTS idx_cicids_severity ON cicids_events(severity)",
    "CREATE INDEX IF NOT EXISTS idx_cicids_src_ip   ON cicids_events(src_ip)",
]
_INSERT = """
INSERT INTO cicids_events
    (ingested_at, src_ip, dst_ip, dst_port, protocol,
     label, severity, category, flow_duration, flow_bytes_s, source_file)
VALUES (?,?,?,?,?,?,?,?,?,?,?)
"""

# Exhaustive column aliases for CIC-IDS-2017 variants.
# After _norm_keys (strip + lowercase), then _build_ns_row (remove spaces/underscores/dashes).
# The two-pass lookup in _pick covers every realistic naming variant.
_SRC_IP_KEYS = (
    # Spaced variants (most common in UNB/Kaggle releases)
    "source ip", "src ip",
    # Underscored variants
    "source_ip", "src_ip",
    # Camel/compact variants — caught by ns_row fallback
    "sourceip", "srcip",
    # FlowMeter / alternative tool output
    "flow src ip", "flow_src_ip",
    "orig ip", "orig_ip",
    "local ip", "local_ip",
)
_DST_IP_KEYS = (
    "destination ip", "dst ip", "dest ip",
    "destination_ip", "dst_ip", "dest_ip",
    "destinationip", "dstip", "destip",
    "flow dst ip", "flow_dst_ip",
    "remote ip", "remote_ip",
)
_DST_PORT_KEYS = (
    "destination port", "dst port", "dest port",
    "destination_port", "dst_port", "dest_port",
    "destinationport", "dstport", "destport",
)

# ── Mock IPs for flow-only CSVs ────────────────────────────────────────────────
# CIC-IDS-2017 CSVs generated by CICFlowMeter often omit IP columns entirely.
# When no IP column is found we synthesise realistic-looking addresses so that:
#   • SOAR playbooks have a non-null target_ip to act on
#   • The AI report can produce specific analysis instead of "N/A" fallbacks
# Source IPs use RFC-5737 documentation ranges (non-routable, globally unique).
# Destination IPs use RFC-1918 private ranges (realistic internal victim hosts).

_MOCK_SRC: dict[str, str] = {
    "DoS":          "198.51.100.14",
    "DDoS":         "198.51.100.75",
    "PortScan":     "203.0.113.42",
    "Bot":          "198.51.100.100",
    "FTP-Patator":  "203.0.113.7",
    "SSH-Patator":  "203.0.113.8",
    "Web Attack":   "198.51.100.22",
    "Infiltration": "198.51.100.91",
    "Heartbleed":   "203.0.113.33",
}
_MOCK_DST: dict[str, str] = {
    "Web Attack":   "172.16.0.80",   # web/app server
    "Heartbleed":   "172.16.0.10",   # HTTPS endpoint
    "Patator":      "192.168.1.5",   # auth/SSH server
    "DoS":          "192.168.1.100", # targeted service host
    "DDoS":         "192.168.1.100",
    "Bot":          "192.168.1.200", # C2 callback target
}
_MOCK_SRC_DEFAULT = "198.51.100.43"
_MOCK_DST_DEFAULT = "10.0.1.55"


def _mock_src_ip(label: str) -> str:
    """Return a label-keyed RFC-5737 source IP for flow-only CSVs."""
    for key, ip in _MOCK_SRC.items():
        if key in label:
            return ip
    return _MOCK_SRC_DEFAULT


def _mock_dst_ip(label: str) -> str:
    """Return a label-keyed RFC-1918 destination IP for flow-only CSVs."""
    for key, ip in _MOCK_DST.items():
        if key in label:
            return ip
    return _MOCK_DST_DEFAULT


def _has_ip_columns(normalized_keys: list[str], ns_keys: set[str]) -> bool:
    """Return True if the CSV contains any recognisable IP address column."""
    spaced = {"source ip", "src ip", "destination ip", "dst ip", "dest ip",
              "source_ip", "src_ip", "destination_ip", "dst_ip", "dest_ip"}
    compact = {"sourceip", "srcip", "destinationip", "dstip", "destip",
               "origip", "remoteip", "localip"}
    return bool(
        spaced.intersection(normalized_keys)
        or compact.intersection(ns_keys)
    )


# ── Startup helper ─────────────────────────────────────────────────────────────

def ensure_cicids_tables(db_path: str) -> None:
    """Create cicids_events table and indexes if they don't already exist.

    Called at application startup so every API endpoint has a valid table
    to query even before the first CSV is uploaded.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(_CREATE_TABLE)
        for idx in _CREATE_INDEXES:
            conn.execute(idx)
        conn.commit()
    logger.debug("cicids_events table ensured at %s", db_path)


# ── Public API ────────────────────────────────────────────────────────────────

def ingest_cicids_to_db(path: Path, db_path: str) -> dict:
    """
    Parse a CIC-IDS-2017 CSV and bulk-insert into cicids_events.
    RAM usage stays flat regardless of file size (chunked reads + batch commits).
    Returns an IngestSummary dict.
    """
    path = Path(path)
    summary: dict = {
        "total_rows": 0,
        "inserted":   0,
        "skipped":    0,
        "by_label":   {},
        "by_severity":{},
        "source_file": path.name,
    }

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(_CREATE_TABLE)
        for idx in _CREATE_INDEXES:
            conn.execute(idx)
        conn.commit()

        now_iso = datetime.now(tz=timezone.utc).isoformat()
        chunk: list[tuple] = []

        # utf-8-sig strips the BOM automatically; errors="replace" handles any bad bytes
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            has_ip_cols: bool | None = None   # detected on first row
            for raw in reader:
                summary["total_rows"] += 1
                row    = _norm_keys(raw)
                ns_row = _build_ns_row(row)  # built once, shared across all _pick calls

                # ── First-row header inspection ───────────────────────────────
                if has_ip_cols is None:
                    all_keys = list(row.keys())
                    ns_keys  = set(ns_row.keys())
                    has_ip_cols = _has_ip_columns(all_keys, ns_keys)
                    logger.info(
                        "cicids_parser: CSV headers (%d cols): %s", len(all_keys), all_keys
                    )
                    if has_ip_cols:
                        logger.info("cicids_parser: IP columns detected — using real IPs")
                    else:
                        logger.warning(
                            "cicids_parser: No IP columns found in '%s'. "
                            "Substituting RFC-5737/RFC-1918 mock IPs so SOAR and AI "
                            "have non-null targets. Expected one of: 'Source IP', "
                            "'Src IP', 'Destination IP', 'Dst IP'.",
                            path.name,
                        )

                label = _pick(row, ns_row, "label")
                if not label:
                    summary["skipped"] += 1
                    continue

                severity, category = classify_label(label)

                # ── IP resolution ─────────────────────────────────────────────
                # Priority: real CSV value → mock (flow-only CSV) → None
                raw_src = _pick(row, ns_row, *_SRC_IP_KEYS)
                raw_dst = _pick(row, ns_row, *_DST_IP_KEYS)
                src_ip  = raw_src if raw_src else (_mock_src_ip(label) if not has_ip_cols else None)
                dst_ip  = raw_dst if raw_dst else (_mock_dst_ip(label) if not has_ip_cols else None)

                chunk.append((
                    now_iso,
                    src_ip,
                    dst_ip,
                    _safe_int(_pick(row, ns_row, *_DST_PORT_KEYS)),
                    _safe_int(_pick(row, ns_row, "protocol")),
                    label,
                    severity,
                    category,
                    _safe_float(_pick(row, ns_row, "flow duration", "flow_duration")),
                    _safe_float(_pick(row, ns_row, "flow bytes/s", "flow_bytes/s",
                                      "flow bytes per second", "flowbytess")),
                    path.name,
                ))

                summary["by_label"][label]       = summary["by_label"].get(label, 0) + 1
                summary["by_severity"][severity]  = summary["by_severity"].get(severity, 0) + 1

                if len(chunk) >= CHUNK_SIZE:
                    conn.executemany(_INSERT, chunk)
                    conn.commit()
                    summary["inserted"] += len(chunk)
                    chunk.clear()
                    logger.debug("cicids_parser: %d rows inserted", summary["inserted"])

        if chunk:
            conn.executemany(_INSERT, chunk)
            conn.commit()
            summary["inserted"] += len(chunk)

    logger.info(
        "cicids_parser: done — %d rows ingested from %s (%d skipped)",
        summary["inserted"], path.name, summary["skipped"],
    )
    return summary


def query_cicids_events(
    db_path: str,
    search:   str = "",
    severity: str = "",
    label:    str = "",
    limit:    int = 100,
    offset:   int = 0,
) -> list[dict]:
    """Paginated, filtered query over cicids_events."""
    if not Path(db_path).exists():
        return []
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            conditions: list[str] = []
            params: list = []

            if search:
                conditions.append("(src_ip LIKE ? OR dst_ip LIKE ? OR label LIKE ?)")
                like = f"%{search}%"
                params += [like, like, like]
            if severity:
                conditions.append("severity = ?")
                params.append(severity.upper())
            if label:
                conditions.append("label LIKE ?")
                params.append(f"%{label}%")

            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            params += [limit, offset]

            rows = cur.execute(
                f"SELECT id, ingested_at, src_ip, dst_ip, dst_port, protocol, "
                f"label, severity, category, flow_duration, flow_bytes_s, source_file "
                f"FROM cicids_events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            return [dict(r) for r in rows]
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            logger.debug("query_cicids_events: table not yet created — returning []")
        else:
            logger.error("query_cicids_events DB error: %s", exc)
        return []
    except Exception as exc:
        logger.error("query_cicids_events error: %s", exc)
        return []


def get_cicids_stats(db_path: str) -> dict:
    """Aggregate counts for the dashboard widgets."""
    empty = {"total": 0, "by_label": {}, "by_severity": {}}
    if not Path(db_path).exists():
        return empty
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            total = cur.execute("SELECT COUNT(*) FROM cicids_events").fetchone()[0]
            by_label = {
                r["label"]: r["cnt"]
                for r in cur.execute(
                    "SELECT label, COUNT(*) AS cnt FROM cicids_events "
                    "GROUP BY label ORDER BY cnt DESC"
                ).fetchall()
            }
            by_severity = {
                r["severity"]: r["cnt"]
                for r in cur.execute(
                    "SELECT severity, COUNT(*) AS cnt FROM cicids_events GROUP BY severity"
                ).fetchall()
            }
            return {"total": total, "by_label": by_label, "by_severity": by_severity}
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            logger.debug("get_cicids_stats: table not yet created — returning zeros")
        else:
            logger.error("get_cicids_stats DB error: %s", exc)
        return empty
    except Exception as exc:
        logger.error("get_cicids_stats error: %s", exc)
        return empty


def get_attack_summary_for_report(db_path: str, source_file: str = "") -> dict:
    """
    Build the attack_summary dict passed to generate_ir_report().
    Uses a single query with GROUP_CONCAT to avoid N+1 IP-sample lookups.
    """
    if not Path(db_path).exists():
        return {"total_events": 0, "attacks": [], "source_file": source_file}
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            where  = "WHERE source_file = ?" if source_file else ""
            params = [source_file] if source_file else []

            total = cur.execute(
                f"SELECT COUNT(*) FROM cicids_events {where}", params
            ).fetchone()[0]

            rows = cur.execute(
                f"""
                SELECT
                    label,
                    severity,
                    COUNT(*) AS cnt,
                    GROUP_CONCAT(DISTINCT src_ip) AS ips
                FROM cicids_events
                {where}
                GROUP BY label
                ORDER BY cnt DESC
                """,
                params,
            ).fetchall()

            attacks = []
            for r in rows:
                if r["label"].upper() == "BENIGN":
                    continue
                sample_ips = [ip for ip in (r["ips"] or "").split(",") if ip][:5]
                attacks.append({
                    "label":      r["label"],
                    "count":      r["cnt"],
                    "severity":   r["severity"],
                    "sample_ips": sample_ips,
                })

            return {"total_events": total, "attacks": attacks, "source_file": source_file, "time_range": {}}
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            logger.debug("get_attack_summary_for_report: table not yet created")
        else:
            logger.error("get_attack_summary_for_report DB error: %s", exc)
        return {"total_events": 0, "attacks": [], "source_file": source_file}
    except Exception as exc:
        logger.error("get_attack_summary_for_report error: %s", exc)
        return {"total_events": 0, "attacks": [], "source_file": source_file}
