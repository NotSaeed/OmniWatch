"""
OmniWatch BOTSv3 Parser
Streams a Splunk BOTSv3 JSON export file, dispatches each event to the correct
sourcetype handler, and bulk-inserts normalized events into the database.

BOTSv3 export format: one JSON object per line (newline-delimited JSON / NDJSON).
Each object has at minimum: _raw, sourcetype, _time.
"""

import json
import logging
import sqlite3
from collections import defaultdict
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ingestion.models import IngestSummary, NormalizedEvent
from ingestion.sourcetype_handlers import (
    http_stream,
    osquery,
    palo_alto,
    suricata,
    sysmon,
    windows_event,
    zeek,
)

logger = logging.getLogger(__name__)

# ── Sourcetype dispatch table ──────────────────────────────────────────────────
_HANDLERS: dict[str, Any] = {
    "suricata":        suricata,
    "sysmon":          sysmon,
    "xmlwineventlog":  windows_event,
    "wineventlog":     windows_event,
    "pan:traffic":     palo_alto,
    "pan:threat":      palo_alto,
    "stream:http":     http_stream,
    "bro:conn":        zeek,
    "zeek:conn":       zeek,
    "osquery":         osquery,
    "osquery:results": osquery,
}


def _normalise_sourcetype(st: str) -> str:
    """Map BOTSv3 sourcetype variants to canonical handler keys."""
    st = st.lower().strip()
    # Handle prefixed variants like "XmlWinEventLog:Security"
    for key in _HANDLERS:
        if st.startswith(key):
            return key
    return st


# ── File streaming ─────────────────────────────────────────────────────────────

def load_botsv3_file(path: str | Path) -> Iterator[dict]:
    """
    Stream JSON events from a BOTSv3 NDJSON export file.
    Skips malformed lines and yields valid dicts.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipped malformed JSON at line %d", lineno)


# ── Normalization ──────────────────────────────────────────────────────────────

def normalize_event(raw: dict) -> NormalizedEvent | None:
    """
    Dispatch a raw BOTSv3 event to the correct sourcetype handler.
    Returns a NormalizedEvent or None if no handler exists / parsing fails.
    """
    sourcetype = _normalise_sourcetype(raw.get("sourcetype", ""))
    handler    = _HANDLERS.get(sourcetype)
    if handler is None:
        return None
    return handler.parse(raw)


# ── Database ingestion ─────────────────────────────────────────────────────────

def ingest_botsv3_to_db(path: str | Path, db_path: str | Path) -> IngestSummary:
    """
    Parse a BOTSv3 export file and bulk-insert normalized events into SQLite.
    Skips duplicate event_ids (INSERT OR IGNORE).
    """
    counts: dict[str, int] = defaultdict(int)
    batch:  list[tuple]    = []
    total_parsed  = 0
    total_stored  = 0
    skipped       = 0
    BATCH_SIZE    = 500

    def _flush(conn: sqlite3.Connection) -> int:
        if not batch:
            return 0
        conn.executemany(
            """
            INSERT OR IGNORE INTO raw_events
              (event_id, timestamp, sourcetype, source_family,
               src_ip, dst_ip, dst_port, hostname, username,
               process_name, action, severity_hint, raw_text, extra_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            batch,
        )
        stored = len(batch)
        batch.clear()
        return stored

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")

        for raw in load_botsv3_file(path):
            event = normalize_event(raw)
            total_parsed += 1

            if event is None:
                skipped += 1
                continue

            import json as _json
            batch.append((
                event.event_id,
                event.timestamp.isoformat(),
                event.sourcetype,
                event.source_family,
                event.src_ip,
                event.dst_ip,
                event.dst_port,
                event.hostname,
                event.username,
                event.process_name,
                event.action,
                event.severity_hint,
                event.raw_text,
                _json.dumps(event.extra),
            ))
            counts[event.sourcetype] += 1

            if len(batch) >= BATCH_SIZE:
                total_stored += _flush(conn)

        total_stored += _flush(conn)
        conn.commit()

    logger.info("Ingested %d/%d events (%d skipped)", total_stored, total_parsed, skipped)
    return IngestSummary(
        total_parsed=total_parsed,
        total_stored=total_stored,
        by_sourcetype=dict(counts),
        skipped=skipped,
    )


def get_ingest_summary(events: list[NormalizedEvent]) -> IngestSummary:
    """Build a summary from an in-memory list of events (testing/preview use)."""
    counts: dict[str, int] = defaultdict(int)
    for e in events:
        counts[e.sourcetype] += 1
    return IngestSummary(
        total_parsed=len(events),
        total_stored=len(events),
        by_sourcetype=dict(counts),
        skipped=0,
    )
