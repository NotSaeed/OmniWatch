"""
OmniWatch BOTSv3 CSV Parser
Streams a Splunk/CSV export of BOTSv3 data, normalizes headers,
and bulk-inserts normalized events into the database.
"""

import csv
import logging
import sqlite3
import sys

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2147483647)

from collections import defaultdict
from pathlib import Path
from typing import Any

from ingestion.models import IngestSummary, NormalizedEvent
from ingestion.botsv3_parser import normalize_event as normalize_json_event

logger = logging.getLogger(__name__)

# Common Splunk/CSV aliases to map to canonical field names
_FIELD_MAP = {
    "dest":           "DestinationIp",
    "dest_ip":        "DestinationIp",
    "src":            "SourceIp",
    "src_ip":         "SourceIp",
    "dest_port":      "DestinationPort",
    "src_port":       "SourcePort",
    "user":           "User",
    "host":           "Computer",
    "image":          "Image",
    "command":        "CommandLine",
    "cmdline":        "CommandLine",
    "process":        "ProcessName",
    "eventid":        "EventID",
}

def _remap_row(row: dict[str, str]) -> dict[str, Any]:
    """Normalize CSV row keys to match expects of sourcetype handlers."""
    new_row: dict[str, Any] = {}
    for k, v in row.items():
        if not k: continue
        clean_k = k.strip().lower().lstrip("_")
        
        # Keep original but also add canonical alias if found
        new_row[k] = v
        if clean_k in _FIELD_MAP:
             new_row[_FIELD_MAP[clean_k]] = v
        
        # Handle _time -> UtcTime for Sysmon etc
        if clean_k == "time":
            new_row["UtcTime"] = v
            new_row["_time"] = v
            
    return new_row

def ingest_botsv3_csv_to_db(path: str | Path, db_path: str | Path) -> IngestSummary:
    """
    Parse a BOTSv3 CSV file and bulk-insert normalized events into SQLite.
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
    
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")

    with sqlite3.connect(str(db_path), timeout=60.0) as conn:
        conn.execute("PRAGMA journal_mode=WAL")

        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_parsed += 1
                
                # Normalize row for handlers
                mapped_row = _remap_row(row)
                
                # Reuse the JSON normalization logic (which takes a dict)
                event = normalize_json_event(mapped_row)
                
                if event is None:
                    # If we can't find a specific handler, we still try to store it as a generic event
                    # if it has a sourcetype and _raw/raw_text
                    st = mapped_row.get("sourcetype")
                    if not st and mapped_row.get("protocol_stack"):
                        st = "stream:generic"
                        
                    if st:
                        from datetime import datetime, timezone
                        import uuid
                        ts_str = mapped_row.get("_time") or mapped_row.get("time") or mapped_row.get("timestamp")
                        try:
                            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(tz=timezone.utc)
                        except:
                            ts = datetime.now(tz=timezone.utc)
                            
                        event = NormalizedEvent(
                            event_id=str(uuid.uuid4()),
                            timestamp=ts,
                            sourcetype=st,
                            source_family="network",
                            raw_text=mapped_row.get("_raw") or str(row),
                            src_ip=mapped_row.get("SourceIp"),
                            dst_ip=mapped_row.get("DestinationIp"),
                            hostname=mapped_row.get("Computer") or mapped_row.get("host"),
                        )
                    else:
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
                
                # Log progress every 50k rows
                if total_parsed % 50000 == 0:
                    logger.info("BOTSv3 CSV Progress: %d rows parsed...", total_parsed)
                    if total_stored % 5000 == 0:
                        logger.info(f"Ingested {total_stored} rows so far... Still processing file.")

            # Flush the remaining rows in the final batch
            total_stored += _flush(conn)
        conn.commit()

    logger.info("Ingested %d/%d CSV events (%d skipped)", total_stored, total_parsed, skipped)
    return IngestSummary(
        total_parsed=total_parsed,
        total_stored=total_stored,
        by_sourcetype=dict(counts),
        skipped=skipped,
    )
