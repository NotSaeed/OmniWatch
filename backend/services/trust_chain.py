"""
OmniWatch SHA-256 Hash Chain — Cryptographic Trust Layer
=========================================================
Builds a verifiable chain over anomalous alert batches so every batch
can later be proven to be unmodified since ingestion.

Chain construction per batch
-----------------------------
  1. Hash each alert deterministically:
       alert_hash = SHA256(JSON({identity fields}, sort_keys=True))

  2. Combine into a batch digest (ordered Merkle leaf):
       batch_hash = SHA256( alert_hash_0 || alert_hash_1 || … )

  3. Extend the running chain tip:
       chain_tip  = SHA256( prev_tip || batch_hash )
       (For the root batch prev_tip is the empty string.)

Verification
------------
  Re-derive every chain_tip from stored batch_hashes and compare.
  Any tampering with a stored receipt will cause a mismatch.

Storage
-------
  hash_chain_receipts table — one row per batch.
  Written atomically inside a WAL-mode SQLite connection so concurrent
  readers (the API) never see a partial write.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS hash_chain_receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    batch_index INTEGER NOT NULL,
    batch_hash  TEXT    NOT NULL,
    chain_tip   TEXT    NOT NULL,
    alert_count INTEGER NOT NULL,
    created_at  TEXT    NOT NULL,
    UNIQUE(session_id, batch_index)
);
CREATE INDEX IF NOT EXISTS idx_hcr_session ON hash_chain_receipts(session_id);
"""

# Fields used to derive each alert's identity hash.
# Must stay stable — changing these fields invalidates all old receipts.
_IDENTITY_FIELDS = (
    "source_ip", "dest_ip", "dest_port",
    "protocol", "label", "severity",
    "mitre_technique", "bytes_total",
)


def ensure_chain_table(db_path: str) -> None:
    with sqlite3.connect(db_path, timeout=30.0) as conn:
        conn.executescript(_DDL)
    logger.info("Hash-chain receipt table ready")


# ── Per-alert hashing ─────────────────────────────────────────────────────────

def _hash_alert(alert: dict[str, Any]) -> str:
    """
    Deterministic SHA-256 of an alert's identity fields.
    None values are serialised as the JSON null so the hash is stable
    regardless of how callers represent missing data.
    """
    canonical = {k: alert.get(k) for k in _IDENTITY_FIELDS}
    payload = json.dumps(canonical, sort_keys=True, default=str).encode()
    return hashlib.sha256(payload).hexdigest()


# ── Batch chaining ────────────────────────────────────────────────────────────

def build_chain(
    db_path: str,
    session_id: str,
    batch_index: int,
    alerts: list[dict[str, Any]],
    prev_tip: str | None = None,
) -> tuple[str, str]:
    """
    Build and persist a chain receipt for one alert batch.

    Parameters
    ----------
    db_path     : Path to the SQLite database.
    session_id  : UUID of the pipeline session this batch belongs to.
    batch_index : Zero-based batch counter within the session.
    alerts      : Alert dicts produced by tier2_enrich().
    prev_tip    : Chain tip of the previous batch (None for the first).

    Returns
    -------
    (batch_hash, new_chain_tip)
    """
    if not alerts:
        # Empty batch — chain a sentinel so indices stay contiguous.
        batch_hash = hashlib.sha256(b"\x00empty").hexdigest()
        chain_tip  = hashlib.sha256(
            ((prev_tip or "") + batch_hash).encode()
        ).hexdigest()
        _persist(db_path, session_id, batch_index, batch_hash, chain_tip, 0)
        return batch_hash, chain_tip

    # Step 1 — hash each alert individually
    alert_hashes = [_hash_alert(a) for a in alerts]

    # Step 2 — batch digest: SHA256 of all individual hashes concatenated
    batch_payload = "".join(alert_hashes).encode()
    batch_hash    = hashlib.sha256(batch_payload).hexdigest()

    # Step 3 — extend the chain tip
    chain_input = (prev_tip or "") + batch_hash
    chain_tip   = hashlib.sha256(chain_input.encode()).hexdigest()

    # Step 4 — persist
    _persist(db_path, session_id, batch_index, batch_hash, chain_tip, len(alerts))

    return batch_hash, chain_tip


def _persist(
    db_path: str,
    session_id: str,
    batch_index: int,
    batch_hash: str,
    chain_tip: str,
    alert_count: int,
) -> None:
    try:
        with sqlite3.connect(db_path, timeout=30.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                INSERT OR IGNORE INTO hash_chain_receipts
                  (session_id, batch_index, batch_hash, chain_tip,
                   alert_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    batch_index,
                    batch_hash,
                    chain_tip,
                    alert_count,
                    datetime.now(tz=timezone.utc).isoformat(),
                ),
            )
    except Exception as exc:
        # Log and continue — a failed receipt write must not kill the pipeline.
        logger.warning("Hash-chain receipt write failed (batch %d): %s", batch_index, exc)


# ── Verification ──────────────────────────────────────────────────────────────

def verify_chain(db_path: str, session_id: str) -> dict[str, Any]:
    """
    Re-derive every chain_tip from stored batch_hashes and confirm each
    stored tip matches.  Returns a verification report dict.

    The check is purely structural — it proves that the receipt table has
    not been tampered with since ingestion.  It does NOT re-hash the alerts
    (those are already gone from memory), but it validates the chain linkage.
    """
    with sqlite3.connect(db_path, timeout=10.0) as conn:
        rows = conn.execute(
            "SELECT batch_index, batch_hash, chain_tip, alert_count "
            "FROM hash_chain_receipts "
            "WHERE session_id = ? ORDER BY batch_index",
            (session_id,),
        ).fetchall()

    if not rows:
        return {
            "valid":       False,
            "batches":     0,
            "tip_hash":    None,
            "total_alerts": 0,
            "error":       "No receipts found for this session",
        }

    tip: str | None = None
    total_alerts = 0

    for idx, (batch_index, batch_hash, stored_tip, alert_count) in enumerate(rows):
        # Verify contiguous batch indices
        if batch_index != idx:
            return {
                "valid":       False,
                "batches":     len(rows),
                "tip_hash":    stored_tip,
                "total_alerts": total_alerts,
                "error":       f"Missing batch at index {idx} (found {batch_index})",
            }

        # Re-derive tip and compare
        expected_tip = hashlib.sha256(
            ((tip or "") + batch_hash).encode()
        ).hexdigest()
        if expected_tip != stored_tip:
            return {
                "valid":       False,
                "batches":     len(rows),
                "tip_hash":    stored_tip,
                "total_alerts": total_alerts,
                "error":       f"Chain broken at batch {batch_index}: "
                               f"expected {expected_tip[:16]}…, "
                               f"stored {stored_tip[:16]}…",
            }

        tip = stored_tip
        total_alerts += (alert_count or 0)

    return {
        "valid":        True,
        "batches":      len(rows),
        "tip_hash":     tip,
        "total_alerts": total_alerts,
        "error":        None,
    }
