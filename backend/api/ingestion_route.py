"""
OmniWatch Unified Telemetry Ingestion Router
=============================================

POST /api/upload-telemetry
    Streams a large CSV to disk (never fully buffered in RAM), detects schema,
    then runs the Tier 1 → 2 → 3 analysis pipeline as a background task.
    Sends real-time WebSocket messages at every stage transition.
    Returns immediately with {session_id} so the frontend can poll for progress.

GET  /api/pipeline/session/{session_id}
    Returns current session status: rows processed, alerts found, CISO summary.

GET  /api/pipeline/alerts
    Query the unified telemetry_alerts table with filtering & pagination.

GET  /api/pipeline/verify/{session_id}
    Verify the SHA-256 hash chain for a completed session.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, UploadFile

from api.websocket import manager
from db.database import get_db_path
from ingestion.analysis_engine import (
    compute_ciso_summary,
    create_session,
    DDSketchBaseliner,
    detect_schema,
    ensure_pipeline_tables,
    LodaBaseliner,
    insert_alerts_batch,
    normalize_chunk,
    run_tier1_combined,
    tier2_enrich,
    time_window_correlate,
    update_session,
)
from llm.ollama_client import get_client
from services.trust_chain import build_chain, ensure_chain_table, verify_chain

logger = logging.getLogger(__name__)
router = APIRouter()

_CHUNK_ROWS      = 10_000   # ~300 ms/chunk → ~3 Hz progress updates on 2M-row files
_PROGRESS_EVERY  = 10_000   # broadcast every chunk (matches chunk size)

# ── Upload staging directory ──────────────────────────────────────────────────
# Routed to D: drive so the OS system partition (C:) is never touched.
# The directory is created automatically on first use.
# Lifecycle: CSV is deleted immediately after Polars streams it to Parquet;
# Parquet is deleted after all chunks are processed.  _run_pipeline's finally
# block is the last-resort safety net for both files.
_UPLOADS_DIR = Path("D:/OmniWatch_Uploads")


# ── Startup helper ────────────────────────────────────────────────────────────

def _migrate_triggered_rules(db: str) -> None:
    """Fire-once migration: adds triggered_rules column if not yet present."""
    try:
        with sqlite3.connect(db) as _c:
            _c.execute(
                "ALTER TABLE telemetry_alerts ADD COLUMN triggered_rules INTEGER NOT NULL DEFAULT 0"
            )
    except Exception:
        pass  # Column already exists — ALTER TABLE is idempotent via try/except


_RULE_BIT_NAMES = ["DDSketch", "LODA", "CUSUM", "Port", "Volume", "Label-KW", "Time-Win"]

def _dominant_rule_str(bitmask: int) -> str:
    for bit in [1, 0, 3, 4, 5, 2, 6]:
        if bitmask & (1 << bit):
            return _RULE_BIT_NAMES[bit]
    return "Heuristic"


def init_pipeline_db(db_path: str) -> None:
    """Called from main.py lifespan — creates tables and enables WAL mode."""
    ensure_pipeline_tables(db_path)
    ensure_chain_table(db_path)
    _migrate_triggered_rules(db_path)


# ── Upload endpoint ───────────────────────────────────────────────────────────

@router.post("/api/upload-telemetry")
async def upload_telemetry(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """
    Accept a CSV file of any size.

    Streams the upload to the OS temp dir, then immediately returns a 200
    with {session_id}.  The analysis pipeline runs as a FastAPI BackgroundTask
    — it starts only AFTER the HTTP response has been fully sent, guaranteeing
    the client never waits more than a few seconds (disk-write time only).
    """
    fname = (file.filename or "upload.csv").strip()
    # Log at the very top so the terminal shows the request was received,
    # even if something later silently fails.
    logger.info("▶ upload_telemetry START: file='%s' content_type='%s'",
                fname, file.content_type)

    if not fname.lower().endswith(".csv"):
        raise HTTPException(400, "Only .csv files are accepted")

    # ── Outer catch-all ───────────────────────────────────────────────────────
    # Any exception not handled by an inner try/except surfaces here with a
    # full traceback in the server log and an explicit 500 body so the browser
    # displays the real Python error instead of staying stuck on "Uploading…".
    try:
        session_id = str(uuid.uuid4())

        try:
            db = get_db_path()
        except Exception as exc:
            raise HTTPException(500, f"Cannot resolve database path: {exc}") from exc

        # ── Stream upload to D: drive staging directory ───────────────────────
        # Keeps system partition (C:) untouched. The CSV is converted to Parquet
        # via streaming (never fully loaded into RAM) then deleted immediately.
        try:
            _UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
            dest = _UPLOADS_DIR / f"omniwatch_{session_id}.csv"
        except Exception as exc:
            raise HTTPException(
                500,
                f"Cannot create D:/OmniWatch_Uploads — ensure drive D: is mounted "
                f"and writable. Detail: {type(exc).__name__}: {exc}",
            ) from exc

        bytes_written = 0
        try:
            with dest.open("wb") as fh:
                while True:
                    chunk = await file.read(512 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
                    bytes_written += len(chunk)
        except Exception as exc:
            logger.error("Stream write failed for '%s':\n%s", fname, traceback.format_exc())
            dest.unlink(missing_ok=True)
            raise HTTPException(500, f"Upload failed during streaming: {type(exc).__name__}: {exc}") from exc

        logger.info("✓ Streamed %d bytes → %s", bytes_written, dest.name)

        # ── Persist session record ────────────────────────────────────────────
        # Run in executor so _db_retry's time.sleep() never blocks the event loop.
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, create_session, db, session_id, fname)
        except Exception as exc:
            logger.error("create_session failed for '%s':\n%s", fname, traceback.format_exc())
            dest.unlink(missing_ok=True)
            raise HTTPException(500, f"Database error creating session: {type(exc).__name__}: {exc}") from exc

        logger.info("✓ Session created: %s", session_id)

        # ── Fire background pipeline ──────────────────────────────────────────
        # BackgroundTasks.add_task() is guaranteed to execute AFTER the HTTP
        # response has been fully sent — unlike asyncio.create_task() which
        # could theoretically run before the response is flushed.
        # _run_pipeline's finally block owns temp-file deletion; it must NOT
        # be deleted here before the background task has read the file.
        background_tasks.add_task(_run_pipeline, session_id, dest, fname, db)
        logger.info("✓ Pipeline registered as background task for session %s", session_id)

        return {
            "session_id": session_id,
            "filename":   fname,
            "bytes":      bytes_written,
            "status":     "processing",
            "message":    "File received — analysis pipeline started",
        }

    except HTTPException:
        raise  # Re-raise HTTP errors produced by inner blocks unchanged

    except Exception as exc:
        # Any other unexpected error — log it in full and return 500 so the
        # frontend receives the real error message instead of hanging.
        tb = traceback.format_exc()
        logger.error(
            "upload_telemetry UNHANDLED EXCEPTION for '%s' [%s: %s]\n%s",
            fname, type(exc).__name__, exc, tb,
        )
        raise HTTPException(
            status_code=500,
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc


# ── Polars numeric coercion ───────────────────────────────────────────────────

def _coerce_polars_numerics(df: object) -> object:
    """
    Defensively cast known numeric columns to Float64 before converting to pandas.

    Polars reads all CSV columns as Utf8 when infer_schema_length=0, which is
    required so messy BOTSv3/Splunk headers don't abort the scan.  Without this
    step, numeric fields arrive in pandas as Python str objects.  A cell that is
    an empty string or garbled text becomes 0.0 via pd.to_numeric(errors="coerce")
    .fillna(0), so the LODA feature matrix ends up all-zero and both LODA and
    the Z-score baseline silently produce 0 alerts.

    Strategy for each logical field:
      • Build a list of aliases that exist in this frame (order = preference).
      • Cast each to Float64 with strict=False (bad strings → null, not crash).
      • pl.coalesce() picks the first non-null value across aliases.
      • fill_null(0.0) so downstream .to_numpy() never encounters pd.NA.
      • Write the result back under the first alias name that was present;
        normalize_chunk will rename it to the canonical field name later.
    """
    try:
        import polars as pl
    except ImportError:
        return df

    # Hard guard: if a LazyFrame was passed by mistake, collect it now.
    # In Polars 1.x, LazyFrame.columns exists and LazyFrame.with_columns() works,
    # but it returns another LazyFrame — which then crashes on .to_pandas().
    # Collecting here prevents that silent escalation.
    if isinstance(df, pl.LazyFrame):
        logger.warning(
            "_coerce_polars_numerics: received a LazyFrame — collecting eagerly. "
            "Caller should pass a collected pl.DataFrame to avoid redundant I/O."
        )
        df = df.collect()

    existing = set(df.columns)

    # (canonical_hint, ordered_aliases, null_fill)
    # null_fill=1.0 for mathematical columns (bytes/packets/duration) so that
    # downstream LODA log/division never receives 0. Port fallback stays 0.0.
    _COALESCE_GROUPS: list[tuple[str, list[str], float]] = [
        ("bytes_out", [
            "bytes_out", "bytes", "out_bytes", "orig_bytes",
            "out", "sent_bytes", "req_bytes", "stream:bytes",
        ], 1.0),
        ("bytes_in", [
            "bytes_in", "resp_bytes", "recv_bytes", "in",  # resp_bytes = Zeek-in-BOTSv3
        ], 1.0),
        ("dest_port", [
            "dest_port", "dst_port", "dpt", "dport",   # ← added dport (BOTSv3 short alias)
            "id.resp_p",
        ], 0.0),
        ("src_port", [
            "src_port", "sport", "spt", "id.orig_p",
        ], 0.0),
        ("packets", [
            "packets", "pkt_count", "pkts", "packet_count",
            "orig_pkts", "resp_pkts", "total fwd packets", "stream:packets",
        ], 1.0),
        ("flow_duration", [
            "flow_duration", "duration", "stream:duration",
        ], 1.0),
    ]

    def _safe_coalesce(
        df_cols: set,
        aliases: list,
        null_fill: float,
    ) -> "pl.Expr | None":
        """
        Return a coalesced Float64 expression for whichever aliases are present
        in this batch, or None if none exist.  Casting each column individually
        with strict=False before coalescing prevents SchemaError when one alias
        is String and another already happened to be parsed as numeric.
        """
        present = [a for a in aliases if a in df_cols]
        if not present:
            return None
        cast_exprs = [pl.col(a).cast(pl.Float64, strict=False) for a in present]
        return pl.coalesce(cast_exprs + [pl.lit(null_fill, dtype=pl.Float64)])

    ops: list = []
    for _canonical, aliases, _null_fill in _COALESCE_GROUPS:
        expr = _safe_coalesce(existing, aliases, _null_fill)
        if expr is None:
            continue
        # Alias back onto the first alias that is actually present so that
        # normalize_chunk's rename map can find the column by its raw name.
        target = next(a for a in aliases if a in existing)
        ops.append(expr.alias(target))

    if ops:
        try:
            df = df.with_columns(ops)
        except Exception as _wce:
            # A BOTSv3 batch can have edge-case column states that pass the
            # existence check above but fail inside the Polars expression
            # engine (e.g. duplicate alias names after Splunk header munging).
            # Log and return the uncoerced frame rather than crashing the batch.
            logger.warning(
                "_coerce_polars_numerics: with_columns failed (%s: %s) — "
                "returning frame without numeric coercion for this batch.",
                type(_wce).__name__, _wce,
            )

    return df


# ── Background pipeline ───────────────────────────────────────────────────────

async def _run_pipeline(
    session_id: str,
    csv_path: Path,
    filename: str,
    db: str,
) -> None:
    """
    Full async pipeline orchestrator.

    Stages
    ------
    A  Schema detection (reads first line only — O(1) memory)
    B  Chunked analysis:
         • Time-window per-IP correlation
         • Tier 1 heuristic filter ∪ Isolation Forest ∪ Z-score baselining
         • Tier 2 MITRE enrichment (label > Z-score > port > volume > protocol)
         • SHA-256 hash chain (inline per chunk)
         • DB insertion with WAL + lock-retry
    C  CISO summary computation (single DB scan after all chunks)

    WebSocket messages
    ------------------
    pipeline_stage     — stage name change
    pipeline_progress  — row/alert counts (every _PROGRESS_EVERY rows)
    pipeline_complete  — final payload with CISO summary
    pipeline_error     — error string + traceback excerpt
    """
    loop = asyncio.get_running_loop()

    async def _ws(payload: dict) -> None:
        try:
            await manager.broadcast({"session_id": session_id, **payload})
        except Exception:
            logger.debug("WS broadcast failed (non-fatal): %s", traceback.format_exc())

    try:
        # ── A: Schema detection ───────────────────────────────────────────────
        await _ws({"type": "pipeline_stage", "stage": "normalizing",
                   "message": f"Detecting schema for {filename}…"})

        try:
            schema = await loop.run_in_executor(None, _peek_schema, csv_path)
        except Exception as exc:
            logger.error("Schema detection failed for %s:\n%s", filename, traceback.format_exc())
            schema = "generic"

        update_session(db, session_id, dataset_type=schema, status="running")

        await _ws({"type": "pipeline_stage", "stage": "normalizing",
                   "message": f"Schema → {schema.upper()} — normalizing fields",
                   "dataset_type": schema})

        # ── B: Chunked analysis ───────────────────────────────────────────────
        await _ws({"type": "pipeline_stage", "stage": "tier1",
                   "message": "Tier 1: heuristic + LODA + Z-score…"})

        result = await _process_chunks(session_id, csv_path, schema, db, loop, _ws)

        update_session(
            db, session_id,
            rows_processed=result["rows"],
            alerts_found=result["alerts"],
            chain_root_hash=result["root_hash"],
            chain_tip_hash=result["tip"],
            ddsketch_threshold_fp14=result["ddsketch_fp14"],
            loda_payload=result["loda_payload"],
        )

        # If the chunk reader broke mid-file (e.g. pandas parse error), surface it
        # as an error so the UI shows the partial row count rather than "complete".
        if result["read_error"]:
            update_session(db, session_id, status="error")
            await _ws({
                "type":    "pipeline_error",
                "error":   f"CSV read stopped after {result['rows']:,} rows — see server log for details",
                "traceback": "",
            })
            logger.error(
                "Pipeline aborted mid-file — session=%s rows_processed=%d",
                session_id, result["rows"],
            )
            return

        # ── C: CISO summary ───────────────────────────────────────────────────
        await _ws({"type": "pipeline_stage", "stage": "tier2",
                   "message": "Computing MITRE coverage & CISO metrics…"})

        try:
            ciso = await loop.run_in_executor(None, compute_ciso_summary, db, session_id)
        except Exception:
            logger.error("compute_ciso_summary failed:\n%s", traceback.format_exc())
            ciso = {
                "total_alerts": 0, "by_severity": {}, "top_techniques": [],
                "top_attacker_ips": [], "top_labels": [],
                "analyst_hours_saved": 0, "cost_avoided_usd": 0,
            }

        update_session(
            db, session_id,
            status="complete",
            completed_at=datetime.now(tz=timezone.utc).isoformat(),
            ciso_summary=json.dumps(ciso),
        )

        await _ws({
            "type":           "pipeline_complete",
            "filename":       filename,
            "dataset_type":   schema,
            "rows_processed": result["rows"],
            "alerts_found":   result["alerts"],
            "chain_tip":      result["tip"],
            "root_hash":      result["root_hash"],
            "ciso":           ciso,
        })
        logger.info(
            "Pipeline done — session=%s schema=%s rows=%d alerts=%d",
            session_id, schema, result["rows"], result["alerts"],
        )

    except Exception as exc:
        tb = traceback.format_exc()
        logger.error("Pipeline FATAL error for session %s:\n%s", session_id, tb)
        try:
            update_session(db, session_id, status="error")
        except Exception:
            pass
        await _ws({"type": "pipeline_error", "error": str(exc),
                   "traceback": tb[-800:]})  # last 800 chars — safe to expose in dev

    finally:
        # ── Last-resort cleanup — runs even if _process_chunks raised ─────────
        # Primary deletion happens inside _process_chunks; these calls are no-ops
        # in the happy path but prevent orphaned files on unexpected failures.
        for _stale in [
            csv_path,
            _UPLOADS_DIR / f"omniwatch_{session_id}.parquet",
        ]:
            try:
                _stale.unlink(missing_ok=True)
            except Exception:
                pass


async def _process_chunks(
    session_id: str,
    csv_path: Path,
    schema: str,
    db: str,
    loop: asyncio.AbstractEventLoop,
    ws: any,
) -> dict:
    """
    Iterate the CSV in _CHUNK_ROWS chunks.  Each chunk is processed in the
    thread pool so the event loop stays responsive for WS message flushing.

    Per-chunk pipeline:
      1. normalize_chunk        — column rename to canonical names
      2. time_window_correlate  — per-IP rolling connection count
      3. run_tier1_combined     — heuristic ∪ LODA ∪ Z-score
      4. tier2_enrich           — MITRE derivation (Z-score aware)
      5. build_chain            — SHA-256 batch receipt
      6. insert_alerts_batch    — WAL-mode write with lock-retry
    """
    rows_total     = 0
    alerts_total   = 0
    batch_idx      = 0
    chain_tip: str | None = None
    root_hash: str | None = None
    last_broadcast = 0
    last_db_write  = 0      # debounce update_session — only flush when alerts arrive or at boundary
    read_error     = False  # set True if the chunk reader breaks early (not clean EOF)
    baseliner      = DDSketchBaseliner()  # accumulates bytes/s across all chunks
    loda_baseliner = LodaBaseliner()      # accumulates features for session-level LODA model

    try:
        import pandas as pd
    except ImportError as exc:
        logger.error("pandas is required — pip install pandas")
        raise RuntimeError("pandas is required — pip install pandas") from exc

    # ── RAM-safe reader strategy ──────────────────────────────────────────────
    #
    # SOLUTION — pl.read_csv_batched():
    #   Opens the CSV once and yields explicit DataFrames of batch_size rows.
    #   Only one batch lives in RAM at a time (≈ 50–150 MB for 100K rows).
    #   Unlike scan_csv().sink_parquet() (Polars streaming engine), the batched
    #   reader does NOT have an internal row-count ceiling and processes every
    #   row in files of any size, including 2M+ row BOTSv3 exports.
    #   The CSV file is held open until all batches are exhausted; cleanup
    #   happens at the end of this function and in _run_pipeline's finally block.
    #
    # Fallback: pandas chunked reader for environments without Polars.
    #
    _batched_reader = None   # pl.BatchedCsvReader once opened
    _use_polars = False

    try:
        import polars as pl

        def _open_batched_reader():
            return pl.read_csv_batched(
                str(csv_path),
                batch_size=_CHUNK_ROWS,      # exactly _CHUNK_ROWS rows per batch
                infer_schema_length=0,       # ← ALL columns read as Utf8/String;
                                             #   prevents SchemaError from type
                                             #   inference flipping mid-file on
                                             #   BOTSv3's wildly heterogeneous rows.
                ignore_errors=True,          # coerce bad cells to null, not crash
                encoding="utf8-lossy",       # replace invalid bytes (BOTSv3 has them)
                truncate_ragged_lines=True,  # extra columns silently dropped
                eol_char="\n",              # force Unix line-endings; avoids
                                             # parser stalling on bare \r mid-field
            )

        _batched_reader = await loop.run_in_executor(None, _open_batched_reader)
        _use_polars = True
        logger.info("Polars batched CSV reader opened: %s", csv_path.name)

    except ImportError:
        logger.info("polars not installed — using pandas chunked reader "
                    "(pip install polars for 3-5× speedup and OOM protection)")
    except Exception:
        logger.warning("Polars batched reader failed for %s — falling back to pandas:\n%s",
                       csv_path.name, traceback.format_exc())
        _batched_reader = None

    # ── Pandas fallback reader ────────────────────────────────────────────────
    reader = None
    if not _use_polars:
        def _open_reader():
            return pd.read_csv(
                csv_path,
                chunksize=_CHUNK_ROWS,
                dtype=str,
                engine="c",
                encoding="utf-8-sig",
                encoding_errors="replace",   # replace bad bytes (0xbd etc.)
                on_bad_lines="skip",
                low_memory=False,
                memory_map=True,             # OS mmap for large files
            )
        try:
            reader = await loop.run_in_executor(None, _open_reader)
        except Exception as exc:
            logger.error("Failed to open CSV reader for %s:\n%s",
                         csv_path.name, traceback.format_exc())
            raise RuntimeError(f"Cannot read CSV: {exc}") from exc

    # ── Fault-isolated Polars batch reader ───────────────────────────────────
    # Defined once before the loop so the closure captures _batched_reader
    # exactly once and the function object is not recreated every iteration.
    #
    # Two-layer isolation:
    #   Layer 1 — next_batches(1):  if this raises, the reader is broken; we
    #             re-raise so the outer except can set read_error=True and break.
    #   Layer 2 — coerce + to_pandas: if this raises (e.g. SchemaError from a
    #             single pathological batch), we fall back to raw string pandas
    #             conversion so no rows are lost and the loop continues.
    import re as _re_pl
    _PL_JUNK_RE = _re_pl.compile(r'[\x00-\x1f\x7f﻿�]+')

    def _sanitize_pl_col_names(df_pl: object) -> object:
        renamed = {c: _PL_JUNK_RE.sub('', c).strip().lower() for c in df_pl.columns}
        return df_pl.rename(renamed)

    def _read_next_batch(_r=_batched_reader):
        # Layer 1 — advance the batched reader
        try:
            batches = _r.next_batches(1)
        except Exception as _re:
            logger.error(
                "_read_next_batch: next_batches() raised %s: %s — "
                "reader state is undefined; aborting Polars path.",
                type(_re).__name__, _re,
            )
            raise  # propagates → outer except → read_error=True

        if not batches:
            return None  # clean EOF

        # Layer 2 — numeric coercion + pandas conversion
        try:
            df_pl = _sanitize_pl_col_names(batches[0])
            df_pl = _coerce_polars_numerics(df_pl)
            return df_pl.to_pandas()
        except Exception as _ce:
            logger.warning(
                "_read_next_batch: coerce/pandas failed (%s: %s) — "
                "returning raw string batch so rows are not lost.",
                type(_ce).__name__, _ce,
            )
            # Raw fallback: all columns as Python str; normalize_chunk will
            # handle pd.to_numeric() coercion downstream.
            return batches[0].to_pandas()

    # ── Main chunk loop ───────────────────────────────────────────────────────
    while True:
        if _use_polars:
            try:
                chunk = await loop.run_in_executor(None, _read_next_batch)
            except Exception:
                logger.error("Polars batch read failed after %d rows:\n%s",
                             rows_total, traceback.format_exc())
                read_error = True
                break
            if chunk is None:
                break

        else:
            # Pandas fallback: standard chunked file iterator
            def _next_chunk():
                try:
                    return next(reader)
                except StopIteration:
                    return None

            try:
                chunk = await loop.run_in_executor(None, _next_chunk)
            except Exception:
                logger.error("CSV chunk read failed after %d rows:\n%s",
                             rows_total, traceback.format_exc())
                read_error = True
                break

            if chunk is None:
                break

        rows_total += len(chunk)

        # Capture loop-local copies for the executor closure
        _chunk       = chunk
        _schema      = schema
        _session_id  = session_id
        _db          = db
        _batch_idx   = batch_idx
        _chain_tip   = chain_tip

        _baseliner      = baseliner       # explicit capture for the executor closure
        _loda_baseliner = loda_baseliner  # explicit capture for the executor closure

        def _process():
            try:
                norm      = normalize_chunk(_chunk, _schema)
                _baseliner.update(norm)       # accumulate bytes/s into DDSketch
                _loda_baseliner.update(norm)  # accumulate features into LODA baseliner
                norm      = time_window_correlate(norm, window="1min")
                flagged, baselines = run_tier1_combined(norm, _schema)

                if flagged.empty:
                    return [], _chain_tip, None

                alerts = tier2_enrich(flagged, baselines=baselines)
                if not alerts:
                    return [], _chain_tip, None

                bh, new_tip = build_chain(_db, _session_id, _batch_idx, alerts, _chain_tip)
                insert_alerts_batch(_db, _session_id, _schema, alerts)
                return alerts, new_tip, bh

            except Exception:
                logger.error(
                    "Chunk processing error (session=%s batch=%d):\n%s",
                    _session_id, _batch_idx, traceback.format_exc(),
                )
                return [], _chain_tip, None  # non-fatal: skip bad chunk

        try:
            batch_alerts, chain_tip, _ = await loop.run_in_executor(None, _process)
        except Exception:
            logger.error("Executor error (session=%s):\n%s",
                         session_id, traceback.format_exc())
            batch_alerts = []

        if batch_alerts:
            if batch_idx == 0:
                root_hash = chain_tip
            alerts_total += len(batch_alerts)
            batch_idx    += 1

        # Flush session row to DB only when new alerts arrived or at the progress boundary.
        # This cuts SQLite WAL flushes from one-per-chunk down to one-per-alert-batch.
        should_flush = bool(batch_alerts) or (rows_total - last_db_write >= _PROGRESS_EVERY)
        if should_flush:
            try:
                update_session(db, session_id,
                               rows_processed=rows_total,
                               alerts_found=alerts_total)
                last_db_write = rows_total
            except Exception:
                logger.warning("update_session failed (non-fatal): %s",
                               traceback.format_exc())

        # Broadcast progress every _PROGRESS_EVERY rows
        if rows_total - last_broadcast >= _PROGRESS_EVERY:
            last_broadcast = rows_total
            await ws({
                "type":           "pipeline_progress",
                "stage":          "tier1",
                "rows_processed": rows_total,
                "alerts_found":   alerts_total,
            })

        # Yield so the event loop can flush pending WS frames
        await asyncio.sleep(0)

    ddsketch_fp14 = baseliner.threshold_fp14()
    logger.info(
        "DDSketch p99 threshold: T=%d (n=%d samples, p99≈%.0f bytes/s)",
        ddsketch_fp14, baseliner.sample_count,
        ddsketch_fp14 / (1 << 14) if ddsketch_fp14 > 0 else 0,
    )
    if ddsketch_fp14 == 0:
        logger.warning(
            "DDSketch threshold is ZERO (n=%d samples) — volumetric baselining is BLIND. "
            "The bytes_out / bytes column was empty or all-zero across all chunks. "
            "Check that the dataset has a byte-count field and the schema map covers it.",
            baseliner.sample_count,
        )

    await loop.run_in_executor(None, loda_baseliner.fit)
    loda_payload = loda_baseliner.payload()
    if loda_payload:
        import json as _json
        _lp = _json.loads(loda_payload)
        logger.info(
            "LODA fitted: k=%d, n_bins=%d, threshold_fp10=%d",
            _lp["k"], _lp["n_bins"], _lp["anomaly_threshold_fp10"],
        )
        if _lp["anomaly_threshold_fp10"] == 0:
            logger.warning(
                "LODA anomaly_threshold_fp10 is ZERO — LODA is BLIND. "
                "The training feature matrix was all-zero (bytes/packets not extracted). "
                "Verify schema mapping for this dataset type.",
            )
    else:
        logger.warning(
            "LODA payload unavailable — model not trained "
            "(too few rows, numpy missing, or all-zero feature matrix). "
            "LODA anomaly detection is DISABLED for this session."
        )

    # ── CSV cleanup ──────────────────────────────────────────────────────────
    # With read_csv_batched the CSV is held open during processing, so delete
    # it here (primary path). _run_pipeline's finally block is the safety net.
    if _use_polars and csv_path.exists():
        try:
            csv_mb = csv_path.stat().st_size / 1_000_000
            csv_path.unlink()
            logger.info("✓ CSV freed: %.1f MB reclaimed from D: drive", csv_mb)
        except Exception:
            logger.warning("Could not delete CSV %s:\n%s",
                           csv_path.name, traceback.format_exc())

    return {
        "rows":          rows_total,
        "alerts":        alerts_total,
        "tip":           chain_tip or "",
        "root_hash":     root_hash or "",
        "ddsketch_fp14": ddsketch_fp14,
        "loda_payload":  loda_payload,
        "read_error":    read_error,
    }


# ── Schema peeking (runs in executor) ─────────────────────────────────────────

def _peek_schema(path: Path) -> str:
    """
    Read only the column headers of the CSV to detect schema — O(1) memory.

    Primary path: pl.read_csv(n_rows=1) — uses Polars' actual CSV parser so
    quoted field names, BOM markers, and non-ASCII headers are handled correctly.
    The resulting DataFrame is never used for data; only .columns is read.

    Fallback: plain Python line-read + comma-split, used when Polars is absent
    or raises (e.g. file encoding the parser cannot handle at all).
    """
    # Primary: Polars header parser — never accesses .columns on a LazyFrame
    # because read_csv() (not scan_csv()) returns an eager DataFrame immediately.
    try:
        import polars as pl
        headers = pl.read_csv(
            str(path),
            n_rows=1,                # read exactly 1 data row — O(1) for any file size
            infer_schema_length=0,   # all columns as Utf8 — mirrors main scan_csv()
            ignore_errors=True,
            encoding="utf8-lossy",
            truncate_ragged_lines=True,
        ).columns                    # .columns on an eager DataFrame — always valid
        schema = detect_schema(headers)
        logger.debug(
            "_peek_schema (Polars): %d headers detected, schema=%s  first_5=%s",
            len(headers), schema, headers[:5],
        )
        return schema
    except Exception:
        logger.debug("_peek_schema Polars path failed — falling back to Python:\n%s",
                     traceback.format_exc())

    # Fallback: Python file I/O + naive comma-split
    # Safe for well-formed CSVs but misparses quoted field names containing commas.
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
            header = fh.readline()
        headers = [h.strip().strip('"') for h in header.split(",")]
        schema = detect_schema(headers)
        logger.debug(
            "_peek_schema (Python fallback): %d headers, schema=%s",
            len(headers), schema,
        )
        return schema
    except Exception:
        logger.warning("_peek_schema failed entirely for %s — defaulting to generic:\n%s",
                       path.name, traceback.format_exc())
        return "generic"


# ── Query endpoints ───────────────────────────────────────────────────────────

@router.get("/api/sessions/{session_id}/status")
async def get_session_status(session_id: str):
    """
    Lightweight polling endpoint for the frontend progress bar.

    Returns only the three fields needed to drive the UI — avoids the heavier
    CISO-summary join that /api/pipeline/session/{id} performs on every poll.
    Called every ~2.5 s by the frontend setInterval loop.
    """
    db = get_db_path()
    try:
        row = sqlite3.connect(db, timeout=10.0).execute(
            "SELECT status, rows_processed, alerts_found, ciso_summary, chain_tip_hash "
            "FROM pipeline_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    except Exception as exc:
        logger.error("get_session_status DB error:\n%s", traceback.format_exc())
        raise HTTPException(500, f"Database error: {exc}") from exc

    if not row:
        raise HTTPException(404, f"Session {session_id} not found")

    result: dict = {
        "session_id":     session_id,
        "status":         row[0],
        "rows_processed": row[1] or 0,
        "alerts_found":   row[2] or 0,
    }
    # On completion, surface the CISO summary and chain tip so the frontend
    # can update the global state in a single poll tick without an extra fetch.
    if row[0] == "complete":
        result["ciso_summary"]   = json.loads(row[3]) if row[3] else None
        result["chain_tip_hash"] = row[4]
    return result

@router.get("/api/pipeline/session/{session_id}")
async def get_pipeline_session(session_id: str):
    """Poll this endpoint to track pipeline progress."""
    db = get_db_path()
    try:
        row = sqlite3.connect(db, timeout=10.0).execute(
            "SELECT session_id, filename, dataset_type, started_at, completed_at, "
            "status, rows_processed, alerts_found, "
            "chain_root_hash, chain_tip_hash, ciso_summary, "
            "ddsketch_threshold_fp14, loda_payload "
            "FROM pipeline_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    except Exception as exc:
        logger.error("get_pipeline_session DB error:\n%s", traceback.format_exc())
        raise HTTPException(500, f"Database error: {exc}") from exc

    if not row:
        raise HTTPException(404, f"Session {session_id} not found")

    ciso = json.loads(row[10]) if row[10] else None

    # If the stored summary has empty top_attacker_ips (e.g. from an older
    # pipeline run where source_ip was NULL), recompute live from the DB so
    # the Top Threat Sources panel is always populated for complete sessions.
    if ciso is not None and row[5] == "complete" and not ciso.get("top_attacker_ips"):
        try:
            fresh = compute_ciso_summary(db, session_id)
            if fresh.get("top_attacker_ips"):
                ciso["top_attacker_ips"] = fresh["top_attacker_ips"]
            if fresh.get("top_techniques") and not ciso.get("top_techniques"):
                ciso["top_techniques"] = fresh["top_techniques"]
            if fresh.get("top_labels") and not ciso.get("top_labels"):
                ciso["top_labels"] = fresh["top_labels"]
        except Exception:
            logger.warning("ciso_summary refresh failed (non-fatal):\n%s", traceback.format_exc())

    # Count alerts that have not yet received a STARK proof (chain_hash still
    # holds the raw input hash, not a zkVM-verified proof hash).  Exposed as
    # pending_proofs so the dashboard Hero KPI can show an amber indicator
    # during the 15–32 s proof window after the analyst initiates verification.
    try:
        pending_proofs = sqlite3.connect(db, timeout=10.0).execute(
            "SELECT COUNT(*) FROM telemetry_alerts "
            "WHERE session_id = ? AND severity IN ('CRITICAL','HIGH','MEDIUM') "
            "AND zk_status != 'verified'",
            (session_id,),
        ).fetchone()[0]
    except Exception:
        pending_proofs = 0

    return {
        "session_id":               row[0],
        "filename":                 row[1],
        "dataset_type":             row[2],
        "started_at":               row[3],
        "completed_at":             row[4],
        "status":                   row[5],
        "rows_processed":           row[6] or 0,
        "alerts_found":             row[7] or 0,
        "chain_root_hash":          row[8],
        "chain_tip_hash":           row[9],
        "ciso_summary":             ciso,
        "ddsketch_threshold_fp14": row[11] or 0,
        "loda_payload":            json.loads(row[12]) if row[12] else None,
        "pending_proofs":           pending_proofs,
    }


@router.get("/api/pipeline/alerts")
async def get_pipeline_alerts(
    session_id: str | None = Query(None),
    severity:   str | None = Query(None),
    mitre:      str | None = Query(None),
    source_ip:  str | None = Query(None),
    dest_ip:    str | None = Query(None),
    dest_port:  str | None = Query(None),
    label:      str | None = Query(None),
    search:     str | None = Query(None),
    limit:      int        = Query(100, le=500),
    offset:     int        = Query(0),
):
    """Paginated query over telemetry_alerts with filtering.

    Facet params (AND-combined):
      source_ip  — LIKE '%value%' partial match (subnet search: "192.168.")
      dest_ip    — LIKE '%value%' partial match
      dest_port  — exact integer match
      label      — LIKE '%value%' partial match
      mitre      — prefix match LIKE 'value%' (T1071 matches T1071.001)
      severity   — exact match (CRITICAL / HIGH / MEDIUM / LOW / INFO)
      search     — OR search across source_ip, dest_ip, label (legacy unified box)
    """
    db     = get_db_path()
    filter_sql = ""
    params: list = []

    if session_id:
        filter_sql += " AND session_id = ?"
        params.append(session_id)
    if severity:
        filter_sql += " AND severity = ?"
        params.append(severity.upper())
    if mitre:
        filter_sql += " AND mitre_technique LIKE ?"
        params.append(f"{mitre}%")
    if source_ip:
        filter_sql += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if dest_ip:
        filter_sql += " AND dest_ip LIKE ?"
        params.append(f"%{dest_ip}%")
    if dest_port:
        try:
            filter_sql += " AND dest_port = ?"
            params.append(int(dest_port))
        except (ValueError, TypeError):
            pass
    if label:
        filter_sql += " AND label LIKE ?"
        params.append(f"%{label}%")
    if search:
        filter_sql += " AND (source_ip LIKE ? OR dest_ip LIKE ? OR label LIKE ? OR mitre_name LIKE ?)"
        params += [f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"]

    try:
        conn = sqlite3.connect(db, timeout=10.0)
        
        count_sql = "SELECT COUNT(*) FROM telemetry_alerts WHERE 1=1" + filter_sql
        total_filtered = conn.execute(count_sql, params).fetchone()[0]

        sql = (
            "SELECT id, session_id, ingested_at, dataset_type, "
            "source_ip, src_port, dest_ip, dest_port, protocol, label, severity, "
            "mitre_technique, mitre_name, bytes_total, chain_hash, "
            "z_score_bytes, z_score_pkts, raw_features "
            "FROM telemetry_alerts WHERE 1=1"
        ) + filter_sql + " ORDER BY id DESC LIMIT ? OFFSET ?"
        
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
    except Exception as exc:
        logger.error("get_pipeline_alerts DB error:\n%s", traceback.format_exc())
        raise HTTPException(500, f"Database error: {exc}") from exc

    return {
        "data": [
            {
                "id":              r[0],
                "session_id":      r[1],
                "ingested_at":     r[2],
                "dataset_type":    r[3],
                "source_ip":       r[4],
                "src_port":        r[5],
                "dest_ip":         r[6],
                "dest_port":       r[7],
                "protocol":        r[8],
                "label":           r[9],
                "severity":        r[10],
                "mitre_technique": r[11],
                "mitre_name":      r[12],
                "bytes_total":     r[13],
                "chain_hash":      r[14],
                "z_score_bytes":   r[15],
                "z_score_pkts":    r[16],
                "raw_features":    r[17],
            }
            for r in rows
        ],
        "total_filtered": total_filtered
    }


@router.get("/api/pipeline/top-ips")
async def get_pipeline_top_ips(
    session_id: str,
    limit: int = Query(10, le=20),
):
    """
    Live top source IPs for a session, ranked by alert count.

    Queries telemetry_alerts directly — always fresh, bypasses the stale
    ciso_summary cached at pipeline completion.  Primary query filters for
    threat severity (CRITICAL/HIGH/MEDIUM); falls back to any non-null
    source_ip if no threat rows have IPs populated.
    """
    db   = get_db_path()
    loop = asyncio.get_running_loop()

    def _query() -> list[dict]:
        with sqlite3.connect(db, timeout=10.0) as conn:
            rows = conn.execute(
                """
                SELECT source_ip,
                       COUNT(*) AS cnt,
                       MAX(triggered_rules) AS top_rules
                FROM telemetry_alerts
                WHERE session_id = ?
                  AND source_ip IS NOT NULL
                  AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                  AND LOWER(COALESCE(label, '')) NOT IN (
                      'benign', 'normal', 'background', 'legitimate', 'unknown'
                  )
                GROUP BY source_ip
                ORDER BY cnt DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
            if not rows:
                rows = conn.execute(
                    """
                    SELECT source_ip,
                           COUNT(*) AS cnt,
                           MAX(triggered_rules) AS top_rules
                    FROM telemetry_alerts
                    WHERE session_id = ? AND source_ip IS NOT NULL
                    GROUP BY source_ip
                    ORDER BY cnt DESC
                    LIMIT ?
                    """,
                    (session_id, limit),
                ).fetchall()
        return [{"ip": r[0], "count": r[1], "dominant_rule": _dominant_rule_str(r[2] or 0)} for r in rows]

    return await loop.run_in_executor(None, _query)


@router.get("/api/pipeline/mitre-stats")
async def get_pipeline_mitre_stats(session_id: str):
    """
    Return real MITRE technique counts for an active pipeline session.
    Unlike the static label-derived heatmap, this queries actual mitre_technique
    values stored per alert so the frontend shows exactly what detectors mapped.
    """
    db   = get_db_path()
    loop = asyncio.get_running_loop()

    def _query() -> list[dict]:
        with sqlite3.connect(db, timeout=10.0) as conn:
            rows = conn.execute(
                """
                SELECT mitre_technique, mitre_name, COUNT(*) AS cnt
                FROM telemetry_alerts
                WHERE session_id = ?
                  AND mitre_technique IS NOT NULL
                  AND mitre_technique != ''
                GROUP BY mitre_technique
                ORDER BY cnt DESC
                """,
                (session_id,),
            ).fetchall()
        return [
            {"technique_id": r[0], "name": r[1] or r[0], "count": r[2]}
            for r in rows
        ]

    return await loop.run_in_executor(None, _query)


_SOAR_PLAYBOOKS = {
    "CRITICAL": ("P0 — Block & Isolate",  "block_ip"),
    "HIGH":     ("P1 — Flag & Alert",     "flag_traffic"),
    "MEDIUM":   ("P2 — Monitor & Log",    "monitor_traffic"),
}


@router.get("/api/pipeline/soar-feed")
async def get_pipeline_soar_feed(
    session_id: str,
    limit: int = Query(50, le=200),
):
    """
    Synthetic SOAR feed for a pipeline session — maps CRITICAL/HIGH/MEDIUM
    alerts to realistic playbook execution entries.  The Playbooks page merges
    these with real cicids_playbook_log rows so the feed is always populated.
    """
    db   = get_db_path()
    loop = asyncio.get_running_loop()

    def _query() -> list[dict]:
        with sqlite3.connect(db, timeout=10.0) as conn:
            rows = conn.execute(
                """
                SELECT id, ingested_at, dataset_type, source_ip, dest_ip,
                       dest_port, label, severity, mitre_technique, mitre_name,
                       bytes_total, protocol
                FROM telemetry_alerts
                WHERE session_id = ?
                  AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                  AND LOWER(COALESCE(label, '')) NOT IN (
                      'benign', 'normal', 'background', 'legitimate', 'unknown'
                  )
                ORDER BY
                  CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END,
                  id DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()

        entries = []
        for r in rows:
            (rid, ingested_at, dataset_type, source_ip, dest_ip, dest_port,
             label, severity, mitre_technique, mitre_name, bytes_total, protocol) = r

            sev = severity or "MEDIUM"
            playbook_name, action = _SOAR_PLAYBOOKS.get(sev, ("P2 — Monitor & Log", "monitor_traffic"))

            detail_parts = []
            if mitre_name:      detail_parts.append(f"MITRE: {mitre_name}")
            if bytes_total:     detail_parts.append(f"{bytes_total // 1024} KB")
            if protocol:        detail_parts.append(str(protocol))
            if mitre_technique: detail_parts.append(mitre_technique)

            entries.append({
                "id":            -(rid),
                "executed_at":   ingested_at,
                "playbook_name": f"{playbook_name} (Simulated)",
                "action":        action,
                "status":        "SIMULATED",
                "target_ip":     source_ip or dest_ip,
                "target_port":   dest_port,
                "label":         label or "Unknown",
                "severity":      sev,
                "source_file":   dataset_type or "pipeline",
                "action_detail": " · ".join(detail_parts) if detail_parts else "N/A",
            })
        return entries

    return await loop.run_in_executor(None, _query)


@router.post("/api/pipeline/prove/{alert_id}")
async def prove_pipeline_alert(alert_id: int):
    """
    Return a cryptographic commitment for a pipeline telemetry_alert so the
    Trust Chain FIDO2 signing ceremony can proceed without a live edge bincode blob.

    The commitment is the alert's chain_hash (a SHA-256 link in the session's
    tamper-proof hash chain) encoded as standard base64.  The FIDO2 ceremony
    treats this as an opaque receipt — the same signing path used for edge records.
    """
    import base64
    import os

    # ZK Bypass
    if os.getenv("DEV_MODE_ZK_BYPASS", "False").lower() == "true":
        logger.warning("ZK Bypass active: mocking STARK proof for pipeline alert %d", alert_id)
        return {"success": True, "receipt_b64": "MOCK_DEV_RECEIPT_12345"}

    db = get_db_path()
    try:
        row = sqlite3.connect(db, timeout=10.0).execute(
            "SELECT chain_hash, label, severity FROM telemetry_alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
    except Exception as exc:
        raise HTTPException(500, f"Database error: {exc}") from exc

    if not row:
        raise HTTPException(404, f"Alert {alert_id} not found")

    chain_hash, label, severity = row
    if not chain_hash:
        raise HTTPException(
            400,
            "Alert has no chain hash — session may still be processing. "
            "Wait for status=complete then retry.",
        )

    try:
        receipt_b64 = base64.b64encode(bytes.fromhex(chain_hash)).decode("ascii")
    except ValueError:
        # chain_hash stored as raw hex string — fall back to direct encode
        receipt_b64 = base64.b64encode(chain_hash.encode("utf-8")).decode("ascii")

    return {"success": True, "receipt_b64": receipt_b64}


@router.post("/api/pipeline/analyze")
async def analyze_pipeline_session(
    session_id: str = Query(...),
    severity:   str | None = Query(None),
    mitre:      str | None = Query(None),
    source_ip:  str | None = Query(None),
    dest_ip:    str | None = Query(None),
    dest_port:  str | None = Query(None),
    label:      str | None = Query(None),
    search:     str | None = Query(None),
):
    """Generate a Phi-3 AI analysis summary for a pipeline session."""
    db = get_db_path()
    
    filter_sql = " AND session_id = ?"
    params: list = [session_id]

    if severity:
        filter_sql += " AND severity = ?"
        params.append(severity.upper())
    if mitre:
        filter_sql += " AND mitre_technique LIKE ?"
        params.append(f"{mitre}%")
    if source_ip:
        filter_sql += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if dest_ip:
        filter_sql += " AND dest_ip LIKE ?"
        params.append(f"%{dest_ip}%")
    if dest_port:
        try:
            filter_sql += " AND dest_port = ?"
            params.append(int(dest_port))
        except (ValueError, TypeError):
            pass
    if label:
        filter_sql += " AND label LIKE ?"
        params.append(f"%{label}%")
    if search:
        filter_sql += " AND (source_ip LIKE ? OR dest_ip LIKE ? OR label LIKE ? OR mitre_name LIKE ?)"
        params += [f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"]

    try:
        conn = sqlite3.connect(db, timeout=10.0)
        
        count_sql = "SELECT COUNT(*) FROM telemetry_alerts WHERE 1=1" + filter_sql
        alerts_analyzed = conn.execute(count_sql, params).fetchone()[0]

        sql = (
            "SELECT label, severity, mitre_technique, mitre_name, z_score_bytes, z_score_pkts "
            "FROM telemetry_alerts WHERE 1=1" + filter_sql + " "
            "ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
            "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, "
            "z_score_bytes DESC LIMIT 20"
        )
        rows = conn.execute(sql, params).fetchall()
        session_row = conn.execute(
            "SELECT filename, dataset_type, rows_processed, alerts_found, ciso_summary "
            "FROM pipeline_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    except Exception as exc:
        logger.error("analyze_session DB error:\n%s", traceback.format_exc())
        raise HTTPException(500, f"Database error: {exc}") from exc

    if not session_row:
        raise HTTPException(404, f"Session {session_id} not found")

    filename, dataset_type, rows_processed, alerts_found, ciso_json = session_row

    alerts_text = "\n".join(
        "- [{}] {} | MITRE: {} | Z-score: {}".format(
            r[1], r[0], r[3] or r[2] or "Unknown",
            "{:.2f}".format(r[4]) if r[4] is not None else "N/A",
        )
        for r in rows
    ) or "(no alerts)"

    prompt = (
        "You are a SOC analyst reviewing a network telemetry pipeline session.\n\n"
        "**Session:** {} ({})\n"
        "**Rows processed:** {:,}\n"
        "**Filtered Alerts Found:** {:,}\n\n"
        "**Top alerts (by severity and anomaly score):**\n{}\n\n"
        "Provide a concise executive summary (3–5 bullet points) covering:\n"
        "1. The most critical threats detected\n"
        "2. Key MITRE ATT&CK techniques observed\n"
        "3. Recommended immediate actions\n\n"
        "Format in Markdown."
    ).format(filename, dataset_type or "unknown", rows_processed or 0, alerts_analyzed or 0, alerts_text)

    _SYSTEM = (
        "You are a cybersecurity AI assistant helping SOC analysts triage network threats. "
        "Be concise, factual, and actionable. Avoid speculation."
    )

    try:
        client = get_client()
        report = await client.generate_report(prompt, _SYSTEM)
        return {"report": report, "ai_generated": True, "session_id": session_id, "alerts_analyzed": len(rows)}
    except Exception:
        by_sev: dict[str, int] = {}
        for r in rows:
            by_sev[r[1]] = by_sev.get(r[1], 0) + 1
        top_labels = list({r[0] for r in rows})[:5]
        top_mitre  = list({r[3] or r[2] for r in rows if r[3] or r[2]})[:3]
        report = (
            "## Heuristic Session Analysis\n\n"
            "**Dataset:** {} · {:,} flows · {:,} alerts\n\n"
            "### Key Findings\n"
            "- **{} Critical** and **{} High** severity alerts detected\n"
            "- Top attack patterns: {}\n"
            "- MITRE techniques observed: {}\n\n"
            "### Recommended Actions\n"
            "1. Review and triage CRITICAL alerts immediately\n"
            "2. Cross-reference techniques with MITRE ATT&CK framework\n"
            "3. Enable Autonomous Breach Containment (ABC) for high-confidence threats\n\n"
            "*Phi-3 unavailable — Ollama offline. This summary is heuristic only.*"
        ).format(
            filename, rows_processed or 0, alerts_found or 0,
            by_sev.get("CRITICAL", 0), by_sev.get("HIGH", 0),
            ", ".join(top_labels) or "None",
            ", ".join(top_mitre) or "None mapped",
        )
        return {"report": report, "ai_generated": False, "session_id": session_id, "alerts_analyzed": len(rows)}


@router.get("/api/pipeline/verify/{session_id}")
async def verify_session_chain(session_id: str):
    """Cryptographically verify the SHA-256 hash chain for a completed session."""
    db = get_db_path()
    return {"session_id": session_id, **verify_chain(db, session_id)}


@router.get("/api/pipeline/sessions")
async def list_pipeline_sessions(limit: int = Query(20, le=100)):
    """List recent pipeline sessions (most recent first)."""
    db = get_db_path()
    try:
        rows = sqlite3.connect(db, timeout=10.0).execute(
            "SELECT session_id, filename, dataset_type, started_at, completed_at, "
            "status, rows_processed, alerts_found "
            "FROM pipeline_sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    except Exception as exc:
        logger.error("list_pipeline_sessions DB error:\n%s", traceback.format_exc())
        raise HTTPException(500, f"Database error: {exc}") from exc

    return [
        {
            "session_id":     r[0],
            "filename":       r[1],
            "dataset_type":   r[2],
            "started_at":     r[3],
            "completed_at":   r[4],
            "status":         r[5],
            "rows_processed": r[6] or 0,
            "alerts_found":   r[7] or 0,
        }
        for r in rows
    ]


@router.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a single pipeline session and all its telemetry alerts."""
    db = get_db_path()
    try:
        conn = sqlite3.connect(db, timeout=10.0)
        alerts_deleted = conn.execute(
            "DELETE FROM telemetry_alerts WHERE session_id = ?", (session_id,)
        ).rowcount
        sess_deleted = conn.execute(
            "DELETE FROM pipeline_sessions WHERE session_id = ?", (session_id,)
        ).rowcount
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.error("delete_session error: %s", exc)
        raise HTTPException(500, f"Delete failed: {exc}") from exc

    if sess_deleted == 0:
        raise HTTPException(404, f"Session {session_id} not found")

    return {
        "status":       "deleted",
        "session_id":   session_id,
        "rows_deleted": alerts_deleted + sess_deleted,
    }
