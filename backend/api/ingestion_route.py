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
import os
import sqlite3
import tempfile
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
from services.trust_chain import build_chain, ensure_chain_table, verify_chain

logger = logging.getLogger(__name__)
router = APIRouter()

_CHUNK_ROWS      = 10_000
_PROGRESS_EVERY  = 50_000


# ── Startup helper ────────────────────────────────────────────────────────────

def init_pipeline_db(db_path: str) -> None:
    """Called from main.py lifespan — creates tables and enables WAL mode."""
    ensure_pipeline_tables(db_path)
    ensure_chain_table(db_path)


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

        # ── Stream to OS temp dir ─────────────────────────────────────────────
        # tempfile.mkstemp() uses %TEMP% on Windows and /tmp on Linux — a
        # separate filesystem from the app partition that is unlikely to be full.
        # The file is deleted by _run_pipeline's finally block when processing
        # completes, regardless of success or failure.
        try:
            fd, tmp_str = tempfile.mkstemp(suffix=".csv", prefix=f"omniwatch_{session_id}_")
            dest = Path(tmp_str)
        except Exception as exc:
            raise HTTPException(500, f"Cannot create temp file: {type(exc).__name__}: {exc}") from exc

        bytes_written = 0
        try:
            with os.fdopen(fd, "wb") as fh:
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
            ciso = {}

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
        # Always delete the temp CSV — it lives in the OS temp dir and is no
        # longer needed once the pipeline has finished (or failed).
        try:
            csv_path.unlink(missing_ok=True)
            logger.debug("Deleted temp CSV: %s", csv_path)
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
    rows_total    = 0
    alerts_total  = 0
    batch_idx     = 0
    chain_tip: str | None  = None
    root_hash: str | None  = None
    last_broadcast = 0
    read_error     = False   # set True if the chunk reader breaks early (not clean EOF)
    baseliner      = DDSketchBaseliner()  # accumulates bytes/s across all chunks
    loda_baseliner = LodaBaseliner()      # accumulates features for session-level LODA model

    try:
        import pandas as pd
    except ImportError as exc:
        logger.error("pandas is required — pip install pandas")
        raise RuntimeError("pandas is required — pip install pandas") from exc

    def _open_reader():
        return pd.read_csv(
            csv_path,
            chunksize=_CHUNK_ROWS,
            dtype=str,
            encoding="utf-8-sig",
            encoding_errors="replace",   # replace bad bytes (0xbd etc.) instead of crashing
            on_bad_lines="skip",
            low_memory=False,
        )

    try:
        reader = await loop.run_in_executor(None, _open_reader)
    except Exception as exc:
        logger.error("Failed to open CSV reader for %s:\n%s",
                     csv_path.name, traceback.format_exc())
        raise RuntimeError(f"Cannot read CSV: {exc}") from exc

    while True:
        def _next_chunk():
            try:
                return next(reader)
            except StopIteration:
                return None

        try:
            chunk = await loop.run_in_executor(None, _next_chunk)
        except Exception:
            logger.error("Error reading CSV chunk after %d rows:\n%s",
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

        # Update session every chunk so polling reflects real progress
        try:
            update_session(db, session_id,
                           rows_processed=rows_total,
                           alerts_found=alerts_total)
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

    await loop.run_in_executor(None, loda_baseliner.fit)
    loda_payload = loda_baseliner.payload()
    if loda_payload:
        import json as _json
        _lp = _json.loads(loda_payload)
        logger.info(
            "LODA fitted: k=%d, n_bins=%d, threshold_fp10=%d",
            _lp["k"], _lp["n_bins"], _lp["anomaly_threshold_fp10"],
        )
    else:
        logger.info("LODA payload unavailable (too few rows or numpy missing)")

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
    """Read only the header row to detect schema — O(1) memory cost."""
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
            header = fh.readline()
        headers = [h.strip() for h in header.split(",")]
        return detect_schema(headers)
    except Exception:
        logger.warning("_peek_schema failed for %s — defaulting to generic:\n%s",
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
        "ciso_summary":             json.loads(row[10]) if row[10] else None,
        "ddsketch_threshold_fp14": row[11] or 0,
        "loda_payload":            json.loads(row[12]) if row[12] else None,
    }


@router.get("/api/pipeline/alerts")
async def get_pipeline_alerts(
    session_id: str | None = Query(None),
    severity:   str | None = Query(None),
    mitre:      str | None = Query(None),
    search:     str | None = Query(None),
    limit:      int        = Query(100, le=500),
    offset:     int        = Query(0),
):
    """Paginated query over telemetry_alerts with filtering."""
    db     = get_db_path()
    sql    = (
        "SELECT id, session_id, ingested_at, dataset_type, "
        "source_ip, dest_ip, dest_port, protocol, label, severity, "
        "mitre_technique, mitre_name, bytes_total, chain_hash "
        "FROM telemetry_alerts WHERE 1=1"
    )
    params: list = []

    if session_id:
        sql += " AND session_id = ?"
        params.append(session_id)
    if severity:
        sql += " AND severity = ?"
        params.append(severity.upper())
    if mitre:
        sql += " AND mitre_technique LIKE ?"
        params.append(f"{mitre}%")
    if search:
        sql += " AND (source_ip LIKE ? OR dest_ip LIKE ? OR label LIKE ?)"
        params += [f"%{search}%", f"%{search}%", f"%{search}%"]

    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    try:
        rows = sqlite3.connect(db, timeout=10.0).execute(sql, params).fetchall()
    except Exception as exc:
        logger.error("get_pipeline_alerts DB error:\n%s", traceback.format_exc())
        raise HTTPException(500, f"Database error: {exc}") from exc

    return [
        {
            "id":              r[0],
            "session_id":      r[1],
            "ingested_at":     r[2],
            "dataset_type":    r[3],
            "source_ip":       r[4],
            "dest_ip":         r[5],
            "dest_port":       r[6],
            "protocol":        r[7],
            "label":           r[8],
            "severity":        r[9],
            "mitre_technique": r[10],
            "mitre_name":      r[11],
            "bytes_total":     r[12],
            "chain_hash":      r[13],
        }
        for r in rows
    ]


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
