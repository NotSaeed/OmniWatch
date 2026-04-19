"""
Folder monitor — watches data/monitor/ for new CSV files and auto-triggers
CIC-IDS-2017 ingestion.  Uses the watchdog library (thread-based) bridged to
the main asyncio event loop via run_coroutine_threadsafe.
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Shared state (read by GET /api/monitor/status) ───────────────────────────

_state: dict = {
    "active":              False,
    "watch_path":          "",
    "files_processed":     0,
    "last_processed_file": None,
    "last_processed_at":   None,
}

_observer = None
_loop: Optional[asyncio.AbstractEventLoop] = None


def get_status() -> dict:
    return {
        "active":              _state["active"],
        "watch_path":          _state["watch_path"],
        "files_processed":     _state["files_processed"],
        "last_processed_file": _state["last_processed_file"],
        "last_processed_at":   (
            _state["last_processed_at"].isoformat()
            if _state["last_processed_at"] else None
        ),
    }


# ── Lifecycle ─────────────────────────────────────────────────────────────────

def start_monitor(watch_path: Path, event_loop: asyncio.AbstractEventLoop) -> None:
    """
    Start the watchdog observer in a background thread.
    Must be called after the asyncio event loop is running so that
    run_coroutine_threadsafe has a live loop to schedule coroutines into.
    """
    global _observer, _loop

    # Idempotent — do not start a second observer if already running
    if _state["active"] and _observer is not None:
        logger.debug("Folder monitor already active — ignoring duplicate start_monitor() call")
        return

    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        logger.warning(
            "watchdog package not installed — folder monitor disabled. "
            "Run: pip install watchdog"
        )
        return

    watch_path.mkdir(parents=True, exist_ok=True)
    _loop = event_loop
    _state["watch_path"] = str(watch_path)

    class _CsvHandler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            path = Path(event.src_path)
            if path.suffix.lower() != ".csv":
                return
            logger.info("Monitor: new CSV detected — %s", path.name)
            if _loop and not _loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    _handle_new_file(path), _loop
                )

    _observer = Observer()
    _observer.schedule(_CsvHandler(), str(watch_path), recursive=False)
    _observer.start()
    _state["active"] = True
    logger.info("Folder monitor active — watching: %s", watch_path)


def stop_monitor() -> None:
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()
        _observer = None
    _state["active"] = False
    logger.info("Folder monitor stopped")


# ── Ingestion trigger ──────────────────────────────────────────────────────────

async def _handle_new_file(path: Path) -> None:
    """
    Called from the watchdog thread via run_coroutine_threadsafe.
    Broadcasts a detection event, waits briefly for the OS to finish
    writing the file, then runs CIC-IDS-2017 ingestion.
    """
    from api.websocket import manager

    await manager.broadcast({
        "type":     "monitor_file_detected",
        "filename": path.name,
        "path":     str(path),
    })

    # Give OS time to finish writing large files before we open them
    await asyncio.sleep(3)

    if not path.exists():
        logger.warning("Monitor: file vanished before ingestion — %s", path.name)
        return

    await manager.broadcast({
        "type":     "cicids_ingest_started",
        "filename": path.name,
        "source":   "monitor",
    })

    try:
        summary = await _ingest(path)
        _state["files_processed"] += 1
        _state["last_processed_file"] = path.name
        _state["last_processed_at"]   = datetime.now(tz=timezone.utc)

        await manager.broadcast({
            "type":     "cicids_ingest_complete",
            "filename": path.name,
            "data":     summary,
        })
        logger.info("Monitor: ingestion complete for %s — %d rows", path.name, summary.get("inserted", 0))

        # Fire SOAR playbooks against newly-ingested critical events
        from db.database import get_db_path
        from services.soar_engine import run_soar_on_ingest
        fired = await asyncio.get_running_loop().run_in_executor(
            None, run_soar_on_ingest, get_db_path(), path.name
        )
        for entry in fired:
            await manager.broadcast({"type": "cicids_playbook_fired", "data": entry})

    except Exception as exc:
        logger.error("Monitor: ingestion failed for %s: %s", path.name, exc)
        await manager.broadcast({
            "type":     "cicids_ingest_error",
            "filename": path.name,
            "error":    str(exc),
        })


async def _ingest(path: Path) -> dict:
    from db.database import get_db_path
    from ingestion.cicids_parser import ingest_cicids_to_db

    return await asyncio.get_running_loop().run_in_executor(
        None, ingest_cicids_to_db, path, get_db_path()
    )
