"""
OmniWatch FastAPI Application Entry Point
Run: uvicorn main:app --reload --host 0.0.0.0 --port 8080
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from api.auth_routes import router as auth_router
from api.verify_route import router as verify_router
from api.bincode_route import router as edge_router
from api.prove_route import router as prove_router
from api.abc_routes import router as abc_router
from db.database import create_tables

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)

# Resolve paths relative to project root (one level above backend/)
_PROJECT_ROOT = Path(__file__).parent.parent
MONITOR_DIR   = _PROJECT_ROOT / "data" / "monitor"

_scheduler = AsyncIOScheduler()


def _schedule_auto_scan() -> None:
    interval = int(os.getenv("AUTO_SCAN_INTERVAL", "0"))
    if interval > 0:
        from tasks import run_scan_task
        _scheduler.add_job(run_scan_task, "interval", seconds=interval, id="auto_scan")
        logger.info("Auto-scan scheduled every %ds", interval)

    from tasks import run_abc_cycle
    _scheduler.add_job(run_abc_cycle, "interval", seconds=15, id="abc_cycle")
    logger.info("ABC cycle scheduled every 15 s (starts disabled)")


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # SQLAlchemy tables (alerts, scan_runs, playbook_log, raw_events)
    await create_tables()

    # Raw SQLite tables for CIC-IDS-2017 data — created proactively so every
    # API endpoint works cleanly even before the first CSV is uploaded.
    from db.database import get_db_path
    from ingestion.cicids_parser import ensure_cicids_tables
    from services.soar_engine import ensure_soar_tables
    _db = get_db_path()
    ensure_cicids_tables(_db)
    ensure_soar_tables(_db)
    logger.info("Database tables ready")

    # APScheduler
    _schedule_auto_scan()
    _scheduler.start()

    # Watchdog folder monitor — pass the running loop so the monitor can
    # schedule coroutines from its background thread
    try:
        from monitor.watchdog_monitor import start_monitor
        start_monitor(MONITOR_DIR, asyncio.get_running_loop())
    except Exception as exc:
        logger.warning("Folder monitor could not start: %s", exc)

    yield

    # Shutdown
    _scheduler.shutdown(wait=False)
    try:
        from monitor.watchdog_monitor import stop_monitor
        stop_monitor()
    except Exception:
        pass


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="OmniWatch API",
    description="AI-powered SOC triage system — CITREX 2026",
    version="2.0.0",
    lifespan=lifespan,
)

_FIDO2_ORIGIN = os.getenv("FIDO2_ORIGIN", "https://omniwatch.local")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        _FIDO2_ORIGIN,               # HTTPS origin required for WebAuthn secure context
    ],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

app.include_router(router)
app.include_router(auth_router)      # /api/auth/* — FIDO2 registration + signing ceremony
app.include_router(verify_router)    # /api/verify-remediation — dual-factor gate
app.include_router(edge_router)      # /api/edge/* — Sprint 4 bincode ingestion from Pi 4
app.include_router(prove_router)     # /api/edge/prove/* — STARK proof generation
app.include_router(abc_router)       # /api/abc/* — Autonomous Breach Containment


@app.get("/health")
async def health():
    return {"status": "ok", "service": "omniwatch"}
