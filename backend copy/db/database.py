"""
SQLAlchemy async engine + session factory.
All other modules import `AsyncSessionLocal` and `engine` from here.
"""

import os
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./omniwatch.db")

engine = create_async_engine(DATABASE_URL, echo=False)


@event.listens_for(engine.sync_engine, "connect")
def _set_wal_mode(dbapi_conn, _record) -> None:
    """Enable WAL journal mode on every new SQLite connection.
    WAL allows concurrent readers alongside the writer — required for the
    atomic INSERT OR IGNORE pattern in the Spent-Receipt Registry.
    """
    dbapi_conn.execute("PRAGMA journal_mode=WAL")

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


def get_db_path() -> str:
    """Return the plain filesystem path to the SQLite database file."""
    return str(engine.url).replace("sqlite+aiosqlite:///", "").replace("./", "")


async def create_tables() -> None:
    """Create all tables on startup if they don't exist, then apply migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _migrate(conn)


async def _migrate(conn) -> None:
    """Idempotent ALTER TABLE migrations for schema additions."""
    migrations = [
        # Sprint 2 — RAG grounding fields
        "ALTER TABLE alerts ADD COLUMN grounding_available INTEGER DEFAULT 1",
        "ALTER TABLE alerts ADD COLUMN grounding_score REAL",
        # Sprint 3 — FIDO2 / Spent-Receipt Registry
        "ALTER TABLE webauthn_credentials ADD COLUMN sign_count INTEGER DEFAULT 0",
        # Sprint 5 — Active Remediation Bridge extended fields
        "ALTER TABLE firewall_status ADD COLUMN verdict_json TEXT",
        "ALTER TABLE firewall_status ADD COLUMN edge_record_id INTEGER",
        "ALTER TABLE firewall_status ADD COLUMN auto_blocked INTEGER DEFAULT 0",
    ]
    for sql in migrations:
        try:
            await conn.execute(__import__("sqlalchemy").text(sql))
        except Exception:
            pass  # column already exists — SQLite raises OperationalError
