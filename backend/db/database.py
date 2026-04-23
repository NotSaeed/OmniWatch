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
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

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
        "ALTER TABLE alerts ADD COLUMN grounding_available INTEGER DEFAULT 1",
        "ALTER TABLE alerts ADD COLUMN grounding_score REAL",
    ]
    for sql in migrations:
        try:
            await conn.execute(__import__("sqlalchemy").text(sql))
        except Exception:
            pass  # column already exists — SQLite raises OperationalError
