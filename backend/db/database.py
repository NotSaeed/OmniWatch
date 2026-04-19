"""
SQLAlchemy async engine + session factory.
All other modules import `AsyncSessionLocal` and `engine` from here.
"""

import os
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./omniwatch.db")

engine = create_async_engine(DATABASE_URL, echo=False)

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
    """Create all tables on startup if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
