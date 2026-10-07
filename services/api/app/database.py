"""
SAST Platform – Async SQLAlchemy database setup.

Provides:
- Async engine configured from settings.
- Async session factory (AsyncSessionLocal).
- Declarative base for ORM models.
- FastAPI dependency ``get_db`` that yields a managed session.
"""

from __future__ import annotations

import logging
from typing import AsyncIterator

from app.config import settings
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Build an async-compatible DATABASE_URL.
# If the user supplied a plain psycopg2 URL we swap the driver to asyncpg
# so SQLAlchemy async works correctly.
# ---------------------------------------------------------------------------
_db_url = settings.DATABASE_URL
if _db_url.startswith("postgresql+psycopg2://"):
    _db_url = _db_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
elif _db_url.startswith("postgresql://"):
    _db_url = _db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
engine: AsyncEngine = create_async_engine(
    _db_url,
    echo=settings.DEBUG,  # log SQL in debug mode
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,  # verify connections before checkout
    pool_recycle=3600,  # recycle connections every hour
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Module alias used in other modules.
SessionLocal = AsyncSessionLocal


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    """Base class for all ORM models in the SAST Platform."""

    pass


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncIterator[AsyncSession]:
    """Yield a database session and ensure it is closed after the request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
