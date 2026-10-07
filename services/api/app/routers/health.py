"""
SAST Platform – Health router.

Provides a lightweight liveness / readiness probe that checks:
- API process is alive.
- Database connectivity.
- Redis connectivity.
"""

from __future__ import annotations

import logging

import redis as sync_redis
from app.config import settings
from app.database import AsyncSessionLocal
from app.schemas import HealthResponse
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

logger = logging.getLogger(__name__)
router = APIRouter()


async def _check_database() -> str:
    """Return 'ok' if the database is reachable, otherwise an error description."""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        return f"error: {exc}"


def _check_redis() -> str:
    """Return 'ok' if Redis is reachable, otherwise an error description."""
    try:
        client = sync_redis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        client.ping()
        client.close()
        return "ok"
    except Exception as exc:
        logger.warning("Redis health check failed: %s", exc)
        return f"error: {exc}"


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description=(
        "Liveness and readiness probe. "
        "Returns HTTP 200 when all dependencies are healthy, "
        "HTTP 503 if any dependency is degraded."
    ),
)
async def health_check() -> JSONResponse:
    db_status = await _check_database()
    redis_status = _check_redis()

    all_ok = db_status == "ok" and redis_status == "ok"
    http_status = status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE

    payload = HealthResponse(
        status="healthy" if all_ok else "degraded",
        version="1.0.0",
        database=db_status,
        redis=redis_status,
    )

    return JSONResponse(status_code=http_status, content=payload.model_dump())
