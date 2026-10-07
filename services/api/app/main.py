"""
SAST Platform – FastAPI application entry-point.

Sets up the ASGI application with:
- Lifespan for DB initialisation and teardown.
- CORS middleware permissive for development.
- Versioned API routers.
- Rich OpenAPI metadata.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from app.config import settings
from app.database import Base, engine
from app.routers import health, scans, stats, vulnerabilities
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize database on startup and dispose engine on shutdown."""
    logger.info("Starting up %s", settings.APP_NAME)
    # Create all tables that do not yet exist (idempotent).
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema synchronised.")
    except Exception as e:
        logger.warning(f"Database schema sync skipped or partially failed (usually safe if Enums already exist): {e}")
    yield
    logger.info("Shutting down – disposing DB engine …")
    await engine.dispose()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------
def create_application() -> FastAPI:
    application = FastAPI(
        title=settings.APP_NAME,
        description=(
            "**SAST Platform API** – Static Application Security Testing platform.\n\n"
            "Orchestrates code scanning jobs, stores vulnerability findings, and exposes "
            "aggregated security metrics for dashboards."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        contact={
            "name": "Security Engineering",
            "email": "security@example.com",
        },
        license_info={
            "name": "MIT",
        },
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routers
    api_prefix = "/api/v1"
    application.include_router(health.router, prefix=api_prefix, tags=["Health"])
    application.include_router(scans.router, prefix=api_prefix, tags=["Scans"])
    application.include_router(vulnerabilities.router, prefix=api_prefix, tags=["Vulnerabilities"])
    application.include_router(stats.router, prefix=api_prefix, tags=["Statistics"])

    return application


app = create_application()


@app.exception_handler(Exception)
async def handle_exception(request, exc: Exception) -> JSONResponse:
    """Handle unhandled server errors."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
