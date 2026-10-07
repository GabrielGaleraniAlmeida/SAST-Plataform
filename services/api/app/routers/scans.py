"""
SAST Platform – Scans router.

Endpoints:
  POST   /scans           – create a new scan and enqueue a Celery task
  GET    /scans           – paginated list of all scans
  GET    /scans/{id}      – retrieve a single scan
  DELETE /scans/{id}      – delete a scan and all its findings
  POST   /scans/{id}/cancel – cancel a running scan
"""

from __future__ import annotations

import logging
import math
from typing import Optional

import httpx
from app.config import settings
from app.database import get_db
from app.models import Scan, ScanStatus
from app.schemas import (
    ScanCreate,
    ScanFileRequest,
    ScanListResponse,
    ScanResponse,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _get_scan_or_404(scan_id: int, db: AsyncSession) -> Scan:
    """Fetch a scan by primary key or raise 404."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with id={scan_id} not found.",
        )
    return scan


# ---------------------------------------------------------------------------
# POST /scans
# ---------------------------------------------------------------------------
@router.post(
    "/scan/file",
    summary="Scan one source file",
    description="Forwards a source file to the analyzer and returns its findings.",
)
async def scan_file(payload: ScanFileRequest):
    try:
        async with httpx.AsyncClient(timeout=settings.ANALYZER_TIMEOUT) as client:
            response = await client.post(
                f"{settings.ANALYZER_URL.rstrip('/')}/analyze",
                json={
                    "code_content": payload.content,
                    "filename": payload.filename,
                    "language": payload.language,
                },
            )
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        logger.error("Analyzer timed out scanning file %s", payload.filename)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Analyzer timed out while scanning the file.",
        ) from exc
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Analyzer rejected file scan %s with HTTP %s",
            payload.filename,
            exc.response.status_code,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Analyzer failed to scan the file.",
        ) from exc
    except httpx.RequestError as exc:
        logger.error("Analyzer unavailable while scanning file %s: %s", payload.filename, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Analyzer service is unavailable.",
        ) from exc

    result = response.json()
    findings = result.get("vulnerabilities", [])
    return {
        "findings": findings,
        "total": len(findings),
        "files": result.get("files", []),
    }


@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan",
    description=(
        "Registers a new scanning job for the given repository URL and branch, "
        "persists it in the database with status *pending*, and enqueues a "
        "Celery task to perform the actual analysis asynchronously."
    ),
)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    scan = Scan(
        repository_url=payload.repository_url,
        branch=payload.branch,
        language=payload.language,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)  # worker must see the committed row

    from app.tasks import run_scan  # noqa: PLC0415

    try:
        scan.celery_task_id = run_scan.delay(scan.id).id
    except Exception as exc:
        logger.error("Failed to enqueue scan id=%s: %s", scan.id, exc)
        scan.status = ScanStatus.FAILED
    await db.commit()
    await db.refresh(scan)
    return ScanResponse.model_validate(scan)


# ---------------------------------------------------------------------------
# GET /scans
# ---------------------------------------------------------------------------
@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List all scans",
    description="Returns a paginated, optionally filtered list of all scans.",
)
async def list_scans(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=200, description="Items per page"),
    status: Optional[ScanStatus] = Query(default=None, description="Filter by status"),
    repository_url: Optional[str] = Query(default=None, description="Filter by repo URL (partial match)"),
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    query = select(Scan)

    if status is not None:
        query = query.where(Scan.status == status)
    if repository_url:
        query = query.where(Scan.repository_url.ilike(f"%{repository_url}%"))

    # Total count
    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    # Paginated results
    query = query.order_by(Scan.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    scans = result.scalars().all()

    pages = math.ceil(total / page_size) if total > 0 else 0
    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


# ---------------------------------------------------------------------------
# GET /scans/{id}
# ---------------------------------------------------------------------------
@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan by ID",
)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    scan = await _get_scan_or_404(scan_id, db)
    return ScanResponse.model_validate(scan)


# ---------------------------------------------------------------------------
# DELETE /scans/{id}
# ---------------------------------------------------------------------------
@router.delete(
    "/scans/{scan_id}",
    summary="Delete a scan",
    description=(
        "Permanently deletes the scan and all associated vulnerabilities and " "file records (cascade delete)."
    ),
)
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    scan = await _get_scan_or_404(scan_id, db)

    # If the scan is running, attempt to revoke the Celery task first.
    if scan.status == ScanStatus.RUNNING and scan.celery_task_id:
        try:
            from app.tasks import celery_app  # noqa: PLC0415

            celery_app.control.revoke(scan.celery_task_id, terminate=True)
            logger.info("Revoked Celery task %s", scan.celery_task_id)
        except Exception as exc:
            logger.warning("Could not revoke task %s: %s", scan.celery_task_id, exc)

    await db.delete(scan)
    await db.commit()

    return {"detail": "Scan deleted successfully"}


# ---------------------------------------------------------------------------
# POST /scans/{id}/cancel
# ---------------------------------------------------------------------------
@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a running scan",
    description=(
        "Signals the Celery worker to stop processing the scan. " "The scan status transitions to *cancelled*."
    ),
)
async def cancel_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    scan = await _get_scan_or_404(scan_id, db)

    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot cancel a scan with status '{scan.status.value}'.",
        )

    # Revoke Celery task
    if scan.celery_task_id:
        try:
            from app.tasks import celery_app  # noqa: PLC0415

            celery_app.control.revoke(scan.celery_task_id, terminate=True)
            logger.info("Revoked Celery task %s for scan id=%s", scan.celery_task_id, scan_id)
        except Exception as exc:
            logger.warning(
                "Failed to revoke task %s: %s – proceeding with status update.",
                scan.celery_task_id,
                exc,
            )

    scan.status = ScanStatus.CANCELLED
    await db.commit()
    await db.refresh(scan)
    return ScanResponse.model_validate(scan)
