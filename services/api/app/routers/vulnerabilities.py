"""
SAST Platform – Vulnerabilities router.

Endpoints:
  GET   /vulnerabilities          – paginated list with rich filtering
  GET   /vulnerabilities/{id}     – single vulnerability detail
  PATCH /vulnerabilities/{id}/suppress – mark / unmark as suppressed
"""

from __future__ import annotations

import logging
import math
from typing import Optional

from app.database import get_db
from app.models import Severity, Vulnerability
from app.schemas import (
    VulnerabilityListResponse,
    VulnerabilityResponse,
    VulnerabilitySuppressRequest,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
async def _get_vuln_or_404(vuln_id: int, db: AsyncSession) -> Vulnerability:
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if vuln is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with id={vuln_id} not found.",
        )
    return vuln


# ---------------------------------------------------------------------------
# GET /vulnerabilities
# ---------------------------------------------------------------------------
@router.get(
    "/vulnerabilities",
    response_model=VulnerabilityListResponse,
    summary="List vulnerabilities",
    description=(
        "Returns a paginated list of vulnerabilities. "
        "Supports filtering by scan, severity, file path, rule ID, and suppression state."
    ),
)
async def list_vulnerabilities(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    scan_id: Optional[int] = Query(default=None, description="Filter by scan ID"),
    severity: Optional[Severity] = Query(default=None, description="Filter by severity level"),
    file_path: Optional[str] = Query(default=None, description="Partial file path match"),
    rule_id: Optional[str] = Query(default=None, description="Filter by rule ID"),
    suppressed: Optional[bool] = Query(default=None, description="Filter suppressed state"),
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityListResponse:
    query = select(Vulnerability)

    if scan_id is not None:
        query = query.where(Vulnerability.scan_id == scan_id)
    if severity is not None:
        query = query.where(Vulnerability.severity == severity)
    if file_path:
        query = query.where(Vulnerability.file_path.ilike(f"%{file_path}%"))
    if rule_id:
        query = query.where(Vulnerability.rule_id == rule_id)
    if suppressed is not None:
        query = query.where(Vulnerability.suppressed == suppressed)

    # Count
    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar_one()

    # Data
    query = query.order_by(Vulnerability.severity.desc(), Vulnerability.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    vulns = result.scalars().all()

    pages = math.ceil(total / page_size) if total > 0 else 0
    return VulnerabilityListResponse(
        items=[VulnerabilityResponse.model_validate(v) for v in vulns],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


# ---------------------------------------------------------------------------
# GET /vulnerabilities/{id}
# ---------------------------------------------------------------------------
@router.get(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityResponse,
    summary="Get vulnerability by ID",
)
async def get_vulnerability(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityResponse:
    vuln = await _get_vuln_or_404(vuln_id, db)
    return VulnerabilityResponse.model_validate(vuln)


# ---------------------------------------------------------------------------
# PATCH /vulnerabilities/{id}/suppress
# ---------------------------------------------------------------------------
@router.patch(
    "/vulnerabilities/{vuln_id}/suppress",
    response_model=VulnerabilityResponse,
    summary="Suppress or un-suppress a vulnerability",
    description=(
        "Marks a vulnerability as suppressed (i.e. accepted risk / false positive) "
        "or restores it. An optional reason can be provided for audit purposes."
    ),
)
async def suppress_vulnerability(
    vuln_id: int,
    payload: VulnerabilitySuppressRequest,
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityResponse:
    vuln = await _get_vuln_or_404(vuln_id, db)

    vuln.suppressed = payload.suppressed
    vuln.suppressed_reason = payload.reason if payload.suppressed else None

    await db.commit()
    await db.refresh(vuln)
    logger.info(
        "Vulnerability id=%s suppressed=%s reason=%r",
        vuln_id,
        vuln.suppressed,
        vuln.suppressed_reason,
    )
    return VulnerabilityResponse.model_validate(vuln)
