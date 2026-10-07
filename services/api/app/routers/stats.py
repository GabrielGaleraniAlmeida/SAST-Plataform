"""
SAST Platform – Statistics router.

Aggregated metrics endpoints powering the security dashboard.

Endpoints:
  GET /stats/summary              – platform-wide high-level counts
  GET /stats/trends               – vulnerability count per day (last 30 days)
  GET /stats/top-files            – top 10 files with most vulnerabilities
  GET /stats/by-rule              – vulnerabilities grouped by rule
  GET /stats/severity-distribution – pie-chart data by severity
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, cast, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Scan, ScanStatus, Severity, ScanFile, Vulnerability
from app.schemas import (
    ByRuleResponse,
    RuleGroup,
    SeverityCount,
    SeverityDistributionResponse,
    SummaryResponse,
    TopFileEntry,
    TopFilesResponse,
    TrendDataPoint,
    TrendsResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Severity ordering for consistent display
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Dashboard colour palette (matches common security tooling conventions)
_SEVERITY_COLORS: Dict[str, str] = {
    Severity.CRITICAL: "#dc2626",  # red-600
    Severity.HIGH: "#ea580c",      # orange-600
    Severity.MEDIUM: "#d97706",    # amber-600
    Severity.LOW: "#2563eb",       # blue-600
    Severity.INFO: "#6b7280",      # gray-500
}


# ---------------------------------------------------------------------------
# GET /stats/summary
# ---------------------------------------------------------------------------
@router.get(
    "/stats/summary",
    response_model=SummaryResponse,
    summary="Platform summary",
    description="Returns total scans, total vulnerabilities, active/failed scans and severity breakdown.",
)
async def summary(db: AsyncSession = Depends(get_db)) -> SummaryResponse:
    # Scan counts
    scan_counts_result = await db.execute(
        select(Scan.status, func.count(Scan.id).label("cnt"))
        .group_by(Scan.status)
    )
    scan_counts: Dict[str, int] = {row.status: row.cnt for row in scan_counts_result}

    total_scans = sum(scan_counts.values())
    active_scans = scan_counts.get(ScanStatus.RUNNING, 0) + scan_counts.get(ScanStatus.PENDING, 0)
    failed_scans = scan_counts.get(ScanStatus.FAILED, 0)

    # Total vulnerabilities (non-suppressed)
    total_vulns_result = await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.suppressed.is_(False))
    )
    total_vulnerabilities = total_vulns_result.scalar_one()

    # Severity breakdown
    sev_result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id).label("cnt"))
        .where(Vulnerability.suppressed.is_(False))
        .group_by(Vulnerability.severity)
    )
    sev_map: Dict[str, int] = {row.severity: row.cnt for row in sev_result}
    severity_breakdown = [
        SeverityCount(severity=sev, count=sev_map.get(sev, 0))
        for sev in _SEVERITY_ORDER
    ]

    files_analyzed = (await db.execute(select(func.coalesce(func.sum(Scan.total_files), 0)))).scalar_one()
    week_ago = datetime.now(tz=timezone.utc) - timedelta(days=7)
    scans_this_week = (
        await db.execute(select(func.count(Scan.id)).where(Scan.created_at >= week_ago))
    ).scalar_one()

    return SummaryResponse(
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        active_scans=active_scans,
        failed_scans=failed_scans,
        critical_count=sev_map.get(Severity.CRITICAL, 0),
        files_analyzed=files_analyzed,
        scans_this_week=scans_this_week,
        severity_breakdown=severity_breakdown,
    )


# ---------------------------------------------------------------------------
# GET /stats/trends
# ---------------------------------------------------------------------------
@router.get(
    "/stats/trends",
    response_model=TrendsResponse,
    summary="Vulnerability trends",
    description="Returns the count of new vulnerabilities per day over the last N days.",
)
async def trends(
    days: int = Query(default=30, ge=1, le=365, description="Look-back period in days"),
    db: AsyncSession = Depends(get_db),
) -> TrendsResponse:
    since = datetime.now(tz=timezone.utc) - timedelta(days=days)

    result = await db.execute(
        select(
            func.date(Vulnerability.created_at).label("day"),
            func.count(Vulnerability.id).label("cnt"),
        )
        .where(Vulnerability.created_at >= since)
        .where(Vulnerability.suppressed.is_(False))
        .group_by(func.date(Vulnerability.created_at))
        .order_by(func.date(Vulnerability.created_at))
    )

    # Build a complete series with 0-fill for missing days
    raw: Dict[str, int] = {}
    for row in result:
        day_str = str(row.day)  # "YYYY-MM-DD"
        raw[day_str] = row.cnt

    data: List[TrendDataPoint] = []
    for i in range(days):
        day = since.date() + timedelta(days=i)
        day_str = day.isoformat()
        data.append(TrendDataPoint(date=day_str, count=raw.get(day_str, 0)))

    return TrendsResponse(data=data, period_days=days)


# ---------------------------------------------------------------------------
# GET /stats/top-files
# ---------------------------------------------------------------------------
@router.get(
    "/stats/top-files",
    response_model=TopFilesResponse,
    summary="Top files by vulnerability count",
    description="Returns the top 10 files across all scans ordered by number of vulnerabilities.",
)
async def top_files(
    limit: int = Query(default=10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> TopFilesResponse:
    result = await db.execute(
        select(
            Vulnerability.file_path,
            Vulnerability.scan_id,
            func.count(Vulnerability.id).label("cnt"),
        )
        .where(Vulnerability.suppressed.is_(False))
        .group_by(Vulnerability.file_path, Vulnerability.scan_id)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(limit)
    )

    items = [
        TopFileEntry(
            file_path=row.file_path,
            vulnerabilities_count=row.cnt,
            scan_id=row.scan_id,
        )
        for row in result
    ]
    return TopFilesResponse(items=items)


# ---------------------------------------------------------------------------
# GET /stats/by-rule
# ---------------------------------------------------------------------------
@router.get(
    "/stats/by-rule",
    response_model=ByRuleResponse,
    summary="Vulnerabilities by rule",
    description="Groups all non-suppressed vulnerabilities by detection rule.",
)
async def by_rule(db: AsyncSession = Depends(get_db)) -> ByRuleResponse:
    result = await db.execute(
        select(
            Vulnerability.rule_id,
            Vulnerability.rule_name,
            Vulnerability.severity,
            func.count(Vulnerability.id).label("cnt"),
        )
        .where(Vulnerability.suppressed.is_(False))
        .group_by(Vulnerability.rule_id, Vulnerability.rule_name, Vulnerability.severity)
        .order_by(func.count(Vulnerability.id).desc())
    )

    # Group by (rule_id, rule_name)
    rule_map: Dict[str, Dict] = {}
    for row in result:
        key = row.rule_id
        if key not in rule_map:
            rule_map[key] = {
                "rule_id": row.rule_id,
                "rule_name": row.rule_name,
                "count": 0,
                "severities": defaultdict(int),
            }
        rule_map[key]["count"] += row.cnt
        rule_map[key]["severities"][row.severity] += row.cnt

    items: List[RuleGroup] = []
    for data in sorted(rule_map.values(), key=lambda x: -x["count"]):
        items.append(
            RuleGroup(
                rule_id=data["rule_id"],
                rule_name=data["rule_name"],
                count=data["count"],
                severities=[
                    SeverityCount(severity=s, count=c)
                    for s, c in data["severities"].items()
                ],
            )
        )

    return ByRuleResponse(items=items)


# ---------------------------------------------------------------------------
# GET /stats/severity-distribution
# ---------------------------------------------------------------------------
@router.get(
    "/stats/severity-distribution",
    response_model=SeverityDistributionResponse,
    summary="Severity distribution",
    description="Pie / donut chart data showing vulnerability counts per severity level.",
)
async def severity_distribution(
    db: AsyncSession = Depends(get_db),
) -> SeverityDistributionResponse:
    result = await db.execute(
        select(
            Vulnerability.severity,
            func.count(Vulnerability.id).label("cnt"),
        )
        .where(Vulnerability.suppressed.is_(False))
        .group_by(Vulnerability.severity)
    )
    sev_map: Dict[str, int] = {row.severity: row.cnt for row in result}

    labels: List[str] = []
    values: List[int] = []
    colors: List[str] = []

    for sev in _SEVERITY_ORDER:
        count = sev_map.get(sev, 0)
        if count > 0:
            labels.append(sev.value.capitalize())
            values.append(count)
            colors.append(_SEVERITY_COLORS[sev])

    return SeverityDistributionResponse(labels=labels, values=values, colors=colors)
