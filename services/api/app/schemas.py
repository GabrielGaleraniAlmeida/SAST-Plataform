"""
SAST Platform – Pydantic v2 schemas.

Defines request / response models that mirror the SQLAlchemy ORM layer.
All schemas use ``model_config = ConfigDict(from_attributes=True)`` so they
can be constructed directly from ORM objects.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from app.enums import ScanStatus, Severity
from pydantic import BaseModel, ConfigDict, Field, computed_field


# ===========================================================================
# Shared utilities
# ===========================================================================
class _OrmBase(BaseModel):
    """Base model that enables ORM-mode for all subclasses."""

    model_config = ConfigDict(from_attributes=True)


# ===========================================================================
# Scan schemas
# ===========================================================================
class ScanCreate(BaseModel):
    """Payload accepted when starting a new scan."""

    repository_url: str = Field(
        ...,
        description="Full URL of the Git repository to scan.",
        examples=["https://github.com/org/repo"],
        max_length=2048,
    )
    branch: str = Field(
        default="main",
        description="Git branch to check out.",
        max_length=255,
    )
    language: Optional[str] = Field(
        default=None,
        description="Override the detected language (e.g. 'python', 'java').",
        max_length=64,
    )


class ScanFileRequest(BaseModel):
    """Request for scanning one source file through the analyzer service."""

    filename: str = Field(..., min_length=1, max_length=4096)
    content: str = Field(..., min_length=1, max_length=1_000_000)
    language: Literal["python", "javascript", "typescript", "java"] = "python"


class ScanUpdate(BaseModel):
    """Partial update allowed for a scan (internal use / admin)."""

    status: Optional[ScanStatus] = None
    language: Optional[str] = None
    total_files: Optional[int] = None
    total_vulnerabilities: Optional[int] = None
    completed_at: Optional[datetime] = None
    celery_task_id: Optional[str] = None


class ScanResponse(_OrmBase):
    """Full scan representation returned to API consumers."""

    id: int
    repository_url: str
    branch: str
    status: ScanStatus
    language: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
    total_files: int
    total_vulnerabilities: int
    celery_task_id: Optional[str]

    @computed_field
    @property
    def vulnerability_count(self) -> int:
        """Alias for frontend compatibility."""
        return self.total_vulnerabilities


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: List[ScanResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ===========================================================================
# Vulnerability schemas
# ===========================================================================
class VulnerabilityCreate(BaseModel):
    """Used internally when the analyzer pushes findings into the API."""

    scan_id: int
    file_path: str = Field(..., max_length=4096)
    line_number: int = Field(..., ge=1)
    column: Optional[int] = Field(default=None, ge=0)
    rule_id: str = Field(..., max_length=255)
    rule_name: str = Field(..., max_length=512)
    severity: Severity
    cwe_id: Optional[str] = Field(default=None, max_length=64)
    title: str = Field(..., max_length=512)
    description: Optional[str] = None
    code_snippet: Optional[str] = None
    ai_suggestion: Optional[str] = None
    ai_severity: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class VulnerabilitySuppressRequest(BaseModel):
    """Body for the suppress endpoint."""

    suppressed: bool = True
    reason: Optional[str] = Field(default=None, max_length=1024)


class VulnerabilityResponse(_OrmBase):
    """Vulnerability detail returned to API consumers."""

    id: int
    scan_id: int
    file_path: str
    line_number: int
    column: Optional[int]
    rule_id: str
    rule_name: str
    severity: Severity
    cwe_id: Optional[str]
    title: str
    description: Optional[str]
    code_snippet: Optional[str]
    ai_suggestion: Optional[str]
    ai_severity: Optional[str]
    confidence: Optional[float]
    suppressed: bool
    suppressed_reason: Optional[str]
    created_at: datetime


class VulnerabilityListResponse(BaseModel):
    """Paginated list of vulnerabilities."""

    items: List[VulnerabilityResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ===========================================================================
# ScanFile schemas
# ===========================================================================
class ScanFileCreate(BaseModel):
    scan_id: int
    file_path: str = Field(..., max_length=4096)
    language: Optional[str] = None
    lines_of_code: int = Field(default=0, ge=0)
    vulnerabilities_count: int = Field(default=0, ge=0)


class ScanFileResponse(_OrmBase):
    id: int
    scan_id: int
    file_path: str
    language: Optional[str]
    lines_of_code: int
    vulnerabilities_count: int


# ===========================================================================
# Statistics schemas
# ===========================================================================
class SeverityCount(BaseModel):
    severity: Severity
    count: int


class SummaryResponse(BaseModel):
    """High-level platform health numbers."""

    total_scans: int
    total_vulnerabilities: int
    active_scans: int
    failed_scans: int
    critical_count: int
    files_analyzed: int
    scans_this_week: int
    severity_breakdown: List[SeverityCount]


class TrendDataPoint(BaseModel):
    date: str  # ISO-8601 date string "YYYY-MM-DD"
    count: int


class TrendsResponse(BaseModel):
    data: List[TrendDataPoint]
    period_days: int


class TopFileEntry(BaseModel):
    file_path: str
    vulnerabilities_count: int
    scan_id: int


class TopFilesResponse(BaseModel):
    items: List[TopFileEntry]


class RuleGroup(BaseModel):
    rule_id: str
    rule_name: str
    count: int
    severities: List[SeverityCount]


class ByRuleResponse(BaseModel):
    items: List[RuleGroup]


class SeverityDistributionResponse(BaseModel):
    """Suitable for a pie / donut chart."""

    labels: List[str]
    values: List[int]
    colors: List[str]


# ===========================================================================
# Health schema
# ===========================================================================
class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    redis: str
