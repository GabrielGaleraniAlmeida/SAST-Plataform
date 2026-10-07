"""
SAST Platform – SQLAlchemy ORM models.

Three core models:
- Scan        – represents a single repository scanning job.
- Vulnerability – individual finding produced by a scan.
- ScanFile    – per-file statistics attached to a scan.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from app.database import Base
from app.enums import ScanStatus, Severity
from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
class Scan(Base):
    """Represents one complete scanning job against a repository."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repository_url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.PENDING,
        index=True,
    )
    language: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    total_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Celery task id for status tracking / cancellation
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    files: Mapped[List["ScanFile"]] = relationship("ScanFile", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status} repo={self.repository_url!r}>"


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------
class Vulnerability(Base):
    """A single security finding produced by a scan."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    file_path: Mapped[str] = mapped_column(String(4096), nullable=False, index=True)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    column: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Rule metadata
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity"),
        nullable=False,
        index=True,
    )
    cwe_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Finding detail
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # AI-enhanced fields
    ai_suggestion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_severity: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(nullable=True)

    # Triage fields
    suppressed: Mapped[bool] = mapped_column(nullable=False, default=False, index=True)
    suppressed_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")

    def __repr__(self) -> str:
        return f"<Vulnerability id={self.id} rule={self.rule_id} " f"severity={self.severity} file={self.file_path!r}>"


# ---------------------------------------------------------------------------
# ScanFile
# ---------------------------------------------------------------------------
class ScanFile(Base):
    """Per-file statistics collected during a scan."""

    __tablename__ = "scan_files"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    file_path: Mapped[str] = mapped_column(String(4096), nullable=False)
    language: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    lines_of_code: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerabilities_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="files")

    def __repr__(self) -> str:
        return f"<ScanFile id={self.id} scan_id={self.scan_id} file={self.file_path!r}>"
