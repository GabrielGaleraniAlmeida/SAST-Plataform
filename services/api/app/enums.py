"""
Shared enumerations used across the SAST Platform.
Centralized to avoid duplication between services.
"""

from __future__ import annotations

import enum


class ScanStatus(str, enum.Enum):
    """Lifecycle states of a scan job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    """CVSS-inspired severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
