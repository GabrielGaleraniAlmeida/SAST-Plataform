"""Pydantic models of the analyzer service."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    AUTO = "auto"


class AnalysisRequest(BaseModel):
    """Scan a git repository or a raw code string."""

    repository_url: Optional[str] = None
    branch: str = "main"
    language: Language = Language.AUTO
    code_content: Optional[str] = None
    filename: str = "snippet.py"


class CodeLocation(BaseModel):
    filename: str
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    col_start: Optional[int] = Field(None, ge=0)
    col_end: Optional[int] = Field(None, ge=0)
    snippet: Optional[str] = None


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    rule_name: str
    description: str
    severity: SeverityLevel
    cwe_id: str
    cve_id: Optional[str] = None
    location: CodeLocation
    language: str
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    false_positive_risk: str = "low"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
