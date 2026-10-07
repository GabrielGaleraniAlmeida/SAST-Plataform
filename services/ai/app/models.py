"""
AI/LLM Integration Service - Pydantic Models
=============================================
Data models for request/response validation across all AI endpoints.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SeverityLevel(str, Enum):
    """Standard vulnerability severity levels (CVSS-aligned)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(str, Enum):
    """OWASP-aligned vulnerability categories."""

    INJECTION = "injection"
    BROKEN_AUTH = "broken_auth"
    XSS = "xss"
    IDOR = "idor"
    SECURITY_MISCONFIG = "security_misconfig"
    SENSITIVE_DATA = "sensitive_data"
    XXE = "xxe"
    BROKEN_ACCESS = "broken_access"
    DESERIALIZATION = "deserialization"
    KNOWN_VULNS = "known_vulns"
    CRYPTO = "crypto"
    RACE_CONDITION = "race_condition"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Input Models
# ---------------------------------------------------------------------------


class VulnerabilityInput(BaseModel):
    """
    Describes a single vulnerability finding from a SAST scanner.
    """

    rule_id: str = Field(
        ...,
        description="Unique identifier for the rule that triggered this finding",
        examples=["CWE-89", "SAST-SQL-001"],
    )
    rule_name: str = Field(
        ..., description="Human-readable name of the rule", examples=["SQL Injection", "Path Traversal"]
    )
    description: str = Field(..., description="Detailed description of the vulnerability", min_length=10)
    file_path: str = Field(..., description="Relative path to the affected source file", examples=["src/api/users.py"])
    line_number: int = Field(..., ge=1, description="Line number where the vulnerability was found")
    code_snippet: Optional[str] = Field(default=None, description="Relevant code snippet (ideally ±5 lines of context)")
    language: Optional[str] = Field(
        default="unknown",
        description="Programming language of the affected file",
        examples=["python", "java", "javascript"],
    )
    category: Optional[VulnerabilityCategory] = Field(
        default=VulnerabilityCategory.OTHER, description="Vulnerability category (OWASP-aligned)"
    )
    existing_severity: Optional[SeverityLevel] = Field(
        default=None, description="Severity assigned by the original SAST scanner (if any)"
    )
    cwe_id: Optional[str] = Field(
        default=None, description="CWE identifier, e.g. 'CWE-89'", examples=["CWE-89", "CWE-22"]
    )
    metadata: Optional[dict[str, Any]] = Field(default_factory=dict, description="Additional scanner-specific metadata")

    @field_validator("code_snippet")
    @classmethod
    def truncate_snippet(cls, v: Optional[str]) -> Optional[str]:
        """Prevent excessively long snippets that would overflow the LLM context."""
        if v and len(v) > 3000:
            return v[:3000] + "\n... [truncated]"
        return v


class BatchRequest(BaseModel):
    """Request body for batch AI analysis of multiple findings."""

    vulnerabilities: list[VulnerabilityInput] = Field(
        ..., description="List of vulnerability findings to analyze", min_length=1, max_length=50
    )
    include_remediation: bool = Field(
        default=False, description="Whether to also generate remediation suggestions for each finding"
    )
    include_explanation: bool = Field(default=False, description="Whether to also generate plain-language explanations")


# ---------------------------------------------------------------------------
# Output Models
# ---------------------------------------------------------------------------


class SeverityResult(BaseModel):
    """
    AI-assessed severity classification for a single vulnerability.
    """

    severity: SeverityLevel = Field(..., description="AI-assigned severity level")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score for the severity classification (0.0–1.0)"
    )
    reasoning: str = Field(..., description="Explanation of why this severity level was assigned")
    original_severity: Optional[SeverityLevel] = Field(
        default=None, description="Original SAST scanner severity (for comparison)"
    )
    severity_changed: bool = Field(
        default=False, description="True if AI severity differs from the original scanner severity"
    )
    is_false_positive: bool = Field(
        default=False, description="AI's assessment of whether this is likely a false positive"
    )
    false_positive_reasoning: Optional[str] = Field(
        default=None, description="Reason why it might be a false positive (if applicable)"
    )
    model_used: str = Field(default="ollama/llama3", description="LLM model that performed the classification")


class RemediationResult(BaseModel):
    """
    AI-generated code fix and remediation guidance for a vulnerability.
    """

    fixed_code: Optional[str] = Field(default=None, description="Fixed/patched version of the vulnerable code snippet")
    explanation: str = Field(..., description="Step-by-step explanation of what changed and why")
    references: list[str] = Field(default_factory=list, description="Relevant references (OWASP, CWE, CVE, docs)")
    estimated_effort: Optional[str] = Field(
        default=None, description="Estimated effort to apply the fix (e.g., 'low', 'medium', 'high')"
    )
    breaking_change: bool = Field(default=False, description="Whether applying this fix may introduce breaking changes")
    additional_steps: list[str] = Field(
        default_factory=list, description="Additional remediation steps beyond the code fix"
    )
    model_used: str = Field(default="ollama/llama3", description="LLM model that generated the remediation")


class BatchFindingResult(BaseModel):
    """Result for a single finding within a batch analysis response."""

    rule_id: str
    file_path: str
    line_number: int
    severity_result: Optional[SeverityResult] = None
    remediation_result: Optional[RemediationResult] = None
    explanation: Optional[str] = None
    error: Optional[str] = Field(default=None, description="Error message if analysis of this specific finding failed")


class BatchResponse(BaseModel):
    """Response from the batch AI analysis endpoint."""

    total: int = Field(..., description="Total number of findings submitted")
    processed: int = Field(..., description="Number of findings successfully processed")
    failed: int = Field(..., description="Number of findings that failed analysis")
    results: list[BatchFindingResult] = Field(..., description="Per-finding analysis results")
    high_confidence_false_positives: list[str] = Field(
        default_factory=list, description="Rule IDs of findings very likely to be false positives"
    )


class HealthResponse(BaseModel):
    """Health check response from the /ai/health endpoint."""

    status: str = Field(..., examples=["healthy", "degraded", "unhealthy"])
    ollama_connected: bool
    ollama_url: str
    model: str
    version: str = "1.0.0"
    message: Optional[str] = None
