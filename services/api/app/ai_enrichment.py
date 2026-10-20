"""Apply AI metadata to a finding without changing scanner visibility."""

from __future__ import annotations

from typing import Any, Dict, Optional


def apply_ai_enrichment(
    finding: Dict[str, Any],
    severity_result: Optional[Dict[str, Any]],
    remediation_result: Optional[Dict[str, Any]],
) -> None:
    if severity_result:
        finding["ai_severity"] = severity_result["severity"]
        finding["ai_triage"] = {
            "is_false_positive": severity_result["is_false_positive"],
            "confidence": severity_result["confidence"],
            "reasoning": severity_result.get("false_positive_reasoning"),
        }
    if remediation_result:
        finding["ai_suggestion"] = "\n\n".join(
            filter(
                None,
                [remediation_result.get("explanation"), remediation_result.get("fixed_code")],
            )
        )
