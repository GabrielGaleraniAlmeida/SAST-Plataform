"""
AI/LLM Integration Service - Security Analyzer
===============================================
Core analysis logic that combines the Ollama client with prompt templates
to deliver structured vulnerability analysis results.

All public methods gracefully handle Ollama unavailability via rule-based fallbacks.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from app.llm_client import OllamaClient
from app.models import (
    RemediationResult,
    SeverityLevel,
    SeverityResult,
    VulnerabilityInput,
)
from app.prompts import (
    EXPLANATION_PROMPT,
    FALSE_POSITIVE_TRIAGE_PROMPT,
    REMEDIATION_PROMPT,
    SEVERITY_CLASSIFICATION_PROMPT,
    SYSTEM_PROMPT,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule-based severity defaults used as fallback when Ollama is unavailable
# ---------------------------------------------------------------------------

_RULE_BASED_SEVERITY: dict[str, SeverityLevel] = {
    # Injection flaws
    "sql_injection": SeverityLevel.CRITICAL,
    "command_injection": SeverityLevel.CRITICAL,
    "code_injection": SeverityLevel.CRITICAL,
    "ldap_injection": SeverityLevel.HIGH,
    "xpath_injection": SeverityLevel.HIGH,
    # Auth / crypto
    "hardcoded_secret": SeverityLevel.HIGH,
    "hardcoded_password": SeverityLevel.HIGH,
    "weak_crypto": SeverityLevel.MEDIUM,
    "broken_auth": SeverityLevel.HIGH,
    # Web
    "xss": SeverityLevel.HIGH,
    "csrf": SeverityLevel.MEDIUM,
    "ssrf": SeverityLevel.HIGH,
    "open_redirect": SeverityLevel.MEDIUM,
    # File system
    "path_traversal": SeverityLevel.HIGH,
    "file_inclusion": SeverityLevel.HIGH,
    # Misc
    "insecure_deserial": SeverityLevel.HIGH,
    "xxe": SeverityLevel.HIGH,
    "race_condition": SeverityLevel.MEDIUM,
    "info_disclosure": SeverityLevel.LOW,
}

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]+?)\s*```", re.IGNORECASE)


class AISecurityAnalyzer:
    """
    Orchestrates AI-powered vulnerability analysis using an OllamaClient.

    Each public method:
    1. Builds a prompt from the appropriate template.
    2. Calls the LLM via the OllamaClient.
    3. Parses the structured JSON response.
    4. Falls back to rule-based logic if the LLM is unavailable or returns
       an unparseable response.
    """

    def __init__(self, ollama_client: OllamaClient) -> None:
        self._client = ollama_client

    # ------------------------------------------------------------------
    # Public analysis methods
    # ------------------------------------------------------------------

    async def classify_severity(
        self,
        vulnerability: VulnerabilityInput,
    ) -> SeverityResult:
        """
        Use the LLM to assess the severity of a single vulnerability finding.

        Returns a SeverityResult with severity, confidence, and reasoning.
        Falls back to rule-based defaults on LLM failure.
        """
        prompt = self._client._build_prompt(
            SEVERITY_CLASSIFICATION_PROMPT,
            rule_id=vulnerability.rule_id,
            rule_name=vulnerability.rule_name,
            category=vulnerability.category,
            cwe_id=vulnerability.cwe_id,
            language=vulnerability.language,
            file_path=vulnerability.file_path,
            line_number=vulnerability.line_number,
            description=vulnerability.description,
            code_snippet=vulnerability.code_snippet or "(no snippet provided)",
        )

        raw = await self._client.generate(prompt, system=SYSTEM_PROMPT)
        result = self._parse_severity_response(raw, vulnerability)

        # Record comparison vs. original scanner severity
        if vulnerability.existing_severity:
            result.original_severity = vulnerability.existing_severity
            result.severity_changed = result.severity != vulnerability.existing_severity

        return result

    async def generate_remediation(
        self,
        vulnerability: VulnerabilityInput,
        severity: Optional[SeverityLevel] = None,
    ) -> RemediationResult:
        """
        Generate a code fix and remediation guidance for the given vulnerability.

        Parameters
        ----------
        vulnerability: The vulnerability to remediate.
        severity:      Severity level (used in the prompt for context). If None,
                       uses existing_severity or falls back to 'unknown'.
        """
        sev_str = (
            severity.value
            if severity
            else (vulnerability.existing_severity.value if vulnerability.existing_severity else "unknown")
        )

        prompt = self._client._build_prompt(
            REMEDIATION_PROMPT,
            rule_id=vulnerability.rule_id,
            rule_name=vulnerability.rule_name,
            cwe_id=vulnerability.cwe_id,
            language=vulnerability.language,
            severity=sev_str,
            description=vulnerability.description,
            file_path=vulnerability.file_path,
            line_number=vulnerability.line_number,
            code_snippet=vulnerability.code_snippet or "(no snippet provided)",
        )

        raw = await self._client.generate(prompt, system=SYSTEM_PROMPT)
        return self._parse_remediation_response(raw)

    async def explain_vulnerability(
        self,
        vulnerability: VulnerabilityInput,
        severity: Optional[SeverityLevel] = None,
    ) -> str:
        """
        Generate a plain-language explanation of the vulnerability for developers.

        Returns a prose string (not JSON). Falls back to a structured default
        explanation if the LLM is unavailable.
        """
        sev_str = (
            severity.value
            if severity
            else (vulnerability.existing_severity.value if vulnerability.existing_severity else "unknown")
        )

        prompt = self._client._build_prompt(
            EXPLANATION_PROMPT,
            rule_id=vulnerability.rule_id,
            rule_name=vulnerability.rule_name,
            cwe_id=vulnerability.cwe_id,
            category=vulnerability.category,
            severity=sev_str,
            language=vulnerability.language,
            file_path=vulnerability.file_path,
            line_number=vulnerability.line_number,
            description=vulnerability.description,
            code_snippet=vulnerability.code_snippet or "(no snippet provided)",
        )

        raw = await self._client.generate(prompt, system=SYSTEM_PROMPT)

        # Explanation prompts return prose, not JSON — return as-is if non-empty
        if raw and "unavailable" not in raw.lower():
            return raw.strip()

        # Fallback explanation
        return (
            f"The finding '{vulnerability.rule_name}' (Rule: {vulnerability.rule_id}) "
            f"was detected at {vulnerability.file_path}:{vulnerability.line_number}. "
            f"{vulnerability.description} "
            "AI-powered explanation is currently unavailable. "
            "Please consult the CWE entry and OWASP resources for more information."
        )

    async def reduce_false_positives(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Batch-triage a list of findings to identify likely false positives.

        Returns the same list enriched with 'is_false_positive', 'fp_confidence',
        and 'fp_reasoning' keys per finding.
        """
        if not findings:
            return findings

        # Limit to 20 findings per triage call to stay within token limits
        chunk_size = 20
        enriched: list[dict] = []

        for i in range(0, len(findings), chunk_size):
            chunk = findings[i : i + chunk_size]
            enriched.extend(await self._triage_chunk(chunk))

        return enriched

    # ------------------------------------------------------------------
    # Response parsers
    # ------------------------------------------------------------------

    def _parse_severity_response(
        self,
        response: str,
        vulnerability: VulnerabilityInput,
    ) -> SeverityResult:
        """
        Extract a SeverityResult from the raw LLM response string.

        Tries JSON parsing first, then applies rule-based fallback.
        """
        data = self._extract_json(response)

        if data:
            try:
                severity_str = str(data.get("severity", "")).lower()
                severity = SeverityLevel(severity_str) if severity_str in SeverityLevel._value2member_map_ else None

                confidence = float(data.get("confidence", 0.5))
                confidence = max(0.0, min(1.0, confidence))

                reasoning = str(data.get("reasoning", "No reasoning provided."))
                is_fp = bool(data.get("is_false_positive", False))
                fp_reason = data.get("false_positive_reasoning") or None

                if severity:
                    return SeverityResult(
                        severity=severity,
                        confidence=confidence,
                        reasoning=reasoning,
                        is_false_positive=is_fp,
                        false_positive_reasoning=str(fp_reason) if fp_reason else None,
                        model_used=f"ollama/{self._client.model}",
                    )
            except (ValueError, TypeError, KeyError) as exc:
                logger.warning("Severity JSON parse error: %s | raw=%s", exc, response[:200])

        # Rule-based fallback
        logger.info(
            "Using rule-based severity fallback for rule_id=%s",
            vulnerability.rule_id,
        )
        fallback_severity = self._rule_based_severity(vulnerability.rule_id)
        return SeverityResult(
            severity=fallback_severity,
            confidence=0.4,
            reasoning=(
                "AI analysis was unavailable or returned an unparseable response. "
                "Severity assigned using rule-based heuristics."
            ),
            is_false_positive=False,
            model_used="rule-based-fallback",
        )

    def _parse_remediation_response(self, response: str) -> RemediationResult:
        """
        Extract a RemediationResult from the raw LLM response string.

        Tries JSON parsing first; on failure returns a generic guidance object.
        """
        data = self._extract_json(response)

        if data:
            try:
                references = data.get("references", [])
                if isinstance(references, str):
                    references = [references]

                additional = data.get("additional_steps", [])
                if isinstance(additional, str):
                    additional = [additional]

                return RemediationResult(
                    fixed_code=data.get("fixed_code") or None,
                    explanation=str(data.get("explanation", "No explanation provided.")),
                    references=list(references),
                    estimated_effort=data.get("estimated_effort") or None,
                    breaking_change=bool(data.get("breaking_change", False)),
                    additional_steps=list(additional),
                    model_used=f"ollama/{self._client.model}",
                )
            except (ValueError, TypeError, KeyError) as exc:
                logger.warning("Remediation JSON parse error: %s | raw=%s", exc, response[:200])

        # Fallback: return the raw response as the explanation
        explanation = response.strip() if response else "AI remediation is currently unavailable."
        return RemediationResult(
            fixed_code=None,
            explanation=explanation,
            references=["https://owasp.org/", "https://cwe.mitre.org/"],
            estimated_effort="unknown",
            breaking_change=False,
            additional_steps=["Review the vulnerability manually and apply secure coding guidelines."],
            model_used="rule-based-fallback",
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _triage_chunk(
        self,
        chunk: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Send a chunk of findings to the false-positive triage prompt."""
        import json as _json

        prompt = self._client._build_prompt(
            FALSE_POSITIVE_TRIAGE_PROMPT,
            findings_json=_json.dumps(chunk, indent=2, default=str),
        )

        raw = await self._client.generate(prompt, system=SYSTEM_PROMPT)
        triage_results = self._extract_json(raw)

        if not isinstance(triage_results, list):
            logger.warning("FP triage returned non-list JSON; skipping enrichment")
            return chunk

        triage_map: dict[str, dict] = {}
        for item in triage_results:
            key = f"{item.get('rule_id')}:{item.get('file_path')}:{item.get('line_number')}"
            triage_map[key] = item

        enriched: list[dict] = []
        for finding in chunk:
            key = f"{finding.get('rule_id')}:{finding.get('file_path')}:{finding.get('line_number')}"
            triage = triage_map.get(key, {})
            enriched_finding = dict(finding)
            enriched_finding["is_false_positive"] = triage.get("is_false_positive", False)
            enriched_finding["fp_confidence"] = triage.get("confidence", 0.0)
            enriched_finding["fp_reasoning"] = triage.get("reasoning", "")
            enriched.append(enriched_finding)

        return enriched

    @staticmethod
    def _extract_json(text: str) -> Any:
        """
        Extract and parse a JSON object or array from the raw LLM response.

        Handles:
        - Raw JSON responses
        - JSON wrapped in ```json ... ``` fences
        - JSON embedded within a longer prose response
        """
        if not text:
            return None

        # 1. Try the full text directly
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Try stripping markdown code fences
        match = _JSON_BLOCK_RE.search(text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # 3. Greedy scan: find first { or [ and attempt to parse from there
        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start_idx = text.find(start_char)
            if start_idx == -1:
                continue
            # Find the last matching closing bracket
            end_idx = text.rfind(end_char)
            if end_idx == -1 or end_idx <= start_idx:
                continue
            candidate = text[start_idx : end_idx + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        logger.debug("Could not extract JSON from LLM response: %s", text[:300])
        return None

    @staticmethod
    def _rule_based_severity(rule_id: str) -> SeverityLevel:
        """
        Assign a severity level based on rule_id keywords when the LLM is unavailable.
        """
        rule_lower = rule_id.lower()
        for keyword, severity in _RULE_BASED_SEVERITY.items():
            if keyword in rule_lower:
                return severity
        return SeverityLevel.MEDIUM  # Safe default
