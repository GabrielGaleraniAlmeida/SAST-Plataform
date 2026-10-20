import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from services.ai.app.analyzer import AISecurityAnalyzer
from services.ai.app.llm_client import OllamaClient
from services.ai.app.models import (
    RemediationResult,
    SeverityLevel,
    VulnerabilityInput,
)
from services.api.app.ai_enrichment import apply_ai_enrichment


def make_finding(**overrides):
    values = {
        "rule_id": "SAST-003-command-injection",
        "rule_name": "Command Injection",
        "description": "Untrusted input reaches a shell command.",
        "file_path": "app.py",
        "line_number": 12,
        "language": "python",
    }
    values.update(overrides)
    return VulnerabilityInput(**values)


class FakeOllama:
    model = "test-model"

    def __init__(self, response):
        self.generate = AsyncMock(return_value=response)

    def _build_prompt(self, template, **kwargs):
        return template.format(**{key: value if value is not None else "N/A" for key, value in kwargs.items()})


def test_severity_classification_parses_model_response():
    client = FakeOllama(
        '{"severity":"high","confidence":0.91,"reasoning":"Shell input is attacker-controlled.",'
        '"is_false_positive":false}'
    )
    analyzer = AISecurityAnalyzer(client)

    result = asyncio.run(analyzer.classify_severity(make_finding()))

    assert result.severity is SeverityLevel.HIGH
    assert result.confidence == 0.91
    assert result.is_false_positive is False
    assert result.model_used == "ollama/test-model"


def test_remediation_parses_fix_and_guidance():
    client = FakeOllama(
        '{"fixed_code":"subprocess.run([cmd], shell=False)",'
        '"explanation":"Avoid shell interpretation.","references":["https://example.test"],'
        '"estimated_effort":"low","breaking_change":false,"additional_steps":["Add a regression test"]}'
    )
    analyzer = AISecurityAnalyzer(client)

    result = asyncio.run(analyzer.generate_remediation(make_finding()))

    assert result.fixed_code == "subprocess.run([cmd], shell=False)"
    assert result.explanation == "Avoid shell interpretation."
    assert result.additional_steps == ["Add a regression test"]


def test_invalid_severity_response_uses_rule_based_fallback():
    client = FakeOllama("not JSON")
    analyzer = AISecurityAnalyzer(client)

    result = asyncio.run(analyzer.classify_severity(make_finding()))

    assert result.severity is SeverityLevel.CRITICAL
    assert result.confidence == 0.4
    assert result.is_false_positive is False
    assert result.model_used == "rule-based-fallback"


def test_invalid_remediation_response_is_explicitly_fallback():
    client = FakeOllama("not JSON")
    analyzer = AISecurityAnalyzer(client)

    result: RemediationResult = asyncio.run(analyzer.generate_remediation(make_finding()))

    assert result.fixed_code is None
    assert result.model_used == "rule-based-fallback"
    assert "not JSON" in result.explanation
    assert result.additional_steps


def test_ollama_unavailable_uses_conservative_severity_fallback():
    client = FakeOllama(
        "AI analysis is currently unavailable because the Ollama service could not be reached."
    )
    analyzer = AISecurityAnalyzer(client)

    result = asyncio.run(analyzer.classify_severity(make_finding()))

    assert result.severity is SeverityLevel.CRITICAL
    assert result.confidence == 0.4
    assert result.is_false_positive is False


def test_unreachable_ollama_client_uses_analyzer_fallback():
    async def run():
        client = OllamaClient(base_url="http://ollama.test", model="llama3")
        await client.close()

        def fail_connection(request):
            raise httpx.ConnectError("Ollama is offline", request=request)

        client._client = httpx.AsyncClient(
            base_url=client.base_url,
            transport=httpx.MockTransport(fail_connection),
        )
        try:
            with patch("services.ai.app.llm_client._MAX_RETRIES", 1):
                result = await AISecurityAnalyzer(client).classify_severity(make_finding())
            assert result.severity is SeverityLevel.CRITICAL
            assert result.confidence == 0.4
            assert result.is_false_positive is False
        finally:
            await client.close()

    asyncio.run(run())


def test_ai_false_positive_triage_never_suppresses_finding():
    finding = {"rule_id": "SAST-003", "suppressed": False}
    apply_ai_enrichment(
        finding,
        {
            "severity": "low",
            "is_false_positive": True,
            "confidence": 0.99,
            "false_positive_reasoning": "Model assessment only.",
        },
        {"explanation": "Review the command construction.", "fixed_code": "safe_call()"},
    )

    assert finding["suppressed"] is False
    assert finding["ai_triage"]["is_false_positive"] is True
    assert finding["ai_triage"]["confidence"] == 0.99
    assert finding["ai_suggestion"] == "Review the command construction.\n\nsafe_call()"


def test_ai_triage_corpus_has_labeled_positive_and_negative_cases():
    cases = json.loads(
        (
            Path(__file__).parent / "fixtures" / "ai_triage_cases.json"
        ).read_text(encoding="utf-8")
    )

    assert len({case["id"] for case in cases}) == len(cases)
    assert {case["ground_truth_is_false_positive"] for case in cases} == {False, True}
    assert all(case["finding"]["code_snippet"] for case in cases)
