"""
AI/LLM Integration Service - FastAPI Application
=================================================
Exposes REST endpoints for AI-powered vulnerability analysis.

Endpoints:
  POST /ai/classify-severity  — AI severity classification
  POST /ai/remediate          — Code fix generation
  POST /ai/explain            — Plain-language explanation
  POST /ai/batch-analyze      — Batch processing of multiple findings
  GET  /ai/health             — Ollama connectivity health check
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from app.analyzer import AISecurityAnalyzer
from app.llm_client import OllamaClient
from app.models import (
    BatchFindingResult,
    BatchRequest,
    BatchResponse,
    HealthResponse,
    RemediationResult,
    SeverityResult,
    VulnerabilityInput,
)
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

_state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize Ollama client on startup and close on shutdown."""
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3")
    logger.info("Starting AI service — Ollama URL: %s Model: %s", ollama_url, ollama_model)

    client = OllamaClient(base_url=ollama_url, model=ollama_model)
    analyzer = AISecurityAnalyzer(ollama_client=client)
    _state["client"] = client
    _state["analyzer"] = analyzer

    yield
    logger.info("Shutting down AI service")
    await client.close()


app = FastAPI(
    title="SAST AI/LLM Integration Service",
    description=(
        "AI-powered security analysis module for the SAST platform. "
        "Uses local LLMs via Ollama to classify severity, generate remediations, "
        "explain vulnerabilities, and reduce false positives."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/ai/docs",
    redoc_url="/ai/redoc",
    openapi_url="/ai/openapi.json",
)

_allowed_origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_analyzer() -> AISecurityAnalyzer:
    """Return the shared AISecurityAnalyzer instance."""
    analyzer = _state.get("analyzer")
    if analyzer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI analyzer is not initialized",
        )
    return analyzer


@app.exception_handler(Exception)
async def handle_exception(request: Request, exc: Exception) -> JSONResponse:
    """Handle unhandled server errors."""
    logger.exception("Unhandled exception on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


@app.get("/ai/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> JSONResponse:
    """Check that Ollama is reachable and the configured model is installed."""
    client: OllamaClient = _state.get("client")  # type: ignore[assignment]
    if client is None:
        payload = HealthResponse(
            status="unhealthy",
            ollama_connected=False,
            ollama_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=os.getenv("OLLAMA_MODEL", "llama3"),
            message="Service initialisation is not complete.",
        )
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload.model_dump())

    is_ready = await client.health_check()
    payload = HealthResponse(
        status="healthy" if is_ready else "degraded",
        ollama_connected=is_ready,
        ollama_url=client.base_url,
        model=client.model,
        message=(
            "Ollama is reachable and the configured model is ready."
            if is_ready
            else (
                f"Ollama is unavailable or model '{client.model}' is not installed. "
                "AI features will use rule-based fallbacks."
            )
        ),
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=payload.model_dump(),
    )


@app.post("/ai/classify-severity", response_model=SeverityResult, tags=["Analysis"])
async def classify_severity(vulnerability: VulnerabilityInput) -> SeverityResult:
    """Classify vulnerability severity using AI."""
    analyzer = get_analyzer()
    logger.info(
        "classify-severity request: rule_id=%s file=%s:%d",
        vulnerability.rule_id,
        vulnerability.file_path,
        vulnerability.line_number,
    )
    result = await analyzer.classify_severity(vulnerability)
    logger.info(
        "classify-severity result: severity=%s confidence=%.2f fp=%s",
        result.severity,
        result.confidence,
        result.is_false_positive,
    )
    return result


@app.post("/ai/remediate", response_model=RemediationResult, tags=["Analysis"])
async def remediate(vulnerability: VulnerabilityInput) -> RemediationResult:
    """Generate remediation code for a vulnerability."""
    analyzer = get_analyzer()
    logger.info(
        "remediate request: rule_id=%s file=%s:%d",
        vulnerability.rule_id,
        vulnerability.file_path,
        vulnerability.line_number,
    )
    result = await analyzer.generate_remediation(vulnerability)
    return result


@app.post("/ai/explain", response_model=dict, tags=["Analysis"])
async def explain(vulnerability: VulnerabilityInput) -> dict:
    """Explain a vulnerability in plain language."""
    analyzer = get_analyzer()
    logger.info(
        "explain request: rule_id=%s file=%s:%d",
        vulnerability.rule_id,
        vulnerability.file_path,
        vulnerability.line_number,
    )
    explanation = await analyzer.explain_vulnerability(vulnerability)
    return {
        "rule_id": vulnerability.rule_id,
        "rule_name": vulnerability.rule_name,
        "file_path": vulnerability.file_path,
        "line_number": vulnerability.line_number,
        "explanation": explanation,
    }


@app.post("/ai/batch-analyze", response_model=BatchResponse, tags=["Analysis"])
async def batch_analyze(request: BatchRequest) -> BatchResponse:
    """Batch AI analysis of multiple vulnerability findings."""
    analyzer = get_analyzer()
    vulnerabilities = request.vulnerabilities
    logger.info(
        "batch-analyze: %d findings, remediation=%s, explanation=%s",
        len(vulnerabilities),
        request.include_remediation,
        request.include_explanation,
    )

    severity_tasks = [analyzer.classify_severity(v) for v in vulnerabilities]
    severity_outcomes = await asyncio.gather(*severity_tasks, return_exceptions=True)

    remediation_outcomes: list[Any] = [None] * len(vulnerabilities)
    if request.include_remediation:
        remediation_tasks = [
            analyzer.generate_remediation(v, sev.severity if not isinstance(sev, Exception) else None)
            for v, sev in zip(vulnerabilities, severity_outcomes)
        ]
        remediation_outcomes = await asyncio.gather(*remediation_tasks, return_exceptions=True)

    explanation_outcomes: list[Any] = [None] * len(vulnerabilities)
    if request.include_explanation:
        explanation_tasks = [
            analyzer.explain_vulnerability(v, sev.severity if not isinstance(sev, Exception) else None)
            for v, sev in zip(vulnerabilities, severity_outcomes)
        ]
        explanation_outcomes = await asyncio.gather(*explanation_tasks, return_exceptions=True)
    results: list[BatchFindingResult] = []
    processed = 0
    failed = 0

    for i, vuln in enumerate(vulnerabilities):
        sev_outcome = severity_outcomes[i]
        rem_outcome = remediation_outcomes[i]
        exp_outcome = explanation_outcomes[i]

        finding_error: str | None = None
        sev_result: SeverityResult | None = None
        rem_result: RemediationResult | None = None
        explanation: str | None = None

        if isinstance(sev_outcome, Exception):
            finding_error = f"Severity classification failed: {sev_outcome}"
            failed += 1
            logger.warning("Severity failed for %s:%d — %s", vuln.file_path, vuln.line_number, sev_outcome)
        else:
            sev_result = sev_outcome
            processed += 1

        if isinstance(rem_outcome, Exception):
            logger.warning("Remediation failed for %s:%d — %s", vuln.file_path, vuln.line_number, rem_outcome)
        elif rem_outcome is not None:
            rem_result = rem_outcome

        if isinstance(exp_outcome, Exception):
            logger.warning("Explanation failed for %s:%d — %s", vuln.file_path, vuln.line_number, exp_outcome)
        elif exp_outcome is not None:
            explanation = exp_outcome

        results.append(
            BatchFindingResult(
                rule_id=vuln.rule_id,
                file_path=vuln.file_path,
                line_number=vuln.line_number,
                severity_result=sev_result,
                remediation_result=rem_result,
                explanation=explanation,
                error=finding_error,
            )
        )

    fp_candidates = [
        {
            "rule_id": r.rule_id,
            "file_path": r.file_path,
            "line_number": r.line_number,
            "description": vulnerabilities[i].description,
            "code_snippet": vulnerabilities[i].code_snippet,
        }
        for i, r in enumerate(results)
        if r.severity_result is not None
    ]

    high_fp_rule_ids: list[str] = []
    if fp_candidates:
        try:
            triaged = await analyzer.reduce_false_positives(fp_candidates)
            high_fp_rule_ids = [
                t["rule_id"] for t in triaged if t.get("is_false_positive") and float(t.get("fp_confidence", 0)) >= 0.75
            ]
        except Exception as exc:
            logger.warning("False-positive triage failed: %s", exc)

    logger.info(
        "batch-analyze complete: processed=%d failed=%d high_fp=%d",
        processed,
        failed,
        len(high_fp_rule_ids),
    )

    return BatchResponse(
        total=len(vulnerabilities),
        processed=processed,
        failed=failed,
        results=results,
        high_confidence_false_positives=high_fp_rule_ids,
    )


@app.get("/", include_in_schema=False)
async def root() -> dict:
    """API root."""
    return {
        "service": "SAST AI/LLM Integration Service",
        "version": "1.0.0",
        "docs": "/ai/docs",
    }


from typing import Any  # noqa: E402
