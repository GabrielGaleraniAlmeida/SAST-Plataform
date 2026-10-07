"""Celery task that runs one scan: analyzer -> AI enrichment -> database."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
from app.config import settings
from app.enums import ScanStatus, Severity
from app.models import Scan, ScanFile, Vulnerability
from celery import Celery
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

celery_app = Celery("sast_tasks", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
celery_app.conf.update(task_track_started=True, task_acks_late=True, worker_prefetch_multiplier=1)

_engine = create_engine(settings.DATABASE_URL.replace("+asyncpg", "+psycopg2"), pool_pre_ping=True)
SyncSession = sessionmaker(bind=_engine, expire_on_commit=False)

AI_BATCH_SIZE = 10
FALSE_POSITIVE_MIN_CONFIDENCE = 0.75


def _enrich_with_ai(findings: List[Dict[str, Any]]) -> None:
    """Best-effort: AI severity, false-positive triage and remediation (in place)."""
    for start in range(0, len(findings), AI_BATCH_SIZE):
        chunk = findings[start : start + AI_BATCH_SIZE]
        payload = {
            "vulnerabilities": [
                {
                    "rule_id": f["rule_id"],
                    "rule_name": f["rule_name"],
                    "description": (f.get("description") or f["rule_name"]).ljust(10, "."),
                    "file_path": f["file_path"],
                    "line_number": max(int(f.get("line_number") or 1), 1),
                    "code_snippet": f.get("code_snippet"),
                    "language": f.get("language") or "unknown",
                    "cwe_id": f.get("cwe_id"),
                    "existing_severity": f.get("severity"),
                }
                for f in chunk
            ],
            "include_remediation": True,
        }
        try:
            resp = httpx.post(f"{settings.AI_URL}/ai/batch-analyze", json=payload, timeout=settings.AI_TIMEOUT)
            resp.raise_for_status()
            results = resp.json()["results"]
        except Exception as exc:
            logger.warning("AI enrichment skipped: %s", exc)
            return
        for finding, res in zip(chunk, results):
            sev, rem = res.get("severity_result"), res.get("remediation_result")
            if sev:
                finding["ai_severity"] = sev["severity"]
                if sev["is_false_positive"] and sev["confidence"] >= FALSE_POSITIVE_MIN_CONFIDENCE:
                    finding["suppressed"] = True
                    finding["suppressed_reason"] = sev.get("false_positive_reasoning") or "AI: likely false positive"
            if rem:
                finding["ai_suggestion"] = "\n\n".join(filter(None, [rem["explanation"], rem.get("fixed_code")]))


@celery_app.task(bind=True, name="sast.run_scan")
def run_scan(self, scan_id: int) -> Dict[str, Any]:
    with SyncSession() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")
        scan.status = ScanStatus.RUNNING
        db.commit()

        try:
            resp = httpx.post(
                f"{settings.ANALYZER_URL}/analyze",
                json={
                    "repository_url": scan.repository_url,
                    "branch": scan.branch,
                    "language": scan.language or "auto",
                },
                timeout=settings.ANALYZER_TIMEOUT,
            )
            resp.raise_for_status()
            result = resp.json()
            findings: List[Dict[str, Any]] = result["vulnerabilities"]
            _enrich_with_ai(findings)

            for f in findings:
                try:
                    severity = Severity(f.get("severity", "info"))
                except ValueError:
                    severity = Severity.INFO
                db.add(
                    Vulnerability(
                        scan_id=scan_id,
                        file_path=f["file_path"],
                        line_number=max(int(f.get("line_number") or 1), 1),
                        column=f.get("column"),
                        rule_id=f["rule_id"],
                        rule_name=f["rule_name"],
                        severity=severity,
                        cwe_id=f.get("cwe_id"),
                        title=f.get("title") or f["rule_name"],
                        description=f.get("description"),
                        code_snippet=f.get("code_snippet"),
                        ai_suggestion=f.get("ai_suggestion"),
                        ai_severity=f.get("ai_severity"),
                        confidence=f.get("confidence"),
                        suppressed=f.get("suppressed", False),
                        suppressed_reason=f.get("suppressed_reason"),
                    )
                )
            db.add_all(ScanFile(scan_id=scan_id, **file) for file in result["files"])

            scan.total_files = result["total_files"]
            scan.total_vulnerabilities = sum(1 for f in findings if not f.get("suppressed"))
            scan.status = ScanStatus.COMPLETED
        except Exception:
            logger.exception("Scan %s failed", scan_id)
            db.rollback()
            scan = db.get(Scan, scan_id)
            scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(tz=timezone.utc)
        db.commit()
        return {"scan_id": scan_id, "status": scan.status.value}
