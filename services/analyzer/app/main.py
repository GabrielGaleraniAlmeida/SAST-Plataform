"""SAST analyzer service: one synchronous endpoint; queuing is done by the API's Celery worker."""

import asyncio
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException

from app.engine.scanner import SASTScanner
from app.models import AnalysisRequest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.scanner = SASTScanner()
    yield


app = FastAPI(title="SAST Analyzer Service", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "sast-analyzer"}


@app.post("/analyze")
async def analyze(request: AnalysisRequest):
    """Scan `repository_url` or `code_content`. Returns {vulnerabilities, files, total_files}."""
    scanner: SASTScanner = app.state.scanner
    lang = request.language.value
    loop = asyncio.get_running_loop()

    if request.code_content:
        snippet_lang = scanner.parser.get_language(request.filename)
        if snippet_lang == "unknown":
            snippet_lang = "python"
        found = await loop.run_in_executor(
            None, scanner.scan_snippet, request.code_content, snippet_lang, request.filename
        )
        return {"vulnerabilities": found, "files": [], "total_files": 1}
    if request.repository_url:
        try:
            return await loop.run_in_executor(
                None, scanner.scan_repository, request.repository_url, request.branch, lang
            )
        except Exception as exc:
            logger.exception("Scan failed")
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    raise HTTPException(status_code=422, detail="Provide 'repository_url' or 'code_content'.")


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8001)
