# =============================================================================
# SAST Platform – API Service Dockerfile
# Python 3.11-slim for minimal attack surface.
# =============================================================================

FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies (cached layer) ────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Application source ─────────────────────────────────────────────────────
COPY app/ ./app/

# ── Runtime user (non-root) ────────────────────────────────────────────────
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app
USER appuser

# ── Expose port ────────────────────────────────────────────────────────────
EXPOSE 8000

# ── Default command ────────────────────────────────────────────────────────
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
