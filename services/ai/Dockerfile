# ============================================================
# AI/LLM Integration Service - Dockerfile
# Python 3.11 slim, Uvicorn, FastAPI
# ============================================================
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Set working directory
WORKDIR /app

# Install system dependencies required for httpx and other packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (leverages Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ ./app/

# Create a non-root user for security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser

# Expose the service port
EXPOSE 8001

# Health check to verify the service is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8001/ai/health || exit 1

# Run the FastAPI application with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2", "--log-level", "info"]
