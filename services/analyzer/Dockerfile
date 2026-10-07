# SAST Analyzer Service - Dockerfile
# Python 3.11 slim base image for minimal footprint
FROM python:3.11-slim

# Metadata labels
LABEL maintainer="SAST Platform Team"
LABEL description="SAST Analysis Engine - Static Application Security Testing Service"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r sast && useradd -r -g sast -d /app -s /sbin/nologin sast

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY app/ ./app/

# Change ownership to non-root user
RUN chown -R sast:sast /app

# Switch to non-root user
USER sast

# Expose the service port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Run the application
CMD ["python", "-m", "app.main"]
