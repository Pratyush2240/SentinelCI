# Build context is the repo root (not audit_service/), enabling package imports
# like `uvicorn audit_service.main:app`.
# In Railway, point to this file via the RAILWAY_DOCKERFILE_PATH="audit_service/Dockerfile"
# variable while keeping the build context at the repo root.

FROM python:3.13-slim

WORKDIR /app

# Copy requirements first so the dependency layer caches
COPY audit_service/requirements.txt ./audit_service/requirements.txt
RUN pip install --no-cache-dir -r audit_service/requirements.txt

# Copy audit_service package source
COPY audit_service/ ./audit_service/

# Create and switch to a non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Bind to 0.0.0.0 and use Railway's injected PORT env var (defaults to 8000) without --reload
CMD ["sh", "-c", "uvicorn audit_service.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
