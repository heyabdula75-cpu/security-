# Production Single-Container Dockerfile (Render / Railway / Fly.io / Cloud Run)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src/backend \
    PORT=8000

WORKDIR /app

# Install backend dependencies
COPY src/backend/requirements.txt /app/src/backend/requirements.txt
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r /app/src/backend/requirements.txt

# Copy backend, frontend, CLI, and seeder
COPY src/backend /app/src/backend
COPY frontend /app/frontend
COPY cli /app/cli
COPY seed_enterprise_demo.py /app/seed_enterprise_demo.py

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8000\")}/health')" || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
