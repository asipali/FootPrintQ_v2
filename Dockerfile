FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DEBUG=false \
    DATABASE_URL=sqlite:////var/lib/footprintiq/footprintiq.db \
    EVIDENCE_STORAGE_PATH=/var/lib/footprintiq/evidence_storage

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system footprintiq \
    && useradd --system --gid footprintiq --home-dir /app footprintiq \
    && mkdir -p /var/lib/footprintiq/evidence_storage /app/data/temp_scans \
    && chown -R footprintiq:footprintiq /var/lib/footprintiq /app

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY pyproject.toml README.md ./

RUN python -m pip install --no-cache-dir .

RUN chown -R footprintiq:footprintiq /app
USER footprintiq

EXPOSE 8000
VOLUME ["/var/lib/footprintiq"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/health/live', timeout=3)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
