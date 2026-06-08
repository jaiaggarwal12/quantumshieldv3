FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libssl-dev curl openssl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Persist the SQLite DB in a dedicated subdirectory so a data volume does not
# shadow the application code (see docker-compose.yml).
RUN mkdir -p /app/data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/v1/health || exit 1
# Apply DB migrations on boot, then start the server.
CMD ["sh", "-c", "alembic upgrade head; uvicorn app.main:app --host 0.0.0.0 --port 8000"]
