# Build context = root repo (butuh agent/scan_judol.py untuk probe.py).
#   docker compose build   (dari root repo)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/monitor.db \
    SCANNER_DIR=/app/agent

WORKDIR /app/server

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/scan_judol.py /app/agent/scan_judol.py
COPY server/app.py server/probe.py ./

RUN useradd --system --uid 10001 --home-dir /nonexistent judol \
    && mkdir -p /data && chown judol:judol /data
USER judol
VOLUME ["/data"]

EXPOSE 8000
CMD ["python", "app.py", "run", "--host", "0.0.0.0", "--port", "8000"]
