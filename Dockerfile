FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/monitor.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py probe.py scan_judol.py ./

RUN useradd --system --uid 10001 --home-dir /nonexistent judol \
    && mkdir -p /data && chown judol:judol /data
USER judol
VOLUME ["/data"]

EXPOSE 8000
CMD ["python", "app.py", "run", "--host", "0.0.0.0", "--port", "8000"]
