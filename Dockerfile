FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=5000

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY scanner/ ./scanner/
COPY web/ ./web/
COPY main.py ./main.py
COPY README.md ./README.md

RUN mkdir -p /app/reports /app/logs \
    && useradd --create-home --uid 10001 scanner \
    && chown -R scanner:scanner /app
USER scanner

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3)"

# Job state and rate limiting are process-local; keep one worker until those
# components move to a shared backend. Threads remain enabled for concurrency.
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--timeout", "120", "--bind", "0.0.0.0:5000", "web.app:app"]
