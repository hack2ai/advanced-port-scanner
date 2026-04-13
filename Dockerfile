# ── Dockerfile — Advanced Port Scanner ───────────────────────────────────────
#
# Build:   docker build -t port-scanner .
# Run CLI: docker run --rm -it port-scanner python main.py -t <target> -p 1-1024
# Run Web: docker run --rm -p 5000:5000 port-scanner python web/app.py
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# System dependencies (ping for OS fingerprinting, net-tools for debugging)
RUN apt-get update && apt-get install -y --no-install-recommends \
      iputils-ping \
      net-tools \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /app

# Install Python dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY scanner/    ./scanner/
COPY web/        ./web/
COPY main.py     .

# Create output/log directories
RUN mkdir -p reports logs

# Expose Flask port
EXPOSE 5000

# Default: launch the web dashboard
CMD ["python", "web/app.py"]
