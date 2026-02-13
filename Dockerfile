# ──────────────────────────────────────────────────
#  Sentinel DDoS — Dockerfile
# ──────────────────────────────────────────────────

# ── Stage 1: Build Dashboard ─────────────────────
FROM node:20-alpine AS dashboard-build

WORKDIR /app/dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm ci --silent
COPY dashboard/ ./
RUN npm run build

# ── Stage 2: Python Backend ─────────────────────
FROM python:3.11-slim

LABEL maintainer="danielgabrielyan127"
LABEL description="Sentinel DDoS — AI-Powered Anti-DDoS L7 Firewall"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY src/ ./src/
COPY rules/ ./rules/
COPY simulator/ ./simulator/
COPY pytest.ini .

# Dashboard static files
COPY --from=dashboard-build /app/dashboard/dist ./dashboard/dist

# Environment
ENV SENTINEL_HOST=0.0.0.0
ENV SENTINEL_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
