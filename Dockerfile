# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies in a layer that caches separately from source.
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.txt

# Application source (no .venv, no caches -- see .dockerignore).
COPY main.py ./
COPY src/ ./src/
COPY evals/ ./evals/
COPY scripts/ ./scripts/
COPY web/ ./web/
COPY vault/ ./vault/

# Non-root least-privilege runtime user.
RUN useradd --create-home --uid 10001 mcp && chown -R mcp:mcp /app
USER mcp

ENV MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["python", "main.py", "serve"]
