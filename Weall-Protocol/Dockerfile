# WeAll-Protocol Dockerfile (prod-lean baseline)
#
# Goals:
# - Align runtime with CI (Python 3.12)
# - Run as non-root
# - Use a production runner (gunicorn + uvicorn worker)
# - Keep image minimal, deterministic, and safe under read-only FS

FROM python:3.12-slim

# Set to 1 ONLY for local/dev builds.
# Production images should be built from fully pinned lockfiles.
ARG ALLOW_UNLOCKED=0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Minimal system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Create an unprivileged user
RUN groupadd -g 10001 appuser \
 && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin appuser

# Copy dependency manifests first to maximize Docker layer cache.
COPY pyproject.toml README.md /app/
COPY requirements.in requirements-dev.in /app/
# Optional lockfiles (preferred when present)
COPY requirements.lock requirements-dev.lock /app/

# Copy project code
COPY src /app/src
COPY generated /app/generated

# Install deps (prefer lockfiles when present) + package
RUN pip install --no-cache-dir -U pip setuptools wheel \
 && if [ -f requirements.lock ]; then \
      if grep -qE '^\s*-r\s+requirements\.in\s*$' requirements.lock; then \
        if [ "$ALLOW_UNLOCKED" = "1" ]; then \
          echo "WARNING: requirements.lock is a placeholder; building with unlocked deps (ALLOW_UNLOCKED=1)."; \
          pip install --no-cache-dir -r requirements.in; \
        else \
          echo "ERROR: requirements.lock is a placeholder (unlocked). Generate a pinned lockfile before building."; \
          echo "  See scripts/lock_deps.sh"; \
          exit 2; \
        fi; \
      else \
        pip install --no-cache-dir -r requirements.lock; \
      fi; \
    else \
      if [ "$ALLOW_UNLOCKED" = "1" ]; then \
        echo "WARNING: requirements.lock missing; building with unlocked deps (ALLOW_UNLOCKED=1)."; \
        pip install --no-cache-dir -r requirements.in; \
      else \
        echo "ERROR: requirements.lock missing. Generate a pinned lockfile before building."; \
        echo "  See scripts/lock_deps.sh"; \
        exit 2; \
      fi; \
    fi \
 && pip install --no-cache-dir . --no-deps

# Ensure runtime dirs exist (data is typically mounted)
RUN mkdir -p /app/data /tmp \
 && chown -R appuser:appuser /app /tmp

USER appuser

EXPOSE 8000

# Env-tunable gunicorn defaults (override via docker-compose env)
# - Workers: generally 2-4 for small nodes; start conservative
# - Timeout: allow some headroom for block/attestation operations
CMD ["sh", "-c", "gunicorn weall.api.app:app \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --workers ${GUNICORN_WORKERS:-2} \
  --timeout ${GUNICORN_TIMEOUT:-60} \
  --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} \
  --keep-alive ${GUNICORN_KEEPALIVE:-5} \
  --access-logfile - \
  --error-logfile -"]
