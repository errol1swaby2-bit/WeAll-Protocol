# WeAll-Protocol Dockerfile
#
# External tester goals:
# - align runtime with CI (Python 3.12)
# - run as non-root
# - use a production-style runner (gunicorn + uvicorn worker)
# - auto-generate tx_index.json during image build so fresh clones do not
#   depend on founder-local generated artifacts
# - keep image minimal and deterministic for local external testing

FROM python:3.12-slim

# Set to 1 ONLY for local/dev builds.
# Production images should be built from fully pinned + hashed lockfiles.
ARG ALLOW_UNLOCKED=0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Keep source imports available during image build steps that run project scripts
# before the package itself is installed.
ENV PYTHONPATH=/app/src

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
COPY requirements.lock requirements-dev.lock /app/

# Copy project code needed for installation and generated artifact creation.
COPY src /app/src
COPY scripts /app/scripts
COPY specs /app/specs
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
        if grep -qE '^\s*--hash=sha256:' requirements.lock; then \
          pip install --no-cache-dir --require-hashes -r requirements.lock; \
        else \
          if [ "$ALLOW_UNLOCKED" = "1" ]; then \
            echo "WARNING: requirements.lock is pinned but not hashed; installing without --require-hashes (ALLOW_UNLOCKED=1)."; \
            echo "  Re-generate with ./scripts/lock_deps.sh for production-grade hash locking."; \
            pip install --no-cache-dir -r requirements.lock; \
          else \
            echo "ERROR: requirements.lock is pinned but missing hashes. Re-generate with ./scripts/lock_deps.sh"; \
            exit 2; \
          fi; \
        fi; \
      fi; \
    else \
      if [ "$ALLOW_UNLOCKED" = "1" ]; then \
        echo "WARNING: requirements.lock missing; building with unlocked deps (ALLOW_UNLOCKED=1)."; \
        pip install --no-cache-dir -r requirements.in; \
      else \
        echo "ERROR: requirements.lock missing. Generate a pinned + hashed lockfile before building."; \
        echo "  See scripts/lock_deps.sh"; \
        exit 2; \
      fi; \
    fi \
 && mkdir -p /app/generated /app/data /tmp \
 && PYTHONPATH=/app/src python /app/scripts/gen_tx_index.py \
 && pip install --no-cache-dir . --no-deps

# Ensure runtime dirs exist (data is typically mounted)
RUN chmod +x /app/scripts/run_node.sh \
 && chown -R appuser:appuser /app /tmp

USER appuser

EXPOSE 8000

# Default remains the same, but compose may override this command.
CMD ["sh", "-c", "gunicorn weall.api.app:app \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --workers ${GUNICORN_WORKERS:-2} \
  --timeout ${GUNICORN_TIMEOUT:-60} \
  --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} \
  --keep-alive ${GUNICORN_KEEPALIVE:-5} \
  --access-logfile - \
  --error-logfile -"]
