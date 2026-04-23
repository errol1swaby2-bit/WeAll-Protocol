#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_URL="${WEALL_API_URL:-http://127.0.0.1:8000}"
FRONTEND_URL="${WEALL_FRONTEND_URL:-http://127.0.0.1:5173}"
FRONTEND_ENV_FILE="${WEALL_FRONTEND_ENV_FILE:-../web/.env.local}"
export WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-1}"

log() {
  printf '\n[%s] %s\n' "quickstart" "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

wait_for_url() {
  local url="$1"
  local seconds="${2:-90}"
  local i
  for ((i=1; i<=seconds; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

port_available() {
  local port="$1"
  python3 - "$port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", port))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
}

dump_backend_diagnostics() {
  echo >&2
  echo "Try:" >&2
  echo "  docker compose ps" >&2
  echo "  docker compose logs weall_api --tail 200" >&2
  echo "  docker compose logs weall_producer --tail 200" >&2
  echo "  docker compose logs kubo --tail 200" >&2
}

need_cmd docker
need_cmd python3
need_cmd curl

log "checking required local ports"
for port in 8000 4001 5001 8080; do
  if ! port_available "$port"; then
    echo "ERROR: required local port already in use: $port" >&2
    echo "Stop the conflicting service or change the local compose port mapping before retrying." >&2
    exit 1
  fi
done

log "creating local runtime directories"
mkdir -p data generated data/ipfs
chmod u+rwx data generated >/dev/null 2>&1 || true

local_host_uid="$(id -u)"
local_host_gid="$(id -g)"

if command -v docker >/dev/null 2>&1; then
  docker run --rm \
    -u 0:0 \
    -v "$(pwd):/repo" \
    alpine:3.20 \
    /bin/sh -lc "
      mkdir -p /repo/data /repo/data/ipfs /repo/generated &&
      chown -R ${local_host_uid}:${local_host_gid} /repo/generated /repo/data 2>/dev/null || true &&
      chmod -R u+rwX /repo/generated /repo/data 2>/dev/null || true
    " >/dev/null 2>&1 || true
fi

log "generating tx index"
python3 scripts/gen_tx_index.py

log "preparing mounted runtime state for container user"
if command -v docker >/dev/null 2>&1; then
  docker run --rm \
    -u 0:0 \
    -v "$(pwd):/repo" \
    alpine:3.20 \
    /bin/sh -lc "
      mkdir -p /repo/data /repo/data/ipfs /repo/generated &&
      chown -R 10001:10001 /repo/data /repo/generated 2>/dev/null || true &&
      chmod -R a+rwX /repo/data /repo/generated 2>/dev/null || true
    " >/dev/null 2>&1 || true
fi

log "starting backend stack"
docker compose up -d --build

log "waiting for API readiness at ${API_URL}/v1/readyz"
if ! wait_for_url "${API_URL}/v1/readyz" 120; then
  echo "ERROR: API did not become ready in time." >&2
  dump_backend_diagnostics
  exit 1
fi

log "verifying container health after readiness"
if ! timeout 60 bash -lc '
  for _ in $(seq 1 60); do
    status="$(docker inspect weall-protocol-weall_api-1 --format "{{.State.Health.Status}}" 2>/dev/null || true)"
    if [ "$status" = "healthy" ]; then
      exit 0
    fi
    sleep 1
  done
  exit 1
'; then
  echo "ERROR: weall_api container did not report healthy status after readiness." >&2
  dump_backend_diagnostics
  exit 1
fi

log "backend is ready"
curl -fsS "${API_URL}/v1/readyz" && printf '\n'
curl -fsS "${API_URL}/v1/status" && printf '\n'

cat <<MSG

Quickstart complete.

Backend URLs:
  Ready:  ${API_URL}/v1/readyz
  Status: ${API_URL}/v1/status
  Docs:   ${API_URL}/docs

Frontend startup:
  cd ../web
  cp .env.example .env.local
  npm ci
  npm run dev -- --host 127.0.0.1 --port 5173

Frontend URL:
  ${FRONTEND_URL}

Recommended frontend env file:
  ${FRONTEND_ENV_FILE}

Demo bootstrap command:
  cd ${ROOT_DIR}
  bash ./scripts/demo_bootstrap_tester.sh

Useful checks:
  docker compose ps
  docker compose logs weall_api --tail 200
  docker compose logs weall_producer --tail 200
  docker compose logs kubo --tail 200
  bash scripts/api_smoke.sh
  python scripts/check_generated.py
MSG
