#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${WEB_DIR:-$(cd "$ROOT_DIR/../web" 2>/dev/null && pwd || true)}"
LOG_DIR="$ROOT_DIR/generated/full_stack_logs"
mkdir -p "$LOG_DIR"

BACKEND_LOG="$LOG_DIR/backend.log"
FRONTEND_LOG="$LOG_DIR/frontend.log"
BACKEND_PID_FILE="$LOG_DIR/backend.pid"
FRONTEND_PID_FILE="$LOG_DIR/frontend.pid"

COMPOSE_FILE="$ROOT_DIR/docker-compose.ipfs.yml"
IPFS_SERVICE="${IPFS_SERVICE:-ipfs}"

IPFS_WAIT_SECONDS="${IPFS_WAIT_SECONDS:-180}"
BACKEND_WAIT_SECONDS="${BACKEND_WAIT_SECONDS:-90}"
FRONTEND_WAIT_SECONDS="${FRONTEND_WAIT_SECONDS:-60}"
PORT_WAIT_SECONDS="${PORT_WAIT_SECONDS:-30}"

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"

export WEALL_GENESIS_MODE="${WEALL_GENESIS_MODE:-1}"
export WEALL_MODE="${WEALL_MODE:-dev}"
export WEALL_CHAIN_ID="${WEALL_CHAIN_ID:-weall-dev}"
export WEALL_NODE_ID="${WEALL_NODE_ID:-@satoshi}"
export WEALL_VALIDATOR_ACCOUNT="${WEALL_VALIDATOR_ACCOUNT:-@satoshi}"
export WEALL_NODE_PRIVKEY_FILE="${WEALL_NODE_PRIVKEY_FILE:-$ROOT_DIR/secrets/weall_node_privkey}"
export WEALL_NODE_PUBKEY_FILE="${WEALL_NODE_PUBKEY_FILE:-$ROOT_DIR/secrets/weall_node_pubkey}"
export WEALL_BLOCK_LOOP_ENABLED="${WEALL_BLOCK_LOOP_ENABLED:-1}"
export WEALL_PRODUCE_EMPTY_BLOCKS="${WEALL_PRODUCE_EMPTY_BLOCKS:-1}"
export WEALL_BLOCK_INTERVAL_MS="${WEALL_BLOCK_INTERVAL_MS:-500}"
export WEALL_IPFS_PARTITION_PATH="${WEALL_IPFS_PARTITION_PATH:-$ROOT_DIR/data/ipfs_partition}"

log() {
  printf '[weall-stack] %s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

rotate_log() {
  local file="$1"
  if [[ -f "$file" ]]; then
    mv "$file" "$file.prev" || true
  fi
}

wait_for_http() {
  local url="$1"
  local seconds="$2"
  local label="$3"
  local started now
  started="$(date +%s)"
  log "waiting for ${label} at ${url}"
  while true; do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      log "${label} ready"
      return 0
    fi
    now="$(date +%s)"
    if (( now - started >= seconds )); then
      return 1
    fi
    sleep 1
  done
}

wait_for_ipfs_api() {
  local seconds="$1"
  local started now
  started="$(date +%s)"
  log "waiting for Kubo/IPFS at http://127.0.0.1:5001/api/v0/version"
  while true; do
    if curl -fsS --max-time 2 -X POST 'http://127.0.0.1:5001/api/v0/version' >/dev/null 2>&1; then
      log "Kubo/IPFS ready"
      return 0
    fi
    if docker compose -f "$COMPOSE_FILE" ps --format json "$IPFS_SERVICE" 2>/dev/null | grep -q '"Health":"healthy"'; then
      log "Kubo/IPFS ready"
      return 0
    fi
    now="$(date +%s)"
    if (( now - started >= seconds )); then
      return 1
    fi
    sleep 1
  done
}

wait_for_port_free() {
  local port="$1"
  local seconds="$2"
  local started now
  started="$(date +%s)"
  log "waiting for port ${port} to be free"
  while ss -ltn "( sport = :${port} )" | grep -q ":${port}"; do
    now="$(date +%s)"
    if (( now - started >= seconds )); then
      return 1
    fi
    sleep 1
  done
  return 0
}

kill_pid_file_if_running() {
  local pid_file="$1"
  local label="$2"
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  rm -f "$pid_file"
  if [[ -n "${pid}" ]] && kill -0 "$pid" 2>/dev/null; then
    log "stopping stale ${label} (pid ${pid})"
    kill "$pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
}

ensure_backend_port_is_clear() {
  kill_pid_file_if_running "$BACKEND_PID_FILE" "backend from pid file"
  rm -f "$ROOT_DIR/gunicorn.ctl"

  if ss -ltn "( sport = :${BACKEND_PORT} )" | grep -q ":${BACKEND_PORT}"; then
    log "stale backend appears to still own port ${BACKEND_PORT}; attempting cleanup"
    pkill -f 'gunicorn weall.api.app:app' >/dev/null 2>&1 || true
  fi

  if ! wait_for_port_free "$BACKEND_PORT" "$PORT_WAIT_SECONDS"; then
    log "port ${BACKEND_PORT} is still busy; current listeners:"
    ss -ltnp | grep ":${BACKEND_PORT}" || true
    die "backend port ${BACKEND_PORT} never became free; stale process likely still running"
  fi
}

ensure_frontend_dir() {
  if [[ -z "${WEB_DIR}" || ! -d "${WEB_DIR}" ]]; then
    die "frontend directory not found. Expected sibling ../web or set WEB_DIR=/absolute/path/to/web"
  fi
}

ensure_ipfs_partition() {
  mkdir -p "$WEALL_IPFS_PARTITION_PATH"
}

start_ipfs() {
  [[ -f "$COMPOSE_FILE" ]] || die "missing compose file: $COMPOSE_FILE"
  ensure_ipfs_partition
  log "starting Kubo/IPFS via docker compose"
  docker compose -f "$COMPOSE_FILE" up -d --remove-orphans "$IPFS_SERVICE"
  if ! wait_for_ipfs_api "$IPFS_WAIT_SECONDS"; then
    docker compose -f "$COMPOSE_FILE" ps || true
    docker compose -f "$COMPOSE_FILE" logs "$IPFS_SERVICE" --tail 200 || true
    die "Kubo/IPFS API did not become ready at http://127.0.0.1:5001/api/v0/version"
  fi
  log "IPFS gateway mapped on http://127.0.0.1:8080"
}

start_backend() {
  ensure_backend_port_is_clear
  rotate_log "$BACKEND_LOG"
  log "starting backend node"
  (
    cd "$ROOT_DIR"
    source .venv/bin/activate
    nohup ./scripts/run_node.sh > "$BACKEND_LOG" 2>&1 &
    echo $! > "$BACKEND_PID_FILE"
  )
  if ! wait_for_http "http://${BACKEND_HOST}:${BACKEND_PORT}/v1/readyz" "$BACKEND_WAIT_SECONDS" "backend"; then
    log "backend failed to become ready; recent log output:"
    tail -n 200 "$BACKEND_LOG" || true
    die "backend did not become ready at http://${BACKEND_HOST}:${BACKEND_PORT}/v1/readyz"
  fi
}

start_frontend() {
  ensure_frontend_dir
  kill_pid_file_if_running "$FRONTEND_PID_FILE" "frontend from pid file"
  pkill -f 'vite.*--host' >/dev/null 2>&1 || true
  rotate_log "$FRONTEND_LOG"
  log "starting frontend dev server"
  (
    cd "$WEB_DIR"
    cat > .env.local <<EOF
VITE_API_BASE=http://${BACKEND_HOST}:${BACKEND_PORT}
EOF
    nohup npm run dev -- --host "$FRONTEND_HOST" --port "$FRONTEND_PORT" > "$FRONTEND_LOG" 2>&1 &
    echo $! > "$FRONTEND_PID_FILE"
  )
  if ! wait_for_http "http://${FRONTEND_HOST}:${FRONTEND_PORT}" "$FRONTEND_WAIT_SECONDS" "frontend"; then
    log "frontend failed to become ready; recent log output:"
    tail -n 200 "$FRONTEND_LOG" || true
    die "frontend did not become ready at http://${FRONTEND_HOST}:${FRONTEND_PORT}"
  fi
}

print_summary() {
  cat <<EOF

[weall-stack] full stack is ready

Backend:
  http://${BACKEND_HOST}:${BACKEND_PORT}
Frontend:
  http://${FRONTEND_HOST}:${FRONTEND_PORT}
IPFS API:
  http://127.0.0.1:5001
IPFS Gateway:
  http://127.0.0.1:8080

Logs:
  $BACKEND_LOG
  $FRONTEND_LOG

Stop:
  $ROOT_DIR/scripts/stop_full_stack.sh
EOF
}

main() {
  require_cmd docker
  require_cmd curl
  require_cmd npm
  require_cmd ss

  start_ipfs
  start_backend
  start_frontend
  print_summary
}

main "$@"
