#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/generated/full_stack_logs"
BACKEND_PID_FILE="$LOG_DIR/backend.pid"
FRONTEND_PID_FILE="$LOG_DIR/frontend.pid"
COMPOSE_FILE="$ROOT_DIR/docker-compose.ipfs.yml"
IPFS_SERVICE="${IPFS_SERVICE:-ipfs}"
PORT_WAIT_SECONDS="${PORT_WAIT_SECONDS:-30}"

log() {
  printf '[weall-stack] %s\n' "$*"
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
    log "stopping ${label} (pid ${pid})"
    kill "$pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
}

wait_for_port_free() {
  local port="$1"
  local seconds="$2"
  local started now
  started="$(date +%s)"
  while ss -ltn "( sport = :${port} )" | grep -q ":${port}"; do
    now="$(date +%s)"
    if (( now - started >= seconds )); then
      return 1
    fi
    sleep 1
  done
  return 0
}

kill_pid_file_if_running "$FRONTEND_PID_FILE" "frontend"
pkill -f 'vite.*--host' >/dev/null 2>&1 || true

kill_pid_file_if_running "$BACKEND_PID_FILE" "backend"
pkill -f 'gunicorn weall.api.app:app' >/dev/null 2>&1 || true
rm -f "$ROOT_DIR/gunicorn.ctl"

if [[ -f "$COMPOSE_FILE" ]]; then
  log "stopping Kubo/IPFS"
  docker compose -f "$COMPOSE_FILE" stop "$IPFS_SERVICE" >/dev/null 2>&1 || true
fi

log "ensuring port 8000 is free"
if ! wait_for_port_free 8000 "$PORT_WAIT_SECONDS"; then
  log "port 8000 is still busy after stop; current listeners:"
  ss -ltnp | grep ':8000' || true
  exit 1
fi

log "done"
