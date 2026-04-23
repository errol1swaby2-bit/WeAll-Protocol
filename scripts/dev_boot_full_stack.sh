#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${ROOT_DIR}/Weall-Protocol"
FRONTEND_DIR="${ROOT_DIR}/web"
PYTHON_BIN="${BACKEND_DIR}/.venv/bin/python"
DEV_STATE_DIR="${ROOT_DIR}/.weall-dev"
FRONTEND_PID_FILE="${DEV_STATE_DIR}/frontend.pid"
FRONTEND_LOG="${DEV_STATE_DIR}/frontend.log"

log() {
  printf '[dev-full-surface] %s\n' "$*"
}

fail() {
  log "ERROR: $*"
  exit 1
}

ensure_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command not found: $1"
  fi
}

pid_is_running() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

port_in_use() {
  local port="$1"
  python3 - "$port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", port))
except OSError:
    sys.exit(0)
else:
    sys.exit(1)
finally:
    sock.close()
PY
}

wait_for_url() {
  local url="$1"
  local seconds="${2:-60}"
  local i
  for ((i=1; i<=seconds; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_port_release() {
  local port="$1"
  local attempts="${2:-12}"
  local delay_seconds="${3:-1}"
  local i
  for ((i=1; i<=attempts; i++)); do
    if ! port_in_use "$port"; then
      return 0
    fi
    if [ "$i" -eq 1 ]; then
      log "waiting for port ${port} to release"
    else
      log "port ${port} still busy; waiting (${i}/${attempts})"
    fi
    sleep "$delay_seconds"
  done
  ! port_in_use "$port"
}

kill_pids() {
  local pids="$1"
  if [ -z "$pids" ]; then
    return 0
  fi
  kill $pids >/dev/null 2>&1 || true
  sleep 1
  kill -9 $pids >/dev/null 2>&1 || true
}

kill_port_tcp() {
  local port="$1"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
  fi

  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -t -i TCP:"${port}" -sTCP:LISTEN 2>/dev/null | tr '\n' ' ' || true)"
    kill_pids "$pids"
  fi

  if command -v ss >/dev/null 2>&1; then
    local pids
    pids="$(ss -ltnp "( sport = :${port} )" 2>/dev/null | grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u | tr '\n' ' ' || true)"
    kill_pids "$pids"
  fi
}

stop_repo_compose() {
  if command -v docker >/dev/null 2>&1; then
    (
      cd "$BACKEND_DIR"
      docker compose down --remove-orphans >/dev/null 2>&1 || true
    )
  fi
}

cleanup_frontend_process() {
  mkdir -p "$DEV_STATE_DIR"
  if [ -f "$FRONTEND_PID_FILE" ]; then
    local old_pid
    old_pid="$(cat "$FRONTEND_PID_FILE" 2>/dev/null || true)"
    if [ -n "$old_pid" ] && pid_is_running "$old_pid"; then
      log "stopping previous frontend pid=$old_pid"
      kill "$old_pid" >/dev/null 2>&1 || true
      if ! wait_for_port_release 5173 8 1 && pid_is_running "$old_pid"; then
        kill -9 "$old_pid" >/dev/null 2>&1 || true
      fi
    fi
    rm -f "$FRONTEND_PID_FILE"
  fi

  pkill -f "vite --host 127.0.0.1 --port 5173" >/dev/null 2>&1 || true
  pkill -f "npm run dev -- --host 127.0.0.1 --port 5173" >/dev/null 2>&1 || true
  pkill -f ".*/node_modules/.*/vite.*127\.0\.0\.1.*5173" >/dev/null 2>&1 || true
  wait_for_port_release 5173 8 1 >/dev/null 2>&1 || true
}

ensure_backend_state_dirs() {
  mkdir -p \
    "${BACKEND_DIR}/data" \
    "${BACKEND_DIR}/data/ipfs" \
    "${BACKEND_DIR}/generated" \
    "$DEV_STATE_DIR"
  chmod u+rwx "${BACKEND_DIR}/data" "${BACKEND_DIR}/generated" >/dev/null 2>&1 || true
}

normalize_repo_permissions() {
  log "normalizing repo permissions for backend state"

  ensure_backend_state_dirs

  local host_uid host_gid
  host_uid="$(id -u)"
  host_gid="$(id -g)"

  if command -v docker >/dev/null 2>&1; then
    docker run --rm \
      -u 0:0 \
      -v "${BACKEND_DIR}:/repo" \
      alpine:3.20 \
      /bin/sh -lc "
        mkdir -p /repo/data /repo/data/ipfs /repo/generated &&
        chown -R ${host_uid}:${host_gid} /repo/data /repo/generated 2>/dev/null || true &&
        chmod -R u+rwX /repo/data /repo/generated 2>/dev/null || true
      " >/dev/null 2>&1 || true
  fi

  chmod -R u+rwX "${BACKEND_DIR}/data" "${BACKEND_DIR}/generated" >/dev/null 2>&1 || true
}

reset_dev_state() {
  log "resetting deterministic dev state"
  normalize_repo_permissions

  if command -v docker >/dev/null 2>&1; then
    docker run --rm \
      -u 0:0 \
      -v "${BACKEND_DIR}:/repo" \
      alpine:3.20 \
      /bin/sh -lc "
        rm -f /repo/data/weall.db \
              /repo/data/weall.db-shm \
              /repo/data/weall.db-wal \
              /repo/data/weall.aux.sqlite \
              /repo/data/weall.aux.sqlite-shm \
              /repo/data/weall.aux.sqlite-wal \
              /repo/data/weall.aux_helper_lanes \
              /repo/data/weall.db.bft_journal.jsonl \
              /repo/generated/demo_bootstrap_result.json
      " >/dev/null 2>&1 || true
  fi

  rm -f "${BACKEND_DIR}/data/weall.db" \
        "${BACKEND_DIR}/data/weall.db-shm" \
        "${BACKEND_DIR}/data/weall.db-wal" \
        "${BACKEND_DIR}/data/weall.aux.sqlite" \
        "${BACKEND_DIR}/data/weall.aux.sqlite-shm" \
        "${BACKEND_DIR}/data/weall.aux.sqlite-wal" \
        "${BACKEND_DIR}/data/weall.aux_helper_lanes" \
        "${BACKEND_DIR}/data/weall.db.bft_journal.jsonl" \
        "${BACKEND_DIR}/generated/demo_bootstrap_result.json" \
        "${FRONTEND_DIR}/public/dev-bootstrap.json" 2>/dev/null || true

  normalize_repo_permissions
}

self_heal_ports() {
  log "self-healing local ports"
  stop_repo_compose
  cleanup_frontend_process

  for port in 8000 5173; do
    if port_in_use "$port"; then
      log "port ${port} still in use; attempting local cleanup"
      kill_port_tcp "$port"
      wait_for_port_release "$port" 12 1 >/dev/null 2>&1 || true
    fi
  done

  if port_in_use 5173; then
    log "port 5173 still in use; attempting targeted frontend cleanup"
    cleanup_frontend_process
    kill_port_tcp 5173
    wait_for_port_release 5173 12 1 >/dev/null 2>&1 || true
  fi

  local stubborn=0
  for port in 8000 5173; do
    if port_in_use "$port"; then
      log "port ${port} remains in use after cleanup"
      stubborn=1
    fi
  done

  if [ "$stubborn" -ne 0 ]; then
    echo >&2
    echo "Automatic cleanup could not free all required ports." >&2
    echo "Run these diagnostics:" >&2
    echo "  lsof -i :8000 -P -n" >&2
    echo "  lsof -i :5173 -P -n" >&2
    echo "  ss -ltnp | grep -E ':8000|:5173'" >&2
    echo "  ps aux | grep -E 'vite|npm run dev|node.*5173' | grep -v grep" >&2
    echo "  docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Ports}}'" >&2
    fail "required local ports are still busy"
  fi
}


ensure_backend_venv() {
  if [ -x "$PYTHON_BIN" ]; then
    return 0
  fi

  log "backend venv missing; creating ${BACKEND_DIR}/.venv"
  (
    cd "$BACKEND_DIR"
    python3 -m venv .venv
    "$PYTHON_BIN" -m pip install --upgrade pip setuptools wheel >/dev/null
    "$PYTHON_BIN" -m pip install -e ".[test]" >/dev/null
  ) || fail "failed to create backend virtualenv"
}

ensure_frontend_deps() {
  local vite_bin="${FRONTEND_DIR}/node_modules/.bin/vite"
  local pkg_lock="${FRONTEND_DIR}/package-lock.json"
  local pkg_json="${FRONTEND_DIR}/package.json"
  local install_needed=0

  if [ ! -x "$vite_bin" ]; then
    install_needed=1
  elif [ -f "$pkg_lock" ] && [ "$pkg_lock" -nt "$vite_bin" ]; then
    install_needed=1
  elif [ -f "$pkg_json" ] && [ "$pkg_json" -nt "$vite_bin" ]; then
    install_needed=1
  fi

  if [ "$install_needed" -eq 0 ]; then
    return 0
  fi

  log "frontend dependencies missing or stale; running npm ci"
  (
    cd "$FRONTEND_DIR"
    npm ci
  ) || fail "frontend dependency install failed"
}

write_frontend_env() {
  mkdir -p "$FRONTEND_DIR"
  cat > "${FRONTEND_DIR}/.env.local" <<'ENV'
VITE_WEALL_APP_NAME=WeAll
VITE_WEALL_ENV_LABEL=dev
VITE_WEALL_ENABLE_DEV_TOOLS=1
VITE_WEALL_ENABLE_DEV_BOOTSTRAP=1
VITE_WEALL_API_BASE=/
VITE_WEALL_DEV_BOOTSTRAP_MANIFEST=/dev-bootstrap.json
VITE_WEALL_EMAIL_ORACLE_BASE=/
ENV
}

start_frontend() {
  cleanup_frontend_process
  write_frontend_env
  ensure_frontend_deps
  mkdir -p "$DEV_STATE_DIR"

  log "starting frontend"
  (
    cd "$FRONTEND_DIR"
    nohup npm run dev -- --host 127.0.0.1 --port 5173 >"$FRONTEND_LOG" 2>&1 &
    echo $! > "$FRONTEND_PID_FILE"
  )

  log "waiting for frontend at http://127.0.0.1:5173"
  if ! wait_for_url "http://127.0.0.1:5173" 90; then
    echo >&2
    echo "Frontend failed to become ready. Last log lines:" >&2
    tail -n 200 "$FRONTEND_LOG" >&2 || true
    fail "frontend failed to start"
  fi
}

main() {
  ensure_cmd curl
  ensure_cmd python3
  ensure_cmd npm
  ensure_cmd docker

  log "root=${ROOT_DIR}"
  log "backend=${BACKEND_DIR}"
  log "frontend=${FRONTEND_DIR}"
  log "python=${PYTHON_BIN}"

  ensure_backend_venv

  self_heal_ports
  reset_dev_state

  log "starting canonical backend quickstart with explicit PYTHONPATH"
  (
    cd "$BACKEND_DIR"
    WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-1}" PYTHONPATH=src bash ./scripts/quickstart_tester.sh
  ) || fail "canonical backend quickstart failed; inspect diagnostics printed above"

  log "verifying backend ready"
  wait_for_url "http://127.0.0.1:8000/v1/readyz" 30 || fail "backend did not report ready"

  log "running canonical demo bootstrap"
  (
    cd "$BACKEND_DIR"
    PYTHONPATH=src bash ./scripts/demo_bootstrap_tester.sh
  ) || fail "canonical demo bootstrap failed"

  log "writing frontend dev bootstrap manifest from canonical demo summary"
  "$PYTHON_BIN" - <<'PY'
import json
from pathlib import Path

repo = Path.cwd()
backend = repo / "Weall-Protocol"
frontend = repo / "web"
summary_path = backend / "generated" / "demo_bootstrap_result.json"
summary = json.loads(summary_path.read_text(encoding="utf-8"))
manifest = {
    "account": summary.get("account"),
    "pubkeyB64": summary.get("pubkey_b64"),
    "post_body": summary.get("post_body") or summary.get("demo_post_body") or "External tester demo post",
    "summary_path": str(summary_path),
    "seededGroup": summary.get("seeded_group"),
    "seededProposal": summary.get("seeded_proposal"),
    "seededDispute": summary.get("seeded_dispute"),
    "recommendedPath": summary.get("recommended_path"),
    "fallbackInstructions": [
        "If a screen looks stale, use the page-level Refresh button before retrying the action.",
        "If a signed action appears stuck, wait for the signer busy notice to clear so the next nonce stays monotonic.",
        "If the browser session drifts, return to Login and press Load demo tester session again.",
    ],
    "resetInstructions": [
        "Run ./scripts/dev_boot_full_stack.sh from the repo root to rebuild the deterministic demo state.",
        "Use the generated dev bootstrap card on Login to restore the seeded tester instantly after reset.",
        "Canonical public metadata remains in Weall-Protocol/generated/demo_bootstrap_result.json and web/public/dev-bootstrap.json, while the private key stays local-only.",
    ],
    "apiBase": "/",
    "api_base": "/",
}
out_path = frontend / "public" / "dev-bootstrap.json"
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
secret_summary_path = backend / "generated" / "demo_bootstrap_secret.json"
secret_local_path = repo / ".weall-dev" / "dev-bootstrap-secret.json"
if secret_summary_path.exists():
    secret_local_path.parent.mkdir(parents=True, exist_ok=True)
    secret_local_path.write_text(secret_summary_path.read_text(encoding="utf-8"), encoding="utf-8")
print(out_path)
PY

  start_frontend

  log "dev full-surface environment ready"
  log "frontend=http://127.0.0.1:5173"
  log "backend=http://127.0.0.1:8000"
  log "manifest=${FRONTEND_DIR}/public/dev-bootstrap.json"
  log "demo_summary=${BACKEND_DIR}/generated/demo_bootstrap_result.json"
  log "frontend_log=${FRONTEND_LOG}"
  log "run ./scripts/demo_rehearsal_check.sh before the conference demo"
  log "operator runbook=docs/CONFERENCE_DEMO_RUNBOOK.md"
  log "demo tester handle is surfaced publicly in the login page dev bootstrap card and public manifest:"
  log "  1) the login page dev bootstrap card"
  log "  2) ${BACKEND_DIR}/generated/demo_bootstrap_result.json"
  log "  3) ${FRONTEND_DIR}/public/dev-bootstrap.json"
  log "demo tester private key now remains local-only in:"
  log "  4) ${BACKEND_DIR}/generated/demo_bootstrap_secret.json"
  log "  5) ${ROOT_DIR}/.weall-dev/dev-bootstrap-secret.json"
  log "print exact credentials locally with:"
  log "  python3 - <<'PY'"
  log "  import json"
  log "  from pathlib import Path"
  log "  data=json.loads(Path('${BACKEND_DIR}/generated/demo_bootstrap_secret.json').read_text())"
  log "  print('HANDLE:', data['account'])"
  log "  print('PRIVATE_KEY_BASE64:', data['secret_key_b64'])"
  log "  PY"
}

main "$@"
