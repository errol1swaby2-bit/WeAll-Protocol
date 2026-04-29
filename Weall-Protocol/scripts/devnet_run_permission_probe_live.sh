#!/usr/bin/env bash
set -euo pipefail

# Start a single controlled-devnet genesis node, run the direct API permission
# probe, and cleanly stop the temporary node process.
#
# This live harness proves backend/execution-layer permission gates without
# relying on frontend gating, seeded demo routes, local DB mutation, or copied
# state.
#
# Useful knobs:
#   WEALL_DEVNET_LIVE_RESET=1        reset local controlled-devnet DBs first
#   WEALL_DEVNET_KEEP_NODES=1        leave the node running after the probe
#   NODE1_API=http://127.0.0.1:8001 override node 1 API
#   WEALL_DEVNET_LIVE_LOG_DIR=...    override log directory
#   WEALL_DEVNET_AUTO_VENV=0         disable automatic .venv activation
#   WEALL_DEVNET_READY_TIMEOUT=120   override readiness timeout in seconds

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

_bool_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

activate_repo_venv() {
  if ! _bool_true "${WEALL_DEVNET_AUTO_VENV:-1}"; then
    return 0
  fi
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    echo "==> Using active Python virtualenv: ${VIRTUAL_ENV}"
    return 0
  fi
  local activate_path="${REPO_ROOT}/.venv/bin/activate"
  if [[ -f "${activate_path}" ]]; then
    # shellcheck disable=SC1090
    source "${activate_path}"
    echo "==> Activated Python virtualenv: ${VIRTUAL_ENV:-${REPO_ROOT}/.venv}"
    return 0
  fi
  echo "ERROR: Python virtualenv not active and ${activate_path} was not found." >&2
  echo "Run: cd ${REPO_ROOT} && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 2
}

activate_repo_venv

NODE1_API="${NODE1_API:-http://127.0.0.1:8001}"
READY_TIMEOUT="${WEALL_DEVNET_READY_TIMEOUT:-120}"
LOG_DIR="${WEALL_DEVNET_LIVE_LOG_DIR:-${REPO_ROOT}/.weall-devnet/logs}"
NODE1_LOG="${LOG_DIR}/node1-permission-probe-live.log"
PROBE_LOG="${LOG_DIR}/permission-probe-live.log"
NODE1_PID=""

cleanup() {
  local rc=$?
  if _bool_true "${WEALL_DEVNET_KEEP_NODES:-0}"; then
    echo "==> Leaving devnet node running because WEALL_DEVNET_KEEP_NODES=1"
    echo "node1_pid=${NODE1_PID:-} node1_log=${NODE1_LOG}"
    exit "${rc}"
  fi
  if [[ -n "${NODE1_PID}" ]] && kill -0 "${NODE1_PID}" >/dev/null 2>&1; then
    echo "==> Stopping node 1 pid=${NODE1_PID}"
    kill "${NODE1_PID}" >/dev/null 2>&1 || true
  fi
  wait "${NODE1_PID:-0}" >/dev/null 2>&1 || true
  exit "${rc}"
}
trap cleanup EXIT INT TERM

wait_http_ready() {
  local name="$1"
  local api="$2"
  local log_path="$3"
  local timeout_s="${4:-60}"

  python3 - "$name" "$api" "$log_path" "$timeout_s" <<'PY'
import json
import sys
import time
import urllib.request

name, api, log_path, timeout_s = sys.argv[1], sys.argv[2].rstrip('/'), sys.argv[3], float(sys.argv[4])
deadline = time.time() + timeout_s
last_error = ''
while time.time() <= deadline:
    try:
        with urllib.request.urlopen(api + '/v1/readyz', timeout=2) as resp:
            status = int(getattr(resp, 'status', 0) or 0)
            if 200 <= status < 300:
                print(json.dumps({'ok': True, 'node': name, 'api': api, 'path': '/v1/readyz', 'status': status}, sort_keys=True))
                raise SystemExit(0)
    except Exception as exc:
        last_error = str(exc)
    time.sleep(0.5)
print(json.dumps({'ok': False, 'failure': 'node_not_ready', 'node': name, 'api': api, 'path': '/v1/readyz', 'last_error': last_error, 'log_path': log_path}, sort_keys=True))
raise SystemExit(1)
PY
}

dump_log_tail() {
  local label="$1"
  local log_path="$2"
  local pid="$3"
  echo "==> ${label} failed readiness; diagnostic log tail follows" >&2
  echo "${label^^}_PID=${pid}" >&2
  python3 - "$log_path" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
if path.exists():
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()[-120:]
else:
    lines = ['<log file missing>']
print(json.dumps({'log_path': str(path), 'tail': lines}, sort_keys=True))
PY
}

if _bool_true "${WEALL_DEVNET_LIVE_RESET:-0}"; then
  echo "==> Resetting controlled-devnet state before permission probe"
  WEALL_DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}" bash scripts/devnet_reset_state.sh
fi
mkdir -p "${LOG_DIR}"

: > "${NODE1_LOG}"
: > "${PROBE_LOG}"

echo "==> Starting node 1: ${NODE1_API}"
(
  export GUNICORN_BIND="${NODE1_BIND:-127.0.0.1:8001}"
  export WEALL_DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"
  export WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-1}"
  export WEALL_BLOCK_INTERVAL_MS="${WEALL_BLOCK_INTERVAL_MS:-1000}"
  export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
  export WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"
  export WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE="1"
  exec bash scripts/devnet_boot_genesis_node.sh
) >"${NODE1_LOG}" 2>&1 &
NODE1_PID="$!"

if ! wait_http_ready "node1" "${NODE1_API}" "${NODE1_LOG}" "${READY_TIMEOUT}"; then
  dump_log_tail "node1" "${NODE1_LOG}" "${NODE1_PID}"
  exit 1
fi

echo "==> Running direct API permission probe"
WEALL_API="${NODE1_API}" bash scripts/devnet_permission_probe.sh "$@" | tee "${PROBE_LOG}"

echo "==> OK: live controlled-devnet permission probe passed"
echo "node1_log=${NODE1_LOG}"
echo "probe_log=${PROBE_LOG}"
