#!/usr/bin/env bash
set -euo pipefail

# Start a complete two-node controlled devnet, run the cross-node convergence
# probe, restart each node from its persisted local state, and verify both nodes
# still expose matching canonical chain identity/state roots after catch-up.
#
# This is a live controlled-devnet harness. It does not call demo seed routes,
# does not copy databases, and does not bypass signed transaction submission or
# verified sync.
#
# Useful knobs:
#   WEALL_DEVNET_LIVE_RESET=1        reset local controlled-devnet DBs first
#   WEALL_DEVNET_KEEP_NODES=1        leave both nodes running after the probe
#   NODE1_API=http://127.0.0.1:8001 override node 1 API
#   NODE2_API=http://127.0.0.1:8002 override node 2 API
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
NODE2_API="${NODE2_API:-http://127.0.0.1:8002}"
READY_TIMEOUT="${WEALL_DEVNET_READY_TIMEOUT:-120}"
LOG_DIR="${WEALL_DEVNET_LIVE_LOG_DIR:-${REPO_ROOT}/.weall-devnet/logs}"

NODE1_LOG="${LOG_DIR}/node1-restart-catchup-live.log"
NODE2_LOG="${LOG_DIR}/node2-restart-catchup-live.log"
PROBE_LOG="${LOG_DIR}/restart-catchup-convergence-live.log"
SYNC_LOG="${LOG_DIR}/restart-catchup-sync-live.log"
COMPARE_LOG="${LOG_DIR}/restart-catchup-compare-live.log"

NODE1_PID=""
NODE2_PID=""

cleanup() {
  local rc=$?
  if _bool_true "${WEALL_DEVNET_KEEP_NODES:-0}"; then
    echo "==> Leaving devnet nodes running because WEALL_DEVNET_KEEP_NODES=1"
    echo "node1_pid=${NODE1_PID:-} node1_log=${NODE1_LOG}"
    echo "node2_pid=${NODE2_PID:-} node2_log=${NODE2_LOG}"
    exit "${rc}"
  fi

  if [[ -n "${NODE2_PID}" ]] && kill -0 "${NODE2_PID}" >/dev/null 2>&1; then
    echo "==> Stopping node 2 pid=${NODE2_PID}"
    kill "${NODE2_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${NODE1_PID}" ]] && kill -0 "${NODE1_PID}" >/dev/null 2>&1; then
    echo "==> Stopping node 1 pid=${NODE1_PID}"
    kill "${NODE1_PID}" >/dev/null 2>&1 || true
  fi
  wait "${NODE2_PID:-0}" >/dev/null 2>&1 || true
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
paths = ['/v1/readyz', '/v1/chain/identity']
while time.time() <= deadline:
    for path in paths:
        url = api + path
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                resp.read()
            if resp.status < 500:
                print(json.dumps({'ok': True, 'node': name, 'api': api, 'path': path, 'status': resp.status}, sort_keys=True))
                raise SystemExit(0)
        except Exception as exc:  # noqa: BLE001 - stdlib helper used by shell wrapper
            last_error = f'{url}: {exc}'
    time.sleep(0.5)

print(json.dumps({
    'ok': False,
    'node': name,
    'api': api,
    'failure': 'node_not_ready',
    'last_error': last_error,
    'log_path': log_path,
}, sort_keys=True), file=sys.stderr)
raise SystemExit(1)
PY
}

emit_log_tail_json() {
  local log_path="$1"
  python3 - "$log_path" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
if path.exists():
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()[-120:]
else:
    lines = ['<missing log file>']
print(json.dumps({'log_path': str(path), 'tail': lines}, sort_keys=True))
PY
}

start_node1() {
  echo "==> Starting node 1: ${NODE1_API}"
  (
    NODE1_API="${NODE1_API}" \
    GUNICORN_BIND="${NODE1_API#http://}" \
    bash scripts/devnet_boot_genesis_node.sh
  ) >>"${NODE1_LOG}" 2>&1 &
  NODE1_PID="$!"
  if ! wait_http_ready "node1" "${NODE1_API}" "${NODE1_LOG}" "${READY_TIMEOUT}"; then
    echo "==> node1 failed readiness; diagnostic log tail follows" >&2
    echo "NODE1_PID=${NODE1_PID}" >&2
    emit_log_tail_json "${NODE1_LOG}" >&2
    exit 1
  fi
}

start_node2() {
  echo "==> Starting node 2: ${NODE2_API}"
  (
    NODE1_API="${NODE1_API}" \
    NODE2_API="${NODE2_API}" \
    GUNICORN_BIND="${NODE2_API#http://}" \
    bash scripts/devnet_boot_joining_node.sh
  ) >>"${NODE2_LOG}" 2>&1 &
  NODE2_PID="$!"
  if ! wait_http_ready "node2" "${NODE2_API}" "${NODE2_LOG}" "${READY_TIMEOUT}"; then
    echo "==> node2 failed readiness; diagnostic log tail follows" >&2
    echo "NODE2_PID=${NODE2_PID}" >&2
    emit_log_tail_json "${NODE2_LOG}" >&2
    exit 1
  fi
}

stop_node1_for_restart() {
  echo "==> Restarting node 1 from persisted state pid=${NODE1_PID}"
  if [[ -n "${NODE1_PID}" ]] && kill -0 "${NODE1_PID}" >/dev/null 2>&1; then
    kill "${NODE1_PID}" >/dev/null 2>&1 || true
    wait "${NODE1_PID}" >/dev/null 2>&1 || true
  fi
  NODE1_PID=""
  sleep 1
}

stop_node2_for_restart() {
  echo "==> Restarting node 2 from persisted state pid=${NODE2_PID}"
  if [[ -n "${NODE2_PID}" ]] && kill -0 "${NODE2_PID}" >/dev/null 2>&1; then
    kill "${NODE2_PID}" >/dev/null 2>&1 || true
    wait "${NODE2_PID}" >/dev/null 2>&1 || true
  fi
  NODE2_PID=""
  sleep 1
}

sync_node1_to_node2() {
  echo "==> Syncing node 2 from node 1"
  NODE1_API="${NODE1_API}" NODE2_API="${NODE2_API}" \
    bash scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}" | tee -a "${SYNC_LOG}"
}

compare_roots() {
  local label="$1"
  echo "==> Comparing node roots: ${label}"
  bash scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}" | tee -a "${COMPARE_LOG}"
}

if _bool_true "${WEALL_DEVNET_LIVE_RESET:-0}"; then
  echo "==> Resetting controlled-devnet state before restart/catch-up run"
  bash scripts/devnet_reset_state.sh
fi

# devnet_reset_state.sh removes .weall-devnet, so create the log directory
# after any reset and before truncating log files.
mkdir -p "${LOG_DIR}"

: > "${NODE1_LOG}"
: > "${NODE2_LOG}"
: > "${PROBE_LOG}"
: > "${SYNC_LOG}"
: > "${COMPARE_LOG}"

start_node1
start_node2

# Establish a non-genesis chain state first, including a signed tx accepted at
# the joiner edge and committed by the canonical producer when needed.
echo "==> Running baseline cross-node convergence probe before restart"
set +e
NODE1_API="${NODE1_API}" NODE2_API="${NODE2_API}" bash scripts/devnet_cross_node_convergence.sh "$@" | tee "${PROBE_LOG}"
probe_rc=${PIPESTATUS[0]}
set -e
if [[ "${probe_rc}" -ne 0 ]]; then
  echo "ERROR: baseline cross-node convergence probe failed with exit=${probe_rc}" >&2
  echo "==> node1 log tail: ${NODE1_LOG}" >&2
  tail -80 "${NODE1_LOG}" >&2 || true
  echo "==> node2 log tail: ${NODE2_LOG}" >&2
  tail -80 "${NODE2_LOG}" >&2 || true
  echo "==> probe log: ${PROBE_LOG}" >&2
  exit "${probe_rc}"
fi
compare_roots "after-baseline-convergence"

# Restart the joining node and verify it reloads the persisted canonical state.
stop_node2_for_restart
start_node2
sync_node1_to_node2
compare_roots "after-node2-restart-catchup"

# Restart the genesis/canonical producer and verify its persisted state matches
# the joining node without requiring a DB copy.
stop_node1_for_restart
start_node1
sync_node1_to_node2
compare_roots "after-node1-restart-catchup"

echo "==> OK: live controlled-devnet restart/catch-up probe passed"
echo "node1_log=${NODE1_LOG}"
echo "node2_log=${NODE2_LOG}"
echo "probe_log=${PROBE_LOG}"
echo "sync_log=${SYNC_LOG}"
echo "compare_log=${COMPARE_LOG}"
