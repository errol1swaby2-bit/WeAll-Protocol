#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m3_common.sh"
m3_activate_venv
for cmd in curl python; do m3_require_command "${cmd}"; done

FREEZE="${M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M3_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
FREEZE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{commit}")"
TREE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{tree}")"
ART="${M3_ARTIFACT_ROOT}/observer"
RUNTIME_PARENT="$(m3_new_runtime observer)"
DEVNET="${RUNTIME_PARENT}/.weall-devnet"
NODE1_API="http://127.0.0.1:${WEALL_M3_OBSERVER_NODE1_PORT:-18321}"
NODE2_API="http://127.0.0.1:${WEALL_M3_OBSERVER_NODE2_PORT:-18322}"
NODE1_LOG="${ART}/runtime-logs/producer.log"
NODE2_LOG="${ART}/runtime-logs/observer.log"
COMPARE_LOG="${ART}/observer-catchup.txt"
NODE1_PID=""
NODE2_PID=""
mkdir -p "${ART}/runtime-logs" "${DEVNET}"

cleanup() {
  local rc=$?
  for pid in "${NODE2_PID:-}" "${NODE1_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then kill "${pid}" >/dev/null 2>&1 || true; fi
  done
  wait "${NODE2_PID:-0}" >/dev/null 2>&1 || true
  wait "${NODE1_PID:-0}" >/dev/null 2>&1 || true
  [[ "${WEALL_KEEP_M3_RUNTIME:-0}" == "1" ]] || rm -rf "${RUNTIME_PARENT}"
  exit "${rc}"
}
trap cleanup EXIT INT TERM

wait_ready() {
  local api="$1" log="$2"
  python - "${api}" "${log}" <<'PY'
import sys, time, urllib.request
api, log = sys.argv[1].rstrip('/'), sys.argv[2]
deadline = time.time() + 120
last = ''
while time.time() < deadline:
    try:
        with urllib.request.urlopen(api + '/v1/readyz', timeout=2) as response:
            response.read()
            if response.status < 500:
                raise SystemExit(0)
    except Exception as exc:
        last = str(exc)
    time.sleep(.5)
print(f'm3_observer_node_not_ready:{api}:{last}:log={log}', file=sys.stderr)
raise SystemExit(1)
PY
}

start_producer() {
  (
    cd "${M3_BACKEND}"
    WEALL_DEVNET_DIR="${DEVNET}" \
    WEALL_DEVNET_AUTO_VENV=0 \
    WEALL_M3_CIVIC_GOVERNANCE_STRICT=1 \
    WEALL_BALLOT_PROFILE_ID=controlled-testnet-aggregate-v1 \
    WEALL_BALLOT_PROFILE_ACTIVE=1 \
    NODE1_API="${NODE1_API}" \
    GUNICORN_BIND="${NODE1_API#http://}" \
    bash scripts/devnet_boot_genesis_node.sh
  ) >"${NODE1_LOG}" 2>&1 &
  NODE1_PID=$!
  wait_ready "${NODE1_API}" "${NODE1_LOG}"
}

start_observer() {
  (
    cd "${M3_BACKEND}"
    WEALL_DEVNET_DIR="${DEVNET}" \
    WEALL_DEVNET_AUTO_VENV=0 \
    WEALL_M3_CIVIC_GOVERNANCE_STRICT=1 \
    WEALL_BALLOT_PROFILE_ID=controlled-testnet-aggregate-v1 \
    WEALL_BALLOT_PROFILE_ACTIVE=1 \
    NODE1_API="${NODE1_API}" \
    NODE2_API="${NODE2_API}" \
    GUNICORN_BIND="${NODE2_API#http://}" \
    WEALL_OBSERVER_MODE=1 \
    WEALL_OBSERVER_EDGE_MODE=1 \
    WEALL_NODE_LIFECYCLE_STATE=observer_onboarding \
    WEALL_SERVICE_ROLES="" \
    WEALL_VALIDATOR_SIGNING_ENABLED=0 \
    WEALL_BFT_ENABLED=0 \
    WEALL_HELPER_MODE_ENABLED=0 \
    WEALL_BLOCK_LOOP_AUTOSTART=0 \
    WEALL_PRODUCE_EMPTY_BLOCKS=0 \
    bash scripts/devnet_boot_joining_node.sh
  ) >"${NODE2_LOG}" 2>&1 &
  NODE2_PID=$!
  wait_ready "${NODE2_API}" "${NODE2_LOG}"
}

sync_compare() {
  (
    cd "${M3_BACKEND}"
    WEALL_DEVNET_DIR="${DEVNET}" NODE1_API="${NODE1_API}" NODE2_API="${NODE2_API}" \
      bash scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}"
    bash scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}"
  ) | tee -a "${COMPARE_LOG}"
}

start_producer
start_observer
sync_compare

kill "${NODE2_PID}" >/dev/null 2>&1 || true
wait "${NODE2_PID}" >/dev/null 2>&1 || true
NODE2_PID=""
sleep 1
start_observer
sync_compare

grep -q "OK: node identities, tips, and state roots match" "${COMPARE_LOG}"
(
  cd "${M3_BACKEND}"
  WEALL_API_BASE="${NODE2_API}" \
  WEALL_OBSERVER_MODE=1 \
  WEALL_VALIDATOR_SIGNING_ENABLED=0 \
  WEALL_BFT_ENABLED=0 \
  WEALL_HELPER_MODE_ENABLED=0 \
  WEALL_BLOCK_LOOP_AUTOSTART=0 \
  WEALL_SERVICE_ROLES="" \
  bash scripts/external_observer_authority_lock_gate.sh
) 2>&1 | tee "${ART}/authority-lock.txt"

python "${ROOT}/scripts/capture_m3_observer_authority.py" \
  --api-base "${NODE2_API}" \
  --out "${ART}/authority.json" \
  --implementation-freeze "${FREEZE}" \
  --implementation-tree "${TREE}"
python "${ROOT}/scripts/extract_m3_state_root_summary.py" \
  --input "${COMPARE_LOG}" \
  --out "${ART}/final-state.json" \
  --gate observer \
  --implementation-freeze "${FREEZE}" \
  --implementation-tree "${TREE}" \
  --node1-id m3-observer-source \
  --node2-id m3-observer-node \
  --observer

echo "OK: M3 observer catch-up without authority gate passed"
