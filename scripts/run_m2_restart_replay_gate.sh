#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m2_common.sh"
m2_activate_venv
ART="${M2_ARTIFACT_ROOT}/restart-replay"
RUNTIME_PARENT="$(m2_new_runtime restart_replay)"
DEVNET="${RUNTIME_PARENT}/.weall-devnet"
mkdir -p "${ART}"
cleanup() { [[ "${WEALL_KEEP_M2_RUNTIME:-0}" == "1" ]] || rm -rf "${RUNTIME_PARENT}"; }
trap cleanup EXIT INT TERM
(
  cd "${M2_BACKEND}"
  WEALL_DEVNET_DIR="${DEVNET}" \
  WEALL_DEVNET_LIVE_LOG_DIR="${ART}/runtime-logs" \
  WEALL_DEVNET_AUTO_VENV=0 \
  WEALL_DEVNET_LIVE_RESET=1 \
  NODE1_API="http://127.0.0.1:${WEALL_M2_RESTART_NODE1_PORT:-18201}" \
  NODE2_API="http://127.0.0.1:${WEALL_M2_RESTART_NODE2_PORT:-18202}" \
  bash scripts/devnet_restart_catchup_live.sh
) 2>&1 | tee "${ART}/restart-replay.txt"
grep -q "OK: live controlled-devnet restart/catch-up probe passed" "${ART}/restart-replay.txt"
grep -q "OK: node chain manifests are valid and current" "${ART}/restart-replay.txt"
python3 "${ROOT}/scripts/extract_m2_state_root_summary.py" \
  --input "${ART}/restart-replay.txt" \
  --out "${ART}/final-state.json" \
  --gate "restart-replay"
echo "OK: M2 backend restart and replay gate passed"
