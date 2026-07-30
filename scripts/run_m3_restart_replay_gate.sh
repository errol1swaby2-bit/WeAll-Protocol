#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m3_common.sh"
m3_activate_venv
FREEZE="${M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M3_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
FREEZE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{commit}")"
TREE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{tree}")"
ART="${M3_ARTIFACT_ROOT}/restart-replay"
RUNTIME_PARENT="$(m3_new_runtime restart_replay)"
DEVNET="${RUNTIME_PARENT}/.weall-devnet"
mkdir -p "${ART}"
cleanup() { [[ "${WEALL_KEEP_M3_RUNTIME:-0}" == "1" ]] || rm -rf "${RUNTIME_PARENT}"; }
trap cleanup EXIT INT TERM
(
  cd "${M3_BACKEND}"
  WEALL_DEVNET_DIR="${DEVNET}" \
  WEALL_DEVNET_LIVE_LOG_DIR="${ART}/runtime-logs" \
  WEALL_DEVNET_AUTO_VENV=0 \
  WEALL_DEVNET_LIVE_RESET=1 \
  WEALL_M3_CIVIC_GOVERNANCE_STRICT=1 \
  WEALL_BALLOT_PROFILE_ID=controlled-testnet-aggregate-v1 \
  WEALL_BALLOT_PROFILE_ACTIVE=1 \
  NODE1_API="http://127.0.0.1:${WEALL_M3_RESTART_NODE1_PORT:-18301}" \
  NODE2_API="http://127.0.0.1:${WEALL_M3_RESTART_NODE2_PORT:-18302}" \
  bash scripts/devnet_restart_catchup_live.sh
) 2>&1 | tee "${ART}/restart-replay.txt"
grep -q "OK: live controlled-devnet restart/catch-up probe passed" "${ART}/restart-replay.txt"
grep -q "OK: node identities, tips, and state roots match" "${ART}/restart-replay.txt"
python "${ROOT}/scripts/extract_m3_state_root_summary.py" \
  --input "${ART}/restart-replay.txt" \
  --out "${ART}/final-state.json" \
  --gate restart-replay \
  --implementation-freeze "${FREEZE}" \
  --implementation-tree "${TREE}" \
  --node1-id m3-restart-producer \
  --node2-id m3-restart-joiner
echo "OK: M3 restart/replay equality gate passed"
