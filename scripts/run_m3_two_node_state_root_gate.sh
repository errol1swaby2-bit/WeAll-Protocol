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
ART="${M3_ARTIFACT_ROOT}/two-node"
RUNTIME_PARENT="$(m3_new_runtime two_node)"
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
  NODE1_API="http://127.0.0.1:${WEALL_M3_TWO_NODE1_PORT:-18311}" \
  NODE2_API="http://127.0.0.1:${WEALL_M3_TWO_NODE2_PORT:-18312}" \
  bash scripts/devnet_run_cross_node_convergence_live.sh
) 2>&1 | tee "${ART}/two-node-state-root.txt"
grep -q "OK: live controlled-devnet cross-node convergence probe passed" "${ART}/two-node-state-root.txt"
grep -q "OK: node identities, tips, and state roots match" "${ART}/two-node-state-root.txt"
python "${ROOT}/scripts/extract_m3_state_root_summary.py" \
  --input "${ART}/two-node-state-root.txt" \
  --out "${ART}/final-state.json" \
  --gate two-node \
  --implementation-freeze "${FREEZE}" \
  --implementation-tree "${TREE}" \
  --node1-id m3-two-node-producer \
  --node2-id m3-two-node-joiner
echo "OK: M3 two-node state-root equality gate passed"
