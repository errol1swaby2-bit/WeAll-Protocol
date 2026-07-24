#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m2_common.sh"
m2_activate_venv
ART="${M2_ARTIFACT_ROOT}/observer"
RUNTIME_PARENT="$(m2_new_runtime observer)"
DEVNET="${RUNTIME_PARENT}/.weall-devnet"
mkdir -p "${ART}"
cleanup() { [[ "${WEALL_KEEP_M2_RUNTIME:-0}" == "1" ]] || rm -rf "${RUNTIME_PARENT}"; }
trap cleanup EXIT INT TERM
# The joining node has no validator signing key and no block loop. The existing
# restart/catch-up harness therefore proves a fresh observer-equivalent node can
# sync, restart from its own persisted state, and retain the canonical root.
(
  cd "${M2_BACKEND}"
  WEALL_DEVNET_DIR="${DEVNET}" \
  WEALL_DEVNET_LIVE_LOG_DIR="${ART}/runtime-logs" \
  WEALL_DEVNET_AUTO_VENV=0 \
  WEALL_DEVNET_LIVE_RESET=1 \
  NODE1_API="http://127.0.0.1:${WEALL_M2_OBSERVER_NODE1_PORT:-18221}" \
  NODE2_API="http://127.0.0.1:${WEALL_M2_OBSERVER_NODE2_PORT:-18222}" \
  bash scripts/devnet_restart_catchup_live.sh
) 2>&1 | tee "${ART}/observer-catchup.txt"
grep -q "after-node2-restart-catchup" "${ART}/observer-catchup.txt"
grep -q "OK: node identities, tips, and state roots match" "${ART}/observer-catchup.txt"
grep -q "OK: node chain manifests are valid and current" "${ART}/observer-catchup.txt"
python3 "${ROOT}/scripts/extract_m2_state_root_summary.py" \
  --input "${ART}/observer-catchup.txt" \
  --out "${ART}/final-state.json" \
  --gate "observer"
echo "OK: M2 observer catch-up gate passed"
