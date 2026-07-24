#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m2_common.sh"
m2_activate_venv
m2_require_command git
m2_require_command python3
m2_require_command node
m2_require_command npm
m2_require_command curl
cd "${ROOT}"
FREEZE="${M2_IMPLEMENTATION_FREEZE_COMMIT:-$(git rev-parse HEAD)}"
FREEZE="$(git rev-parse "${FREEZE}^{commit}")"
[[ "$(git rev-parse HEAD)" == "${FREEZE}" ]] || { echo "ERROR: closure must run at implementation freeze commit ${FREEZE}" >&2; exit 1; }
[[ -z "$(git status --short --untracked-files=all | grep -v '^?? artifacts/m2-closure/' || true)" ]] || {
  echo "ERROR: implementation working tree is not clean before closure" >&2
  git status --short >&2
  exit 1
}
rm -rf "${M2_ARTIFACT_ROOT}"
mkdir -p "${M2_ARTIFACT_ROOT}"/{backend,frontend,browser/account-custody}

run_logged() {
  local log="$1"; shift
  mkdir -p "$(dirname "${log}")"
  set -o pipefail
  "$@" 2>&1 | tee "${log}"
}

run_logged "${M2_ARTIFACT_ROOT}/backend/pytest.txt" bash -lc "cd '${M2_BACKEND}' && PYTHONPATH=src:scripts WEALL_API_BOOT_RUNTIME=0 python3 -m pytest -q"
run_logged "${M2_ARTIFACT_ROOT}/backend/tx-canon.txt" bash -lc "cd '${M2_BACKEND}' && python3 -S scripts/check_tx_canon_artifacts.py"
run_logged "${M2_ARTIFACT_ROOT}/backend/production-genesis.txt" bash -lc "cd '${M2_BACKEND}' && PYTHONPATH=src python3 scripts/assert_production_genesis_artifacts.py"
run_logged "${M2_ARTIFACT_ROOT}/backend/testnet-chain-identity.txt" bash -lc "cd '${M2_BACKEND}' && PYTHONPATH=src python3 scripts/gen_public_testnet_v1_chain_identity.py --check"
run_logged "${M2_ARTIFACT_ROOT}/backend/seed-registry-rotation.txt" bash -lc "cd '${M2_BACKEND}' && PYTHONPATH=src python3 scripts/check_public_testnet_seed_registry_rotation.py"
run_logged "${M2_ARTIFACT_ROOT}/backend/traceability.txt" bash -lc "cd '${M2_BACKEND}' && python3 scripts/check_m2_requirement_traceability.py"

if [[ ! -d "${M2_WEB}/node_modules" ]]; then
  run_logged "${M2_ARTIFACT_ROOT}/frontend/npm-ci.txt" bash -lc "cd '${M2_WEB}' && npm ci"
fi
run_logged "${M2_ARTIFACT_ROOT}/frontend/typecheck.txt" bash -lc "cd '${M2_WEB}' && npm run typecheck"
run_logged "${M2_ARTIFACT_ROOT}/frontend/build.txt" bash -lc "cd '${M2_WEB}' && npm run build"
WEALL_M2_ARTIFACT_DIR="${M2_ARTIFACT_ROOT}/frontend/contract-check" \
  bash "${ROOT}/scripts/run_frontend_contract_check_real_stack.sh"
run_logged "${M2_ARTIFACT_ROOT}/frontend/production-safety.txt" bash -lc "cd '${M2_WEB}' && npm run production-safety-check"
run_logged "${M2_ARTIFACT_ROOT}/frontend/account-custody-source.txt" bash -lc "cd '${M2_WEB}' && npm run test:account-custody-source"
run_logged "${M2_ARTIFACT_ROOT}/frontend/account-custody-crypto-source.txt" bash -lc "cd '${M2_WEB}' && npm run test:account-custody-crypto-source"

run_logged "${M2_ARTIFACT_ROOT}/browser/account-custody/runner.txt" \
  env WEALL_M2_ARTIFACT_DIR="${M2_ARTIFACT_ROOT}/browser/account-custody" \
  bash "${ROOT}/scripts/run_account_custody_real_stack_e2e.sh"
WEALL_M2_ARTIFACT_DIR="${M2_ARTIFACT_ROOT}/browser/async" bash "${ROOT}/scripts/run_m2_async_browser_e2e.sh"
WEALL_M2_ARTIFACT_DIR="${M2_ARTIFACT_ROOT}/browser/live" bash "${ROOT}/scripts/run_m2_live_browser_e2e.sh"
bash "${ROOT}/scripts/run_m2_media_rehearsal.sh"
bash "${ROOT}/scripts/run_m2_restart_replay_gate.sh"
bash "${ROOT}/scripts/run_m2_two_node_state_root_gate.sh"
bash "${ROOT}/scripts/run_m2_observer_catchup_gate.sh"

m2_sanitize_artifacts "${M2_ARTIFACT_ROOT}"
M2_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
  python3 "${ROOT}/scripts/build_m2_evidence_manifest.py" --artifact-root "${M2_ARTIFACT_ROOT}"
echo "OK: complete M2 closure suite passed for freeze commit ${FREEZE}"
