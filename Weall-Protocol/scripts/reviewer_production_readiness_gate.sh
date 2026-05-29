#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"
WEB_ROOT="${REPO_ROOT}/web"

cd "${ROOT}"

echo "[reviewer-gate] repo: ${ROOT}"
echo "[reviewer-gate] checking canon, secrets, release tree, and dependencies"
python3 -S scripts/check_tx_canon_artifacts.py
bash scripts/secret_guard.sh
bash scripts/verify_release_tree.sh
bash scripts/verify_release_dependencies.sh


echo "[reviewer-gate] local observer readiness and authority preconditions"
if [[ "${WEALL_REVIEWER_INCLUDE_LOCAL_OBSERVER_GATES:-0}" == "1" ]]; then
  bash scripts/external_observer_authority_lock_gate.sh
  bash scripts/local_observer_readiness_gate.sh
else
  echo "[reviewer-gate] NOTE: local observer precondition gates skipped by default; run scripts/first_external_observer_reproducibility_gate.sh before inviting a tester."
fi

echo "[reviewer-gate] targeted backend tests"
PYTHONPATH=src pytest -q \
  tests/test_batch437_446_external_testnet_p0_p2_hardening.py \
  tests/test_batch450_messaging_e2ee_key_lifecycle.py \
  tests/test_batch451_messaging_rehearsal_convergence.py \
  tests/test_batch452_rehearsal_content_review_followup.py \
  tests/test_batch453_live_room_remote_media_recovery.py \
  tests/test_batch454_rehearsal_review_visibility_and_viewer_vote.py \
  tests/test_batch456_production_readiness_and_p2p_e2ee_gates.py \
  tests/test_batch457_economics_block_p2p_implementation.py \
  tests/test_batch462_463_reviewer_truth_and_observer_reproducibility.py \
  tests/test_batch464_genesis_api_external_observer_readiness.py \
  tests/test_batch465_runtime_config_env_precedence.py \
  tests/test_batch467_external_observer_account_id_format.py \
  tests/test_batch466_tx_status_outbox_runtime_path.py \
  tests/test_batch458_461_production_implementation.py

if [[ -d "${WEB_ROOT}" ]]; then
  echo "[reviewer-gate] frontend source checks"
  cd "${WEB_ROOT}"
  node scripts/test_batch450_messaging_e2ee_source.mjs
  node scripts/test_batch451_messaging_rehearsal_source.mjs
  node scripts/test_batch452_group_review_source.mjs
  node scripts/test_batch453_live_room_media_source.mjs
  node scripts/test_batch454_review_visibility_source.mjs
  node scripts/test_batch456_production_readiness_source.mjs
  node scripts/test_batch457_economics_block_p2p_source.mjs
  node scripts/test_batch458_461_implementation_source.mjs
  node scripts/guard_production_ux_safety.mjs
fi

cd "${ROOT}"
echo "[reviewer-gate] local block production proof"
python3 scripts/production_block_production_rehearsal_gate.py

if [[ "${WEALL_DOCKER_GENESIS_BOOT_GATE:-0}" == "1" ]]; then
  echo "[reviewer-gate] Docker Genesis API boot gate"
  bash scripts/docker_genesis_api_boot_gate.sh
else
  echo "[reviewer-gate] NOTE: Docker Genesis API boot gate skipped by default; set WEALL_DOCKER_GENESIS_BOOT_GATE=1 when Docker is available."
fi

echo "[reviewer-gate] OK: targeted production-oriented rehearsal evidence passed"
echo "[reviewer-gate] NOTE: local observer gates are preconditions only unless the remote signed observer gate is run."
echo "[reviewer-gate] NOTE: this does not claim public mainnet, public governance, live economics, production validator/BFT readiness, or Signal-grade messaging readiness."
