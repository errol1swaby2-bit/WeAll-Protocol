#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT}/.." && pwd)"
WEB_ROOT="${REPO_ROOT}/web"

cd "${ROOT}"

echo "[reviewer-gate] repo: ${ROOT}"
echo "[reviewer-gate] checking canon, secrets, release tree, and dependencies"
python3 -S scripts/check_tx_canon_artifacts.py
python3 scripts/gen_api_contract_map.py --check
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_v15_public_readiness_artifacts.py
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
  tests/test_batch450_public_payload_key_policy.py \
  tests/test_batch451_public_activity_contract.py \
  tests/test_batch452_rehearsal_content_review_followup.py \
  tests/test_batch453_live_room_remote_media_recovery.py \
  tests/test_batch454_rehearsal_review_visibility_and_viewer_vote.py \
  tests/test_batch456_public_readiness_gates.py \
  tests/test_batch457_economics_block_p2p_implementation.py \
  tests/test_batch462_463_reviewer_truth_and_observer_reproducibility.py \
  tests/test_batch464_genesis_api_external_observer_readiness.py \
  tests/test_batch465_runtime_config_env_precedence.py \
  tests/test_batch467_external_observer_account_id_format.py \
  tests/test_batch469_frontend_account_custody_docs.py \
  tests/test_batch468_one_command_tester_boot.py \
  tests/test_batch466_tx_status_tx_queue_runtime_path.py \
  tests/test_batch458_461_production_implementation.py

if [[ -d "${WEB_ROOT}" ]]; then
  PYTHONPATH=src pytest -q tests/test_batch471_tester_boot_authority_profile_sanitized.py

PYTHONPATH=src pytest -q tests/test_batch472_tester_boot_invokes_boot_script_with_bash.py

PYTHONPATH=src pytest -q tests/test_batch474_clean_clone_tester_boot_docs.py

PYTHONPATH=src pytest -q tests/test_batch476_tester_boot_sets_local_cors.py

PYTHONPATH=src pytest -q tests/test_batch477_tester_boot_exports_runtime_port.py

PYTHONPATH=src pytest -q tests/test_batch479_tester_boot_exports_gunicorn_bind.py

PYTHONPATH=src pytest -q tests/test_batch480_tester_boot_uses_repo_venv.py

PYTHONPATH=src pytest -q tests/test_batch481_real_tokenomics_policy.py

PYTHONPATH=src pytest -q tests/test_batch483_484_transfer_tip_contract.py

PYTHONPATH=src pytest -q tests/test_batch485_reward_issuance_invariants.py

PYTHONPATH=src pytest -q tests/test_batch491_v15_epoch_issuance_scheduler.py

PYTHONPATH=src pytest -q tests/test_batch493_v15_runtime_config_alignment.py

PYTHONPATH=src pytest -q \
  tests/test_batch494_api_contract_map_v15.py \
  tests/test_batch495_launch_disabled_matrix_v15.py \
  tests/test_batch496_protocol_upgrade_record_only_boundary.py \
  tests/test_batch497_public_readiness_artifacts_v15.py

echo "[reviewer-gate] frontend source checks"
  cd "${WEB_ROOT}"
  node scripts/test_batch450_public_payload_source.mjs
  node scripts/test_batch451_public_activity_source.mjs
  node scripts/test_batch452_group_review_source.mjs
  node scripts/test_batch453_live_room_media_source.mjs
  node scripts/test_batch454_review_visibility_source.mjs
  node scripts/test_batch456_public_readiness_source.mjs
  node scripts/test_batch457_economics_block_public_source.mjs
  node scripts/test_batch458_461_public_implementation_source.mjs
  node scripts/test_batch469_account_custody_source.mjs
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
echo "[reviewer-gate] NOTE: this does not claim public mainnet, public governance, live economics, production validator/BFT readiness, or external communications tooling."
