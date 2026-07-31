#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="${ROOT}/Weall-Protocol"
OUT="${WEALL_M1_M3_ADVERSARIAL_LOG:-${TMPDIR:-/tmp}/weall_m1_m3_adversarial_matrix_${$}.log}"
mkdir -p "$(dirname "${OUT}")"

TESTS=(
  tests/test_consensus_signature_policy_pinning.py
  tests/test_consensus_profile_manifest.py
  tests/test_protocol_blocker_safety.py
  tests/test_priority12_network_recovery.py
  tests/test_priority1_commit_rule_adversarial_timing.py
  tests/test_bft_restart_liveness_persistence.py
  tests/test_block_id_content_addressed.py
  tests/test_helper_mixed_bad_traffic_recovery.py
  tests/test_helper_multinode_divergence_guards.py
  tests/test_backup_restore_write_after_restore.py
  tests/test_mixed_node_posture_fail_closed.py
  tests/test_handshake_mixed_bft_posture.py
)

for rel in "${TESTS[@]}"; do
  [[ -f "${BACKEND}/${rel}" ]] || { echo "ERROR: missing adversarial test: ${rel}" >&2; exit 2; }
done

(
  cd "${BACKEND}"
  export PYTHONPATH=src:scripts
  export WEALL_API_BOOT_RUNTIME=0
  python -m pytest -q "${TESTS[@]}"
) 2>&1 | tee "${OUT}"

echo "OK: M1-M3 adversarial matrix passed"
