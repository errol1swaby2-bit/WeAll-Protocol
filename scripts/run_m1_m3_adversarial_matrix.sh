#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="${ROOT}/Weall-Protocol"
OUT="${WEALL_M1_M3_ADVERSARIAL_LOG:-${TMPDIR:-/tmp}/weall_m1_m3_adversarial_matrix_${$}.log}"
mkdir -p "$(dirname "${OUT}")"

PYTHON_BIN="${WEALL_PYTHON:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
    PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
  elif [[ -x "${HOME}/.venvs/weall-protocol/bin/python" ]]; then
    PYTHON_BIN="${HOME}/.venvs/weall-protocol/bin/python"
  else
    PYTHON_BIN="$(command -v python3)"
  fi
fi
[[ -n "${PYTHON_BIN}" && -x "${PYTHON_BIN}" ]] || {
  echo "ERROR: no usable Python interpreter found" >&2
  exit 2
}
echo "[M1-M3 adversarial] python=${PYTHON_BIN}"

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
  "${PYTHON_BIN}" -m pytest -q "${TESTS[@]}"
) 2>&1 | tee "${OUT}"

echo "OK: M1-M3 adversarial matrix passed"
