#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m3_common.sh"
m3_activate_venv
FREEZE="${M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M3_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
FREEZE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{commit}")"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/weall_m3_clean_checkout_XXXXXX")"
cleanup() {
  git -C "${ROOT}" worktree remove --force "${TMP}" >/dev/null 2>&1 || rm -rf "${TMP}"
}
trap cleanup EXIT INT TERM

git -C "${ROOT}" worktree add --detach "${TMP}" "${FREEZE}" >/dev/null
(
  cd "${TMP}/Weall-Protocol"
  PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py
  PYTHONPATH=src python scripts/compile_v2_spec.py --check
  PYTHONPATH=src python scripts/gen_governance_execution_vectors_v1_5.py --check
)
(
  cd "${TMP}"
  python scripts/check_m3_requirement_traceability.py
  test -z "$(git status --short --untracked-files=all)"
)
echo "OK: M3 clean-checkout reproduction passed for ${FREEZE}"
