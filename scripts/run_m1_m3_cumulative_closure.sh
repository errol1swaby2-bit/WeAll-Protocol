#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="${ROOT}/Weall-Protocol"
WEB="${ROOT}/web"
ARTIFACT_ROOT="${WEALL_M1_M3_ARTIFACT_ROOT:-${ROOT}/artifacts/m1-m3-integrated}"
MODE="source-only"

usage() {
  cat <<'USAGE'
Usage: scripts/run_m1_m3_cumulative_closure.sh [--source-only|--full]

--source-only  Fast cumulative source, build, historical-evidence, and adversarial pass.
--full         Also reruns complete M2 and M3 real-stack closure suites in isolated
               worktrees at the same implementation freeze. Requires
               WEALL_M3_ACTOR_MANIFEST and all M2/M3 external test prerequisites.
USAGE
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-only) MODE="source-only"; shift ;;
    --full) MODE="full"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for cmd in git python3 node npm; do
  command -v "${cmd}" >/dev/null 2>&1 || { echo "ERROR: missing command: ${cmd}" >&2; exit 2; }
done

FREEZE="${M1_M3_IMPLEMENTATION_FREEZE_COMMIT:-$(git -C "${ROOT}" rev-parse HEAD)}"
FREEZE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{commit}")"
[[ "$(git -C "${ROOT}" rev-parse HEAD)" == "${FREEZE}" ]] || {
  echo "ERROR: HEAD must equal M1_M3_IMPLEMENTATION_FREEZE_COMMIT" >&2; exit 2;
}
DIRTY="$(git -C "${ROOT}" status --porcelain --untracked-files=all | grep -vE '^.. artifacts/m1-m3-integrated/' || true)"
[[ -z "${DIRTY}" ]] || { echo "ERROR: implementation tree is dirty" >&2; printf '%s\n' "${DIRTY}" >&2; exit 2; }
if git -C "${ROOT}" ls-tree -r --name-only "${FREEZE}" -- artifacts/m1-m3-integrated | grep -q .; then
  echo "ERROR: implementation freeze already contains integrated evidence" >&2; exit 2
fi

rm -rf "${ARTIFACT_ROOT}"
mkdir -p "${ARTIFACT_ROOT}"/{source,frontend,adversarial,historical,environment,m2,m3}
RESULTS="${ARTIFACT_ROOT}/gate-results.tsv"
: > "${RESULTS}"
FAILURES=0

run_gate() {
  local name="$1" rel="$2"; shift 2
  local log="${ARTIFACT_ROOT}/${rel}" rc command_text
  mkdir -p "$(dirname "${log}")"
  printf -v command_text '%q ' "$@"
  echo "[M1-M3] ${name}"
  (set -o pipefail; "$@") >"${log}" 2>&1
  rc=$?
  if [[ ${rc} -eq 0 ]]; then
    printf '%s\tpassed\t0\t%s\t%s\n' "${name}" "${rel}" "${command_text}" >> "${RESULTS}"
    echo "[M1-M3] PASS ${name}"
  else
    printf '%s\tfailed\t%s\t%s\t%s\n' "${name}" "${rc}" "${rel}" "${command_text}" >> "${RESULTS}"
    echo "[M1-M3] FAIL ${name}: ${log}" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

run_backend() { (cd "${BACKEND}" && PYTHONPATH=src:scripts WEALL_API_BOOT_RUNTIME=0 "$@"); }
run_web() { (cd "${WEB}" && "$@"); }

run_gate "consensus profile manifest" "source/consensus-profile.log" run_backend python scripts/check_consensus_profile_manifest.py
run_gate "Spec-M1 v2 derivatives" "source/v2-derivatives.log" run_backend python scripts/compile_v2_spec.py --check
run_gate "M2 requirement traceability" "source/m2-traceability.log" python3 "${ROOT}/scripts/check_m2_requirement_traceability.py"
run_gate "M3 requirement traceability" "source/m3-traceability.log" python3 "${ROOT}/scripts/check_m3_requirement_traceability.py"
run_gate "historical M2/M3 evidence pairs" "historical/verification.log" bash "${ROOT}/scripts/restore_m2_m3_evidence_from_git.sh" --verify-only
run_gate "full backend suite" "source/full-pytest.log" run_backend python -m pytest -q
run_gate "M1-M3 adversarial matrix" "adversarial/runner.log" env \
  WEALL_M1_M3_ADVERSARIAL_LOG="${ARTIFACT_ROOT}/adversarial/matrix.log" \
  bash "${ROOT}/scripts/run_m1_m3_adversarial_matrix.sh"

if [[ ! -d "${WEB}/node_modules" ]]; then
  run_gate "frontend npm clean install" "frontend/npm-ci.log" run_web npm ci
fi
run_gate "frontend typecheck" "frontend/typecheck.log" run_web npm run typecheck
run_gate "frontend production build" "frontend/build.log" run_web npm run build
run_gate "frontend production safety" "frontend/production-safety.log" run_web npm run production-safety-check
run_gate "frontend custody cryptographic source" "frontend/account-custody-crypto.log" run_web npm run test:account-custody-crypto-source
run_gate "reproducible environment capture" "environment/capture.log" python3 \
  "${ROOT}/scripts/capture_m1_m3_reproducible_environment.py" \
  --freeze-commit "${FREEZE}" \
  --out "${ARTIFACT_ROOT}/environment/reproducible-environment.json"

if [[ "${MODE}" == "full" ]]; then
  [[ -n "${WEALL_M3_ACTOR_MANIFEST:-}" && -f "${WEALL_M3_ACTOR_MANIFEST}" ]] || {
    echo "ERROR: --full requires WEALL_M3_ACTOR_MANIFEST" >&2; exit 2;
  }
  TMP="$(mktemp -d "${TMPDIR:-/tmp}/weall_m1_m3_full_XXXXXX")"
  cleanup_worktrees() {
    git -C "${ROOT}" worktree remove --force "${TMP}/m2" >/dev/null 2>&1 || true
    git -C "${ROOT}" worktree remove --force "${TMP}/m3" >/dev/null 2>&1 || true
    rm -rf "${TMP}"
  }
  trap cleanup_worktrees EXIT INT TERM
  git -C "${ROOT}" worktree add --detach "${TMP}/m2" "${FREEZE}" >/dev/null
  git -C "${ROOT}" worktree add --detach "${TMP}/m3" "${FREEZE}" >/dev/null
  for worktree in "${TMP}/m2" "${TMP}/m3"; do
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
      : # inherited by child runners
    elif [[ -d "${ROOT}/.venv" ]]; then
      ln -s "${ROOT}/.venv" "${worktree}/.venv"
    elif [[ -d "${ROOT}/.venv-m3" ]]; then
      ln -s "${ROOT}/.venv-m3" "${worktree}/.venv-m3"
    fi
    if [[ -d "${WEB}/node_modules" ]]; then
      ln -s "${WEB}/node_modules" "${worktree}/web/node_modules"
    fi
  done

  run_gate "fresh complete M2 closure" "m2/runner.log" env \
    M2_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
    WEALL_M2_ARTIFACT_ROOT="${TMP}/m2/artifacts/m2-closure" \
    bash "${TMP}/m2/scripts/run_m2_complete_closure.sh"
  if [[ -d "${TMP}/m2/artifacts/m2-closure" ]]; then
    cp -a "${TMP}/m2/artifacts/m2-closure/." "${ARTIFACT_ROOT}/m2/"
  fi

  run_gate "fresh complete M3 closure" "m3/runner.log" env \
    M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
    WEALL_M3_ACTOR_MANIFEST="${WEALL_M3_ACTOR_MANIFEST}" \
    WEALL_M3_EVIDENCE_DIR="${TMP}/m3/artifacts/m3-closure" \
    bash "${TMP}/m3/scripts/run_m3_complete_closure.sh"
  if [[ -d "${TMP}/m3/artifacts/m3-closure" ]]; then
    cp -a "${TMP}/m3/artifacts/m3-closure/." "${ARTIFACT_ROOT}/m3/"
  fi
  cleanup_worktrees
  trap - EXIT INT TERM
fi

if [[ ${FAILURES} -ne 0 ]]; then
  echo "M1-M3 cumulative closure FAILED: ${FAILURES} gate(s) failed" >&2
  exit 1
fi

python3 "${ROOT}/scripts/build_m1_m3_integrated_manifest.py" \
  --artifact-root "${ARTIFACT_ROOT#${ROOT}/}" \
  --freeze-commit "${FREEZE}" \
  --mode "${MODE}"

echo "OK: M1-M3 ${MODE} cumulative closure passed for ${FREEZE}"
echo "Evidence: ${ARTIFACT_ROOT}"
