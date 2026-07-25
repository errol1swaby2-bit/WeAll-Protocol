#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m3_common.sh"
M3_BACKEND="${ROOT}/Weall-Protocol"
M3_WEB="${WEALL_WEB_DIR:-${ROOT}/web}"
MODE="evidence-generation"

usage() {
  cat <<'EOF'
Usage: scripts/run_m3_complete_closure.sh [--evidence-only]

Generates the complete M3 evidence tree while HEAD remains exactly the
implementation-freeze commit. The resulting artifacts must then be staged,
checked with check_m3_evidence_only_commit.sh --cached, and committed once as
the direct evidence-only child.

--evidence-only  Compatibility alias for the same valid sequencing. HEAD must
                 still equal M3_IMPLEMENTATION_FREEZE_COMMIT; no direct child
                 may exist before evidence generation.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence-only) MODE="evidence-only-generation"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

m3_activate_venv
for cmd in git python node npm curl; do m3_require_command "${cmd}"; done

FREEZE="${M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M3_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
FREEZE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{commit}")"
TREE="$(git -C "${ROOT}" rev-parse "${FREEZE}^{tree}")"
HEAD_COMMIT="$(git -C "${ROOT}" rev-parse HEAD)"
[[ "${HEAD_COMMIT}" == "${FREEZE}" ]] || {
  echo "ERROR: M3 evidence generation must run while HEAD equals the implementation freeze." >&2
  echo "freeze=${FREEZE} head=${HEAD_COMMIT}" >&2
  exit 2
}
if git -C "${ROOT}" ls-tree -r --name-only "${FREEZE}" -- artifacts/m3-closure | grep -q .; then
  echo "ERROR: the implementation freeze already contains M3 closure evidence" >&2
  exit 2
fi
DIRTY="$(git -C "${ROOT}" status --porcelain --untracked-files=all | grep -vE '^.. artifacts/m3-closure/')"
if [[ -n "${DIRTY}" ]]; then
  echo "ERROR: source tree must be clean before M3 evidence generation" >&2
  printf '%s\n' "${DIRTY}" >&2
  exit 2
fi

ACTOR_MANIFEST="${WEALL_M3_ACTOR_MANIFEST:-}"
[[ -n "${ACTOR_MANIFEST}" && -f "${ACTOR_MANIFEST}" ]] || {
  echo "ERROR: WEALL_M3_ACTOR_MANIFEST must point to the completed schema-v3 actor contract." >&2
  exit 2
}
PRECHECK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/weall_m3_actor_precheck_XXXXXX")"
cleanup_precheck() { rm -rf "${PRECHECK_DIR}"; }
trap cleanup_precheck EXIT INT TERM
python "${ROOT}/scripts/validate_m3_actor_manifest.py" \
  --manifest "${ACTOR_MANIFEST}" \
  --implementation-freeze "${FREEZE}" \
  --out-public-manifest "${PRECHECK_DIR}/M3_ACTOR_MANIFEST.json" \
  --out-transcript "${PRECHECK_DIR}/transaction-transcript.json" >/dev/null
readarray -t M3_PREFLIGHT_URLS < <(python - "${ACTOR_MANIFEST}" <<'PYURL'
import json, sys
obj=json.load(open(sys.argv[1], encoding='utf-8'))
print(str(obj['backend_base_url']).rstrip('/'))
print(str(obj.get('frontend_base_url') or 'http://127.0.0.1:5173').rstrip('/'))
PYURL
)
curl -fsS "${M3_PREFLIGHT_URLS[0]}/v1/status" >/dev/null
curl -fsS "${M3_PREFLIGHT_URLS[1]}/" >/dev/null
cleanup_precheck
trap - EXIT INT TERM

rm -rf "${M3_ARTIFACT_ROOT}"
mkdir -p "${M3_ARTIFACT_ROOT}"/{backend,frontend,browser/civic,restart-replay,two-node,observer,privacy}
RESULTS_FILE="${M3_ARTIFACT_ROOT}/gate-results.tsv"
: > "${RESULTS_FILE}"
FAILURES=0

run_gate() {
  local name="$1" rel_log="$2"; shift 2
  local log_path command_text rc
  log_path="${M3_ARTIFACT_ROOT}/${rel_log}"
  mkdir -p "$(dirname "${log_path}")"
  printf -v command_text '%q ' "$@"
  command_text="${command_text//$'\t'/ }"
  command_text="${command_text//$'\n'/ }"
  echo "[M3] ${name}"
  (
    set -o pipefail
    "$@"
  ) >"${log_path}" 2>&1
  rc=$?
  if [[ ${rc} -eq 0 ]]; then
    printf '%s\tpassed\t0\t%s\t%s\n' "${name}" "${rel_log}" "${command_text}" >> "${RESULTS_FILE}"
    echo "[M3] PASS ${name}"
  else
    printf '%s\tfailed\t%s\t%s\t%s\n' "${name}" "${rc}" "${rel_log}" "${command_text}" >> "${RESULTS_FILE}"
    echo "[M3] FAIL ${name} (see ${log_path})" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

run_backend() { (cd "${M3_BACKEND}" && PYTHONPATH=src "$@"); }
run_web() { (cd "${M3_WEB}" && "$@"); }
run_web_package() {
  local required_bin="$1"; shift
  if [[ ! -x "${M3_WEB}/node_modules/.bin/${required_bin}" ]]; then
    echo "Frontend dependency missing: node_modules/.bin/${required_bin}. Run scripts/bootstrap_m3_environment.sh." >&2
    return 1
  fi
  run_web "$@"
}

run_gate "dependency preflight" "backend/dependency-preflight.log" python "${ROOT}/scripts/check_m3_dependencies.py"
run_gate "M3 strict live ballot profile" "backend/live-ballot-profile.log" python \
  "${ROOT}/scripts/check_m3_live_ballot_profile.py" \
  --api-base "${M3_PREFLIGHT_URLS[0]}" \
  --out "${M3_ARTIFACT_ROOT}/backend/live-ballot-profile.json" \
  --implementation-freeze "${FREEZE}" \
  --implementation-tree "${TREE}"
run_gate "M3 requirement traceability" "backend/requirement-traceability.log" python "${ROOT}/scripts/check_m3_requirement_traceability.py"
run_gate "v1.5 readiness artifacts current" "backend/v15-readiness.log" run_backend python scripts/check_v15_public_readiness_artifacts.py
run_gate "v2 specification derivatives current" "backend/v2-derivatives.log" run_backend python scripts/compile_v2_spec.py --check
run_gate "governance execution vectors current" "backend/governance-vectors.log" run_backend python scripts/gen_governance_execution_vectors_v1_5.py --check
run_gate "clean checkout reproduction" "backend/clean-checkout.log" env M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" bash "${ROOT}/scripts/run_m3_clean_checkout_reproduction.sh"
run_gate "M3 runtime regression suite" "backend/m3-runtime-regressions.log" run_backend python -m pytest -q \
  tests/test_m3_electorate_round_policy.py \
  tests/test_m3_genesis_ballot_profile.py \
  tests/test_m3_scope_contract.py \
  tests/test_m3_closure_regressions.py \
  tests/test_m3_closure_integrity.py
run_gate "M3 persistence replay and convergence" "backend/m3-replay-convergence.log" run_backend python -m pytest -q \
  tests/test_feed_persists_order_after_restart_api.py \
  tests/test_priority1_replay_schedule_consistency.py \
  tests/test_priority2_state_replay_determinism.py \
  tests/test_e2e_two_node_convergence.py
run_gate "helper serial equivalence and fallback" "backend/helper-equivalence.log" run_backend python -m pytest -q \
  tests/test_helper_serial_equivalence_corpus.py \
  tests/test_helper_serial_equivalence_fallback.py \
  tests/test_helper_offline_fallback_deterministic.py \
  tests/test_helper_restart_equivalence.py \
  tests/test_helper_multinode_divergence_guards.py
run_gate "full backend suite" "backend/full-pytest.log" run_backend python -m pytest -q

run_gate "frontend public social source" "frontend/public-social-source.log" run_web node scripts/test_public_social_flow_readiness_source.mjs
run_gate "frontend group flow source" "frontend/group-flow-source.log" run_web node scripts/test_group_flow_readiness_source.mjs
run_gate "frontend public-only protocol source" "frontend/public-only-protocol-source.log" run_web npm run test:public-only-protocol-source
run_gate "frontend account profile source" "frontend/account-profile-source.log" run_web node scripts/test_account_profile_readiness_source.mjs
run_gate "frontend first-run source" "frontend/first-run-source.log" run_web node scripts/test_first_run_tester_journey_source.mjs
run_gate "frontend governance source" "frontend/governance-source.log" run_web node scripts/test_governance_rendered_journey_source.mjs
run_gate "frontend dispute source" "frontend/dispute-source.log" run_web node scripts/test_dispute_review_rendered_journey_source.mjs
run_gate "frontend contract check" "frontend/contract-check.log" run_web env API_BASE="${M3_PREFLIGHT_URLS[0]}" npm run contract-check
run_gate "frontend production safety check" "frontend/production-safety.log" run_web npm run production-safety-check
run_gate "frontend typecheck" "frontend/typecheck.log" run_web_package tsc npm run typecheck
run_gate "frontend production build" "frontend/build.log" run_web_package vite npm run build

run_gate "M3 signed real-stack actor journey" "browser/civic/runner.log" env \
  M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
  WEALL_M3_ACTOR_MANIFEST="${ACTOR_MANIFEST}" \
  WEALL_M3_EVIDENCE_DIR="${M3_ARTIFACT_ROOT}" \
  bash "${ROOT}/scripts/run_m3_civic_real_stack_e2e.sh"
run_gate "M3 restart replay equality" "restart-replay/runner.log" env \
  M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
  WEALL_M3_EVIDENCE_DIR="${M3_ARTIFACT_ROOT}" \
  bash "${ROOT}/scripts/run_m3_restart_replay_gate.sh"
run_gate "M3 two-node equality" "two-node/runner.log" env \
  M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
  WEALL_M3_EVIDENCE_DIR="${M3_ARTIFACT_ROOT}" \
  bash "${ROOT}/scripts/run_m3_two_node_state_root_gate.sh"
run_gate "M3 observer catch-up without authority" "observer/runner.log" env \
  M3_IMPLEMENTATION_FREEZE_COMMIT="${FREEZE}" \
  WEALL_M3_EVIDENCE_DIR="${M3_ARTIFACT_ROOT}" \
  bash "${ROOT}/scripts/run_m3_observer_catchup_gate.sh"
run_gate "M3 artifact privacy scan" "privacy/runner.log" env \
  WEALL_M3_EVIDENCE_DIR="${M3_ARTIFACT_ROOT}" \
  bash "${ROOT}/scripts/run_m3_privacy_scan.sh"

python "${ROOT}/scripts/gen_m3_closure_manifest.py" \
  --workspace "${ROOT}" \
  --evidence-dir "${M3_ARTIFACT_ROOT}" \
  --results "${RESULTS_FILE}" \
  --mode "${MODE}" \
  --implementation-freeze "${FREEZE}" >/dev/null 2>&1
MANIFEST_RC=$?

if [[ ${FAILURES} -ne 0 || ${MANIFEST_RC} -ne 0 ]]; then
  echo "M3 closure FAILED: ${FAILURES} gate(s) failed. Evidence: ${M3_ARTIFACT_ROOT}" >&2
  exit 1
fi

echo "M3 evidence generation PASSED for freeze ${FREEZE}."
echo "Next: git add artifacts/m3-closure && M3_IMPLEMENTATION_FREEZE_COMMIT=${FREEZE} bash scripts/check_m3_evidence_only_commit.sh --cached"
