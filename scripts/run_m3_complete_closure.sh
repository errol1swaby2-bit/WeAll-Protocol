#!/usr/bin/env bash
set -uo pipefail

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${WORKSPACE_DIR}/Weall-Protocol"
WEB_DIR="${WEALL_WEB_DIR:-${WORKSPACE_DIR}/web}"
EVIDENCE_DIR="${WEALL_M3_EVIDENCE_DIR:-${WORKSPACE_DIR}/artifacts/m3-closure}"
MODE="implementation-and-evidence"

usage() {
  cat <<'EOF'
Usage: scripts/run_m3_complete_closure.sh [--evidence-only]

Runs the complete M3 closure gate and writes hashed logs plus
M3_EVIDENCE_MANIFEST.json. The command is intentionally fail-closed:
missing dependencies, frontend packages, actor manifests, or external evidence
produce a non-zero result rather than a silent skip.

--evidence-only  Require HEAD to be a clean direct child of
                 M3_IMPLEMENTATION_FREEZE_COMMIT and run only evidence
                 collection against that frozen implementation.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence-only) MODE="evidence-only"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

FREEZE="${M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
if [[ -z "${FREEZE}" ]]; then
  FREEZE="$(git -C "${WORKSPACE_DIR}" rev-parse HEAD)"
fi
FREEZE="$(git -C "${WORKSPACE_DIR}" rev-parse "${FREEZE}^{commit}")"

mkdir -p "${EVIDENCE_DIR}"
rm -f "${EVIDENCE_DIR}"/*.log \
  "${EVIDENCE_DIR}/gate-results.tsv" \
  "${EVIDENCE_DIR}/M3_EVIDENCE_MANIFEST.json" \
  "${EVIDENCE_DIR}/M3_ACTOR_MANIFEST.json" \
  "${EVIDENCE_DIR}/M3_EXTERNAL_TWO_NODE_EVIDENCE.json"
RESULTS_FILE="${EVIDENCE_DIR}/gate-results.tsv"
: > "${RESULTS_FILE}"
FAILURES=0

slug() { printf '%s' "$1" | tr '[:upper:] /:' '[:lower:]---' | tr -cd 'a-z0-9._-'; }

run_gate() {
  local name="$1"; shift
  local log_name command_text
  log_name="$(slug "${name}").log"
  printf -v command_text '%q ' "$@"
  command_text="${command_text//$'\t'/ }"
  command_text="${command_text//$'\n'/ }"
  echo "[M3] ${name}"
  (
    set -o pipefail
    "$@"
  ) >"${EVIDENCE_DIR}/${log_name}" 2>&1
  local rc=$?
  if [[ ${rc} -eq 0 ]]; then
    printf '%s\tpassed\t0\t%s\t%s\n' "${name}" "${log_name}" "${command_text}" >> "${RESULTS_FILE}"
    echo "[M3] PASS ${name}"
  else
    printf '%s\tfailed\t%s\t%s\t%s\n' "${name}" "${rc}" "${log_name}" "${command_text}" >> "${RESULTS_FILE}"
    echo "[M3] FAIL ${name} (see ${EVIDENCE_DIR}/${log_name})" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

run_backend() {
  (cd "${BACKEND_DIR}" && PYTHONPATH=src "$@")
}

run_web() {
  (cd "${WEB_DIR}" && "$@")
}

run_web_package() {
  local required_bin="$1"; shift
  if [[ ! -x "${WEB_DIR}/node_modules/.bin/${required_bin}" ]]; then
    echo "Frontend dependencies are incomplete: missing node_modules/.bin/${required_bin}. Run scripts/bootstrap_m3_environment.sh." >&2
    return 1
  fi
  run_web "$@"
}

if [[ "${MODE}" == "evidence-only" ]]; then
  if [[ -z "${M3_IMPLEMENTATION_FREEZE_COMMIT:-}" ]]; then
    echo "M3_IMPLEMENTATION_FREEZE_COMMIT is required for --evidence-only" >&2
    exit 2
  fi
  if [[ -n "$(git -C "${WORKSPACE_DIR}" status --porcelain)" ]]; then
    echo "Evidence-only closure requires a clean worktree" >&2
    exit 2
  fi
  if ! HEAD_PARENT="$(git -C "${WORKSPACE_DIR}" rev-parse HEAD^ 2>/dev/null)"; then
    HEAD_PARENT=""
  fi
  if [[ "${HEAD_PARENT}" != "${FREEZE}" ]]; then
    echo "Evidence-only HEAD must be a direct child of the implementation freeze commit" >&2
    echo "expected parent=${FREEZE} actual parent=${HEAD_PARENT}" >&2
    exit 2
  fi
fi

run_gate "dependency preflight" python "${WORKSPACE_DIR}/scripts/check_m3_dependencies.py"
run_gate "M3 requirement traceability" python "${WORKSPACE_DIR}/scripts/check_m3_requirement_traceability.py"
run_gate "governance execution vectors current" run_backend python scripts/gen_governance_execution_vectors_v1_5.py --check
run_gate "M3 runtime regression suite" run_backend pytest -q \
  tests/test_m3_electorate_round_policy.py \
  tests/test_m3_scope_contract.py \
  tests/test_m3_closure_regressions.py
run_gate "M3 persistence replay and convergence" run_backend pytest -q \
  tests/test_feed_persists_order_after_restart_api.py \
  tests/test_priority1_replay_schedule_consistency.py \
  tests/test_priority2_state_replay_determinism.py \
  tests/test_e2e_two_node_convergence.py
run_gate "helper serial equivalence and fallback" run_backend pytest -q \
  tests/test_helper_serial_equivalence_corpus.py \
  tests/test_helper_serial_equivalence_fallback.py \
  tests/test_helper_offline_fallback_deterministic.py \
  tests/test_helper_restart_equivalence.py \
  tests/test_helper_multinode_divergence_guards.py

if [[ "${WEALL_M3_SKIP_FULL_BACKEND:-0}" == "1" ]]; then
  run_gate "full backend suite forbidden skip marker" bash -c 'echo "WEALL_M3_SKIP_FULL_BACKEND is non-closing"; exit 1'
else
  run_gate "full backend suite" run_backend pytest -q
fi

run_gate "frontend public social source" run_web node scripts/test_public_social_flow_readiness_source.mjs
run_gate "frontend account profile source" run_web node scripts/test_account_profile_readiness_source.mjs
run_gate "frontend first-run source" run_web node scripts/test_first_run_tester_journey_source.mjs
run_gate "frontend governance source" run_web node scripts/test_governance_rendered_journey_source.mjs
run_gate "frontend dispute source" run_web node scripts/test_dispute_review_rendered_journey_source.mjs
run_gate "frontend typecheck" run_web_package tsc npm run typecheck
run_gate "frontend production build" run_web_package vite npm run build

if [[ -z "${WEALL_M3_ACTOR_MANIFEST:-}" ]]; then
  run_gate "M3 real-stack actor journey" bash -c 'echo "WEALL_M3_ACTOR_MANIFEST is required"; exit 1'
else
  run_gate "M3 real-stack actor journey" run_web_package playwright npm run test:m3-civic-governance-real-stack
fi

if [[ -z "${WEALL_M3_EXTERNAL_TWO_NODE_EVIDENCE:-}" ]]; then
  run_gate "external two-node equal-root evidence" bash -c 'echo "WEALL_M3_EXTERNAL_TWO_NODE_EVIDENCE is required"; exit 1'
else
  run_gate "external two-node equal-root evidence" bash -c '
    set -euo pipefail
    p="$1"
    test -f "$p"
    python3 - "$p" <<"PY"
import json, sys
obj=json.load(open(sys.argv[1], encoding="utf-8"))
assert obj.get("equal_state_root") is True
assert obj.get("equal_chain_tip") is True
assert obj.get("independent_nodes") is True
PY
  ' _ "${WEALL_M3_EXTERNAL_TWO_NODE_EVIDENCE}"
fi

if [[ -n "${WEALL_M3_ACTOR_MANIFEST:-}" && -f "${WEALL_M3_ACTOR_MANIFEST}" ]]; then
  cp "${WEALL_M3_ACTOR_MANIFEST}" "${EVIDENCE_DIR}/M3_ACTOR_MANIFEST.json"
fi
if [[ -n "${WEALL_M3_EXTERNAL_TWO_NODE_EVIDENCE:-}" && -f "${WEALL_M3_EXTERNAL_TWO_NODE_EVIDENCE}" ]]; then
  cp "${WEALL_M3_EXTERNAL_TWO_NODE_EVIDENCE}" "${EVIDENCE_DIR}/M3_EXTERNAL_TWO_NODE_EVIDENCE.json"
fi

python "${WORKSPACE_DIR}/scripts/gen_m3_closure_manifest.py" \
  --workspace "${WORKSPACE_DIR}" \
  --evidence-dir "${EVIDENCE_DIR}" \
  --results "${RESULTS_FILE}" \
  --mode "${MODE}" \
  --implementation-freeze "${FREEZE}" >/dev/null 2>&1
MANIFEST_RC=$?

if [[ ${FAILURES} -ne 0 || ${MANIFEST_RC} -ne 0 ]]; then
  echo "M3 closure FAILED: ${FAILURES} gate(s) failed. Evidence: ${EVIDENCE_DIR}" >&2
  exit 1
fi

echo "M3 closure PASSED. Evidence: ${EVIDENCE_DIR}/M3_EVIDENCE_MANIFEST.json"
