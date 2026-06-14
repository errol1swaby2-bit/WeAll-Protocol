#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${BACKEND_DIR:-${ROOT_DIR}/Weall-Protocol}"
WEB_DIR="${WEB_DIR:-${ROOT_DIR}/web}"
HOST_PYTHON_BIN="${HOST_PYTHON_BIN:-python3}"
BACKEND_VENV_DIR="${BACKEND_VENV_DIR:-${BACKEND_DIR}/.venv}"
PYTHON_BIN="${PYTHON_BIN:-}"
RUN_INSTALL=1
RUN_FRONTEND=1
RUN_FULL_PYTEST=1
RUN_DEPENDENCY_CHECK=1
RUN_CONTROLLED_GO_GATE=1
RUN_RENDERED_FRONTEND="${WEALL_RUN_RENDERED_FRONTEND:-0}"
ALLOW_DIRTY="${WEALL_ALLOW_DIRTY:-0}"
OUT_DIR="${WEALL_GATE_OUT_DIR:-}"

usage() {
  cat <<'EOF'
Usage: scripts/run_clean_clone_go_gate_v1_5.sh [options]

Runs the v1.5 clean-clone controlled-testnet go-gate from the repository root.
The default path creates/uses the backend .venv, installs backend dependencies inside
that virtual environment, runs artifact gates, runs the Batch 615
Genesis -> observer -> promoted-validator -> mempool rehearsal, runs full pytest, runs
frontend production checks, and finally refuses a dirty git worktree.

Options:
  --skip-install       Do not install backend Python dependencies first.
                       The script still creates/uses the backend .venv for checks.
  --venv-dir DIR       Use or create DIR as the backend virtualenv
                       (default: Weall-Protocol/.venv).
  --skip-frontend      Do not run frontend checks.
  --skip-dependency-check
                       Do not run the backend dependency import smoke check.
  --skip-controlled-go-gate
                       Do not run scripts/run_controlled_testnet_go_gate_v1_5.py.
  --run-rendered-frontend
                       Run the Playwright rendered operator journey check.
                       This requires browser dependencies and is otherwise
                       reported as not run by default.
  --no-full-pytest     Run targeted Batch 615 tests, but skip the full pytest suite.
  --allow-dirty        Do not fail when git status is dirty after the gates.
  --out-dir DIR        Write generated rehearsal reports to DIR instead of a temp dir.
  -h, --help           Show this help.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-install)
      RUN_INSTALL=0
      ;;
    --skip-frontend)
      RUN_FRONTEND=0
      ;;
    --venv-dir)
      shift
      if [ "$#" -eq 0 ]; then
        echo "ERROR: --venv-dir requires a path" >&2
        exit 2
      fi
      BACKEND_VENV_DIR="$1"
      ;;
    --skip-dependency-check)
      RUN_DEPENDENCY_CHECK=0
      ;;
    --skip-controlled-go-gate)
      RUN_CONTROLLED_GO_GATE=0
      ;;
    --run-rendered-frontend)
      RUN_RENDERED_FRONTEND=1
      ;;
    --no-full-pytest)
      RUN_FULL_PYTEST=0
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      ;;
    --out-dir)
      shift
      if [ "$#" -eq 0 ]; then
        echo "ERROR: --out-dir requires a path" >&2
        exit 2
      fi
      OUT_DIR="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ ! -d "${BACKEND_DIR}/src/weall" ]; then
  echo "ERROR: backend source tree not found at ${BACKEND_DIR}" >&2
  exit 1
fi

if [ -z "${OUT_DIR}" ]; then
  OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/weall_batch615_gate_XXXXXX")"
fi
mkdir -p "${OUT_DIR}"

export PYTHONPATH="${BACKEND_DIR}/src:${BACKEND_DIR}/scripts${PYTHONPATH:+:${PYTHONPATH}}"

run_backend() {
  (cd "${BACKEND_DIR}" && "$@")
}

run_frontend() {
  (cd "${WEB_DIR}" && "$@")
}

ensure_backend_venv() {
  if [ -n "${PYTHON_BIN}" ]; then
    if [ ! -x "${PYTHON_BIN}" ]; then
      echo "ERROR: PYTHON_BIN was supplied but is not executable: ${PYTHON_BIN}" >&2
      exit 1
    fi
    return 0
  fi

  if [ ! -x "${BACKEND_VENV_DIR}/bin/python" ]; then
    echo "== Creating backend virtualenv: ${BACKEND_VENV_DIR} =="
    if ! run_backend "${HOST_PYTHON_BIN}" -m venv "${BACKEND_VENV_DIR}"; then
      echo "ERROR: unable to create backend virtualenv at ${BACKEND_VENV_DIR}" >&2
      echo "Install the OS venv package if needed, for example: sudo apt install python3-venv" >&2
      exit 1
    fi
  fi

  PYTHON_BIN="${BACKEND_VENV_DIR}/bin/python"
  export VIRTUAL_ENV="${BACKEND_VENV_DIR}"
  export PATH="${BACKEND_VENV_DIR}/bin:${PATH}"
}

echo "== v1.5 clean-clone go-gate =="
echo "Backend: ${BACKEND_DIR}"
echo "Frontend: ${WEB_DIR}"
echo "Output: ${OUT_DIR}"

ensure_backend_venv
echo "Python: ${PYTHON_BIN}"
echo "Virtualenv: ${BACKEND_VENV_DIR}"

if [ "${RUN_INSTALL}" = "1" ]; then
  echo "== Installing backend dependencies =="
  if [ -f "${BACKEND_DIR}/requirements-dev.lock" ]; then
    run_backend "${PYTHON_BIN}" -m pip install -r requirements-dev.lock
  elif [ -f "${BACKEND_DIR}/requirements-dev.txt" ]; then
    run_backend "${PYTHON_BIN}" -m pip install -r requirements-dev.txt
  elif [ -f "${BACKEND_DIR}/requirements.txt" ]; then
    run_backend "${PYTHON_BIN}" -m pip install -r requirements.txt
  else
    echo "ERROR: no backend requirements file found" >&2
    exit 1
  fi
fi

if [ "${RUN_DEPENDENCY_CHECK}" = "1" ]; then
  if run_backend test -f scripts/check_backend_test_dependencies.py; then
    echo "== Checking backend test dependencies =="
    run_backend "${PYTHON_BIN}" scripts/check_backend_test_dependencies.py
  else
    echo "WARN: scripts/check_backend_test_dependencies.py not present; dependency smoke is covered by pytest imports"
  fi
else
  echo "== Skipping backend dependency check because --skip-dependency-check was supplied =="
fi

echo "== Checking release hygiene invariants =="
if run_backend test -f scripts/check_release_hygiene_v1_5.py; then
  run_backend "${PYTHON_BIN}" scripts/check_release_hygiene_v1_5.py --allow-dirty
fi

echo "== Checking generated artifacts =="
run_backend "${PYTHON_BIN}" scripts/gen_api_contract_map.py --check
run_backend "${PYTHON_BIN}" scripts/gen_failure_code_registry_v1_5.py --check
if run_backend test -f scripts/gen_api_response_vectors_v1_5.py; then
  run_backend "${PYTHON_BIN}" scripts/gen_api_response_vectors_v1_5.py --check
fi
if run_backend test -f scripts/gen_state_root_vectors_v1_5.py; then
  run_backend "${PYTHON_BIN}" scripts/gen_state_root_vectors_v1_5.py --check
fi
if run_backend test -f scripts/gen_tokenomics_simulation_v1_5.py; then
  run_backend "${PYTHON_BIN}" scripts/gen_tokenomics_simulation_v1_5.py --check
fi
if run_backend test -f scripts/gen_public_validator_bft_preflight_matrix_v1_5.py; then
  run_backend "${PYTHON_BIN}" scripts/gen_public_validator_bft_preflight_matrix_v1_5.py --check
fi
run_backend "${PYTHON_BIN}" scripts/check_tx_canon_artifacts.py
run_backend "${PYTHON_BIN}" scripts/check_v15_public_readiness_artifacts.py --require-git-tracked
if [ "${RUN_CONTROLLED_GO_GATE}" = "1" ]; then
  run_backend "${PYTHON_BIN}" scripts/run_controlled_testnet_go_gate_v1_5.py --run-gates --require-git-tracked
else
  echo "== Skipping controlled testnet go-gate because --skip-controlled-go-gate was supplied =="
fi

echo "== Running Batch 615 Genesis -> observer -> promoted-validator -> mempool rehearsal =="
run_backend "${PYTHON_BIN}" scripts/rehearse_genesis_observer_promoted_validator_mempool_v1_5.py \
  --json \
  --write-report "${OUT_DIR}/batch615_genesis_observer_promoted_validator_mempool_v1_5.json"

echo "== Running Batch 616 release blocker closure rehearsal =="
if run_backend test -f scripts/rehearse_batch616_release_blocker_closure_v1_5.py; then
  run_backend "${PYTHON_BIN}" scripts/rehearse_batch616_release_blocker_closure_v1_5.py \
    --json \
    --write-report "${OUT_DIR}/batch616_release_blocker_closure_v1_5.json"
fi

echo "== Running Batch 615 targeted tests =="
run_backend "${PYTHON_BIN}" -m pytest -q \
  tests/prod/test_multinode_mempool_propagation_convergence.py \
  tests/prod/test_promoted_validator_live_rehearsal.py \
  tests/prod/test_batch616_release_blocker_closure.py \
  tests/test_batch616_exact_responsibility_lane_consent.py

if [ "${RUN_FULL_PYTEST}" = "1" ]; then
  echo "== Running full pytest suite =="
  run_backend "${PYTHON_BIN}" -m pytest -q
else
  echo "== Skipping full pytest suite because --no-full-pytest was supplied =="
fi

if [ "${RUN_FRONTEND}" = "1" ]; then
  if [ ! -f "${WEB_DIR}/package.json" ]; then
    echo "ERROR: frontend package.json not found at ${WEB_DIR}" >&2
    exit 1
  fi
  echo "== Running frontend checks =="
  if [ -f "${WEB_DIR}/package-lock.json" ]; then
    run_frontend npm ci
  else
    run_frontend npm install
  fi
  run_frontend npm run typecheck
  run_frontend npm run production-safety-check
  run_frontend node scripts/guard_production_ux_safety.mjs
  run_frontend node scripts/test_node_dashboard_source.mjs
  run_frontend node scripts/test_accessibility_source.mjs
  if [ -f "${WEB_DIR}/scripts/test_batch596_dispute_current_queue_source.mjs" ]; then
    run_frontend node scripts/test_batch596_dispute_current_queue_source.mjs
  fi
  if [ -f "${WEB_DIR}/scripts/test_batch616_responsibility_control_surface_source.mjs" ]; then
    run_frontend node scripts/test_batch616_responsibility_control_surface_source.mjs
  fi
  if [ -f "${WEB_DIR}/scripts/test_batch618_public_beta_blocker_surface_source.mjs" ]; then
    run_frontend node scripts/test_batch618_public_beta_blocker_surface_source.mjs
  fi
  if [ -f "${WEB_DIR}/scripts/test_batch620_operator_journey_and_accent_source.mjs" ]; then
    run_frontend node scripts/test_batch620_operator_journey_and_accent_source.mjs
  fi
  if [ "${RUN_RENDERED_FRONTEND}" = "1" ]; then
    if run_frontend npm run | grep -q "test:rendered-operator-journey"; then
      echo "== Running rendered operator journey check =="
      run_frontend npm run test:rendered-operator-journey
    else
      echo "ERROR: rendered operator journey script is missing from web/package.json" >&2
      exit 1
    fi
  else
    echo "== Rendered operator journey check not run; use --run-rendered-frontend or WEALL_RUN_RENDERED_FRONTEND=1 when Playwright browsers are installed =="
  fi
  if [ -x "${ROOT_DIR}/scripts/run_frontend_contract_check_with_backend.sh" ]; then
    "${ROOT_DIR}/scripts/run_frontend_contract_check_with_backend.sh"
  else
    echo "WARN: frontend contract check with backend script not executable; skipping live contract check" >&2
  fi
else
  echo "== Skipping frontend checks because --skip-frontend was supplied =="
fi

if [ "${ALLOW_DIRTY}" != "1" ] && git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "== Verifying git worktree cleanliness =="
  STATUS="$(git -C "${ROOT_DIR}" status --short --untracked-files=all)"
  if [ -n "${STATUS}" ]; then
    echo "ERROR: Batch 615 gate left or detected a dirty worktree:" >&2
    echo "${STATUS}" >&2
    echo "Re-run with --allow-dirty only for local development, not release evidence." >&2
    exit 1
  fi
fi

echo "OK: v1.5 clean-clone go-gate passed"
echo "Report directory: ${OUT_DIR}"
