#!/usr/bin/env bash
set -euo pipefail

# One-command controlled-devnet readiness suite.
#
# This runs the current externally useful readiness harnesses with clean state,
# no demo seed route, no copied DBs, and normal signed tx submission.
#
# Default suite:
#   1. Direct API permission-gating probe
#   2. Full onboarding + node2 edge/local-producer convergence smoke
#   3. Two-node cross-node convergence live probe
#   4. Restart/catch-up live probe
#
# Useful knobs:
#   WEALL_DEVNET_SUITE_RUN_PERMISSION=0    skip permission probe
#   WEALL_DEVNET_SUITE_RUN_ONBOARDING=0    skip full onboarding smoke
#   WEALL_DEVNET_SUITE_RUN_CROSS_NODE=0    skip cross-node live probe
#   WEALL_DEVNET_SUITE_RUN_RESTART=0       skip restart/catch-up live probe
#   WEALL_DEVNET_SUITE_RUN_TIER2=1         run Tier2 inside onboarding smoke
#   WEALL_DEVNET_SUITE_RUN_TIER3=1         run Tier3 inside onboarding smoke
#   WEALL_EMAIL=person@example.com         required for Tier2/Tier3 full PoH path
#   WEALL_DEVNET_AUTO_VENV=0               disable automatic .venv activation

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

_bool_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

activate_repo_venv() {
  if ! _bool_true "${WEALL_DEVNET_AUTO_VENV:-1}"; then
    return 0
  fi
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    echo "==> Using active Python virtualenv: ${VIRTUAL_ENV}"
    return 0
  fi
  local activate_path="${REPO_ROOT}/.venv/bin/activate"
  if [[ -f "${activate_path}" ]]; then
    # shellcheck disable=SC1090
    source "${activate_path}"
    echo "==> Activated Python virtualenv: ${VIRTUAL_ENV:-${REPO_ROOT}/.venv}"
    return 0
  fi
  echo "ERROR: Python virtualenv not active and ${activate_path} was not found." >&2
  echo "Run: cd ${REPO_ROOT} && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 2
}

require_email_for_tier_poh() {
  if _bool_true "${WEALL_DEVNET_SUITE_RUN_TIER2:-0}" || _bool_true "${WEALL_DEVNET_SUITE_RUN_TIER3:-0}"; then
    if [[ -z "${WEALL_EMAIL:-}" ]]; then
      echo "ERROR: WEALL_DEVNET_SUITE_RUN_TIER2/3 requires WEALL_EMAIL so the suite proves Tier-1 bounded oracle elevation first." >&2
      echo "Example:" >&2
      echo "  WEALL_EMAIL=your-email@example.com WEALL_DEVNET_SUITE_RUN_TIER2=1 WEALL_DEVNET_SUITE_RUN_TIER3=1 bash scripts/devnet_controlled_readiness_suite.sh" >&2
      exit 2
    fi
  fi
  if _bool_true "${WEALL_DEVNET_SUITE_RUN_TIER3:-0}" && ! _bool_true "${WEALL_DEVNET_SUITE_RUN_TIER2:-0}"; then
    echo "ERROR: WEALL_DEVNET_SUITE_RUN_TIER3=1 requires WEALL_DEVNET_SUITE_RUN_TIER2=1." >&2
    exit 2
  fi
}

run_step() {
  local name="$1"
  shift
  echo ""
  echo "================================================================================"
  echo "==> SUITE STEP: ${name}"
  echo "================================================================================"
  "$@"
}

activate_repo_venv
require_email_for_tier_poh

SUITE_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "==> Controlled-devnet readiness suite started at ${SUITE_STARTED_AT}"
echo "==> Repo: ${REPO_ROOT}"
echo "==> Tier2 in onboarding: ${WEALL_DEVNET_SUITE_RUN_TIER2:-0}"
echo "==> Tier3 in onboarding: ${WEALL_DEVNET_SUITE_RUN_TIER3:-0}"

if _bool_true "${WEALL_DEVNET_SUITE_RUN_PERMISSION:-1}"; then
  run_step "permission-gating direct API probe" env WEALL_DEVNET_LIVE_RESET=1 bash scripts/devnet_run_permission_probe_live.sh
else
  echo "==> Skipped permission probe"
fi

if _bool_true "${WEALL_DEVNET_SUITE_RUN_ONBOARDING:-1}"; then
  run_step "full onboarding + node2 convergence smoke" \
    env \
      WEALL_DEVNET_RESET_ON_AUTOSTART=1 \
      WEALL_DEVNET_RUN_TIER2="${WEALL_DEVNET_SUITE_RUN_TIER2:-0}" \
      WEALL_DEVNET_RUN_TIER3="${WEALL_DEVNET_SUITE_RUN_TIER3:-0}" \
      bash scripts/devnet_full_onboarding_e2e.sh
else
  echo "==> Skipped onboarding smoke"
fi

if _bool_true "${WEALL_DEVNET_SUITE_RUN_CROSS_NODE:-1}"; then
  run_step "two-node cross-node convergence live probe" env WEALL_DEVNET_LIVE_RESET=1 bash scripts/devnet_run_cross_node_convergence_live.sh
else
  echo "==> Skipped cross-node convergence probe"
fi

if _bool_true "${WEALL_DEVNET_SUITE_RUN_RESTART:-1}"; then
  run_step "restart/catch-up live probe" env WEALL_DEVNET_LIVE_RESET=1 bash scripts/devnet_restart_catchup_live.sh
else
  echo "==> Skipped restart/catch-up probe"
fi

SUITE_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""
echo "==> OK: controlled-devnet readiness suite passed"
echo "started_at=${SUITE_STARTED_AT}"
echo "finished_at=${SUITE_FINISHED_AT}"
