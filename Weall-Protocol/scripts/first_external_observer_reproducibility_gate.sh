#!/usr/bin/env bash
set -euo pipefail

# Combined first-external-observer reproducibility gate.
#
# This script is intentionally split into local preconditions and optional remote
# live proof. It is safe for reviewers to run locally without a second machine,
# but it refuses to claim first external observer readiness unless the remote
# two-machine and signed onboarding gates are explicitly run.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
RUN_REMOTE_PREFLIGHT="${WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT:-0}"
RUN_SIGNED_ONBOARDING="${WEALL_RUN_SIGNED_OBSERVER_ONBOARDING:-0}"

truthy() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

fail() {
  echo "[first-external-observer-gate:FAIL] $*" >&2
  exit 1
}

run_local_preconditions() {
  echo "[first-external-observer-gate] local observer readiness"
  bash scripts/local_observer_readiness_gate.sh

  echo "[first-external-observer-gate] observer authority lock"
  bash scripts/external_observer_authority_lock_gate.sh
}

run_remote_preflight() {
  [ -n "$BUNDLE_PATH" ] || fail "remote preflight requires a public observer bundle path"
  [ -n "${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}" ] || fail "remote preflight requires WEALL_GENESIS_API_BASE or WEALL_API_BASE"
  echo "[first-external-observer-gate] two-machine observer preflight"
  bash scripts/rehearse_external_observer_two_machine.sh "$BUNDLE_PATH"
}

run_signed_onboarding() {
  [ -n "$BUNDLE_PATH" ] || fail "signed observer onboarding requires a public observer bundle path"
  [ -n "${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}" ] || fail "signed observer onboarding requires WEALL_GENESIS_API_BASE or WEALL_API_BASE"
  echo "[first-external-observer-gate] signed observer onboarding live gate"
  bash scripts/rehearse_external_observer_signed_onboarding.sh "$BUNDLE_PATH"
}

LOCAL_PRECONDITIONS_STATUS="not_run"
REMOTE_PREFLIGHT_STATUS="skipped"
SIGNED_ONBOARDING_STATUS="skipped"
FIRST_TRUSTED_EXTERNAL_OBSERVER_READY="no"

run_local_preconditions
LOCAL_PRECONDITIONS_STATUS="passed"

if truthy "$RUN_REMOTE_PREFLIGHT"; then
  run_remote_preflight
  REMOTE_PREFLIGHT_STATUS="passed"
else
  cat <<'MSG'
[first-external-observer-gate] remote preflight skipped
Set WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1, WEALL_GENESIS_API_BASE, and pass the public observer bundle to prove remote genesis compatibility.
MSG
fi

if truthy "$RUN_SIGNED_ONBOARDING"; then
  run_signed_onboarding
  SIGNED_ONBOARDING_STATUS="passed"
else
  cat <<'MSG'
[first-external-observer-gate] signed onboarding skipped
Set WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1, WEALL_GENESIS_API_BASE, and pass the public observer bundle to prove signed external observer onboarding.
MSG
fi

if [ "$REMOTE_PREFLIGHT_STATUS" = "passed" ] && [ "$SIGNED_ONBOARDING_STATUS" = "passed" ]; then
  FIRST_TRUSTED_EXTERNAL_OBSERVER_READY="yes"
fi

cat <<MSG
OK: first external observer reproducibility gate completed for the requested scope

Scope summary:
- local_preconditions: ${LOCAL_PRECONDITIONS_STATUS}
- remote_preflight: ${REMOTE_PREFLIGHT_STATUS}
- signed_observer_onboarding: ${SIGNED_ONBOARDING_STATUS}
- first_trusted_external_observer_ready: ${FIRST_TRUSTED_EXTERNAL_OBSERVER_READY}

Truth boundary:
- Local preconditions passing means the observer bundle and environment are safe to prepare.
- Remote preflight passing means the observer can verify remote genesis compatibility.
- Signed onboarding passing is required before claiming first trusted external observer readiness.
- first_trusted_external_observer_ready=yes is emitted only when both remote_preflight and signed_observer_onboarding pass in the same requested gate run.
- None of these gates prove public multi-validator BFT, live economics, mainnet readiness, or production-grade private messaging.
MSG
