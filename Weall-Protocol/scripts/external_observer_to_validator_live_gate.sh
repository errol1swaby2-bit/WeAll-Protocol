#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
SKIP_OBSERVER_GATE="${WEALL_SKIP_EXTERNAL_OBSERVER_LIVE_GATE:-0}"
RUN_REBOOT="${WEALL_RUN_PROMOTED_VALIDATOR_REBOOT:-0}"

fail() { echo "ERROR: $*" >&2; exit 1; }
[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <public-observer-bundle.json>"

if [ "${SKIP_OBSERVER_GATE}" != "1" ]; then
  bash "${ROOT_DIR}/scripts/external_observer_live_gate.sh" "${BUNDLE_PATH}"
else
  echo "[observer-to-validator] skipping observer live gate because WEALL_SKIP_EXTERNAL_OBSERVER_LIVE_GATE=1"
fi

cat <<'MSG'
[observer-to-validator] Observer onboarding gate complete or intentionally skipped.
[observer-to-validator] WeAll is a pre-public-testnet protocol implementation under active hardening.
[observer-to-validator] The next authority transitions must already be committed by real protocol authority before reboot:
  - native PoH reaches required Tier 2 / Live Verified Human state, or an auditable bootstrap Tier2 grant exists
  - ROLE_NODE_OPERATOR_ENROLL is committed
  - ROLE_NODE_OPERATOR_ACTIVATE is committed by system/governance authority
  - NODE_OPERATOR_VALIDATOR_OPT_IN is committed by the account; readiness/reputation blockers must be readable, not signature failures
  - VALIDATOR_READINESS_VERIFY is committed by system authority with a live readiness receipt
  - ROLE_VALIDATOR_ACTIVATE and validator-set update are committed by system/governance authority
  - full BFT-active signing is expected only when the active validator count satisfies BFT_MIN_VALIDATORS; lower counts are bootstrap/readiness only
MSG

bash "${ROOT_DIR}/scripts/promoted_validator_preflight.sh"

if [ "${RUN_REBOOT}" = "1" ]; then
  exec "${ROOT_DIR}/scripts/reboot_promoted_observer_as_validator.sh"
fi

cat <<'MSG'
OK: external observer to validator preflight gate passed.
Set WEALL_RUN_PROMOTED_VALIDATOR_REBOOT=1 to exec the fail-closed validator reboot script from this same environment.
After the node boots, run scripts/promoted_validator_live_gate.sh against the local validator API.
A genesis+one-promoted-validator run is a bootstrap/readiness proof, not a full HotStuff/BFT finality proof, unless the active validator count satisfies BFT_MIN_VALIDATORS.
MSG
