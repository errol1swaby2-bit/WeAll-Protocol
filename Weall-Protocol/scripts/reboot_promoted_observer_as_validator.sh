#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACCOUNT="${WEALL_VALIDATOR_ACCOUNT:-${WEALL_BOUND_ACCOUNT:-}}"

fail() { echo "ERROR: $*" >&2; exit 2; }
[ -n "${ACCOUNT}" ] || fail "WEALL_VALIDATOR_ACCOUNT or WEALL_BOUND_ACCOUNT is required"

# Observer artifacts are valid for onboarding only.  Refuse to carry them into
# validator mode by clearing them before setting the production validator env.
unset WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE || true
unset WEALL_OBSERVER_PREFLIGHT_ALREADY_PASSED || true
unset WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API || true
unset WEALL_EXTERNAL_OBSERVER_BOOT || true
unset WEALL_EXTERNAL_OBSERVER_WORK_DIR || true

export WEALL_MODE="prod"
export WEALL_NODE_LIFECYCLE_STATE="production_service"
export WEALL_SERVICE_ROLES="${WEALL_SERVICE_ROLES:-node_operator,validator}"
export WEALL_OBSERVER_MODE="0"
export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-1}"
export WEALL_BFT_ENABLED="1"
export WEALL_VALIDATOR_SIGNING_ENABLED="1"
export WEALL_BOUND_ACCOUNT="${WEALL_BOUND_ACCOUNT:-${ACCOUNT}}"
export WEALL_VALIDATOR_ACCOUNT="${WEALL_VALIDATOR_ACCOUNT:-${ACCOUNT}}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-1}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"
export WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"
export WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"

bash "${ROOT_DIR}/scripts/promoted_validator_preflight.sh"
bash "${ROOT_DIR}/scripts/prod_node_preflight.sh"

cat >&2 <<'MSG'
[weall] Promoted validator preflight passed. Booting with BFT and validator signing enabled.
[weall] Post-boot, run scripts/promoted_validator_live_gate.sh against this node's API.
MSG
exec "${ROOT_DIR}/scripts/run_node_prod.sh"
