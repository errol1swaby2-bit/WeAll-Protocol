#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

# Safe first-run production boot path.
# This starts a read/onboarding/PoH communication node. It can help a user
# create an account, complete verification, register a node key, and submit
# node-operator enrollment transactions. It does not grant service authority.

export WEALL_MODE="${WEALL_MODE:-prod}"
export WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-observer_onboarding}"
export WEALL_SERVICE_ROLES="${WEALL_SERVICE_ROLES:-}"
export WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"
export WEALL_VALIDATOR_SIGNING_ENABLED="${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"
export WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"
export WEALL_HELPER_MODE_ENABLED="${WEALL_HELPER_MODE_ENABLED:-0}"
export WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-0}"
export WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"

case "${WEALL_NODE_LIFECYCLE_STATE}" in
  observer_onboarding|bootstrap_registration) ;;
  *) echo "ERROR: boot_onboarding_node.sh only supports observer_onboarding/bootstrap_registration" >&2; exit 2 ;;
esac

if [ "${WEALL_MODE}" != "prod" ]; then
  echo "ERROR: boot_onboarding_node.sh is a production-chain onboarding wrapper and requires WEALL_MODE=prod" >&2
  exit 2
fi

if [ "${WEALL_OBSERVER_PREFLIGHT_ALREADY_PASSED:-0}" != "1" ]; then
  if [ -z "${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}" ]; then
    echo "ERROR: set WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE or run scripts/external_observer_onboarding_smoke.sh before boot_onboarding_node.sh" >&2
    exit 2
  fi
  WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API="${WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API:-0}" \
    bash "${SCRIPT_DIR}/external_observer_onboarding_smoke.sh" "${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE}"
  export WEALL_OBSERVER_PREFLIGHT_ALREADY_PASSED="1"
fi

cat >&2 <<'MSG'
[weall] Starting observer/onboarding node.
[weall] Allowed: read/sync state, serve local onboarding UI, submit account/PoH/enrollment txs.
[weall] Blocked: validator signing, block proposal, helper authority, storage/service rewards.
MSG

exec "${SCRIPT_DIR}/boot_weall_node.sh"
