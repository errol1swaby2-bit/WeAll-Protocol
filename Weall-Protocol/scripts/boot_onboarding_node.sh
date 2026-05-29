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
export WEALL_OBSERVER_EDGE_MODE="${WEALL_OBSERVER_EDGE_MODE:-1}"
if [ -z "${WEALL_TX_UPSTREAM_URLS:-}" ] && [ -n "${WEALL_GENESIS_API_BASE:-}" ]; then
  export WEALL_TX_UPSTREAM_URLS="${WEALL_GENESIS_API_BASE}"
fi
if [ -z "${WEALL_TX_UPSTREAM_URLS:-}" ] && [ -n "${WEALL_BOOTSTRAP_API_BASE:-}" ]; then
  export WEALL_TX_UPSTREAM_URLS="${WEALL_BOOTSTRAP_API_BASE}"
fi
export WEALL_TX_UPSTREAM_REQUIRED="${WEALL_TX_UPSTREAM_REQUIRED:-1}"
export WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT="${WEALL_TX_UPSTREAM_SYNC_ON_SUBMIT:-0}"
export WEALL_TX_UPSTREAM_VERIFY_IDENTITY="${WEALL_TX_UPSTREAM_VERIFY_IDENTITY:-1}"
export WEALL_TX_UPSTREAM_REQUIRE_MANIFEST="${WEALL_TX_UPSTREAM_REQUIRE_MANIFEST:-1}"
export WEALL_TX_OUTBOX_AUTODRAIN="${WEALL_TX_OUTBOX_AUTODRAIN:-1}"
export WEALL_TX_OUTBOX_DRAIN_INTERVAL_S="${WEALL_TX_OUTBOX_DRAIN_INTERVAL_S:-2}"
export WEALL_TX_OUTBOX_DRAIN_BATCH="${WEALL_TX_OUTBOX_DRAIN_BATCH:-25}"
export WEALL_OBSERVER_EDGE_OPERATOR_AUTH="${WEALL_OBSERVER_EDGE_OPERATOR_AUTH:-1}"
export WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN="${WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN:-1}"
export WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT="${WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT:-0}"
export WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL="${WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL:-1}"

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
[weall] Local observer edge: frontend txs are accepted locally, durably queued, and retried to configured upstreams.
[weall] Operator endpoints: set WEALL_OPERATOR_TOKEN before exposing observer edge/state-sync/media-provider control routes.
[weall] Blocked: validator signing, block proposal, helper authority, storage/service rewards.
MSG

exec bash "${SCRIPT_DIR}/boot_weall_node.sh"
