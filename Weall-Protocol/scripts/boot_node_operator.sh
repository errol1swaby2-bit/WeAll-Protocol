#!/usr/bin/env sh
set -eu

# Explicit production service boot path for already-approved node operators.
# This path is intentionally strict: the chain must show Tier 2 + active
# NodeOperator authority + authorized node key before service authority is active.

export WEALL_MODE="${WEALL_MODE:-prod}"
export WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-production_service}"
export WEALL_SERVICE_ROLES="${WEALL_SERVICE_ROLES:-node_operator}"
export WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-0}"
export WEALL_VALIDATOR_SIGNING_ENABLED="${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"
export WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"
export WEALL_HELPER_MODE_ENABLED="${WEALL_HELPER_MODE_ENABLED:-0}"

if [ "${WEALL_MODE}" != "prod" ]; then echo "ERROR: boot_node_operator.sh requires WEALL_MODE=prod" >&2; exit 2; fi
if [ "${WEALL_NODE_LIFECYCLE_STATE}" != "production_service" ]; then echo "ERROR: boot_node_operator.sh requires WEALL_NODE_LIFECYCLE_STATE=production_service" >&2; exit 2; fi
case ",${WEALL_SERVICE_ROLES}," in *,node_operator,*) ;; *) echo "ERROR: production node operator boot requires WEALL_SERVICE_ROLES to include node_operator" >&2; exit 2 ;; esac
if [ -z "${WEALL_BOUND_ACCOUNT:-${WEALL_VALIDATOR_ACCOUNT:-}}" ]; then echo "ERROR: set WEALL_BOUND_ACCOUNT to the activated node operator account" >&2; exit 2; fi
if [ -z "${WEALL_NODE_PRIVKEY_FILE:-${WEALL_NODE_PRIVKEY:-}}" ]; then echo "ERROR: set WEALL_NODE_PRIVKEY_FILE to the separate node key file" >&2; exit 2; fi
if [ -z "${WEALL_NODE_PUBKEY_FILE:-${WEALL_NODE_PUBKEY:-}}" ]; then echo "ERROR: set WEALL_NODE_PUBKEY_FILE or WEALL_NODE_PUBKEY to the registered node public key" >&2; exit 2; fi

cat >&2 <<'MSG'
[weall] Starting production node operator service boot.
[weall] This mode is fail-closed: Tier 2, active NodeOperator role, and registered node key are required.
MSG

exec "$(dirname "$0")/run_node_prod.sh"
