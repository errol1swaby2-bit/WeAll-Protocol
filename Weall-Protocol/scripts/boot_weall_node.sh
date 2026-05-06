#!/usr/bin/env sh
set -eu

# Production-oriented default boot wrapper.  This is the path for operators who
# want to join the canonical WeAll chain, not create a local/demo chain.

export WEALL_MODE="${WEALL_MODE:-prod}"
export WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-observer_onboarding}"
export WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"
export WEALL_VALIDATOR_SIGNING_ENABLED="${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"
export WEALL_CHAIN_MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-./configs/chains/weall-genesis.json}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-1}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"
export WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"
export WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"

if [ "${WEALL_MODE}" != "prod" ]; then
  echo "ERROR: boot_weall_node.sh is production-oriented and requires WEALL_MODE=prod" >&2
  exit 2
fi

if [ ! -f "${WEALL_CHAIN_MANIFEST_PATH}" ]; then
  echo "ERROR: chain manifest not found: ${WEALL_CHAIN_MANIFEST_PATH}" >&2
  exit 2
fi

if [ -z "${WEALL_CHAIN_ID:-}" ]; then
  WEALL_CHAIN_ID="$(python3 - "${WEALL_CHAIN_MANIFEST_PATH}" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    obj = json.load(f)
print(str(obj.get("chain_id") or "").strip())
PY
)"
  export WEALL_CHAIN_ID
fi

if [ -z "${WEALL_CHAIN_ID:-}" ]; then
  echo "ERROR: chain_id missing from ${WEALL_CHAIN_MANIFEST_PATH}" >&2
  exit 2
fi

exec "$(dirname "$0")/run_node.sh"
