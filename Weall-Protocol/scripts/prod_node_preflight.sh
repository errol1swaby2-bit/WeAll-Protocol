#!/usr/bin/env bash
set -euo pipefail

# Operator-side production preflight. This proves that the local node is pinned to the canonical chain
# manifest and, when oracle variables are present, that the normal node-operator
# oracle request contract can be signed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"

fail() {
  echo "ERROR: $*" >&2
  exit 2
}

[ -f "${MANIFEST}" ] || fail "production chain manifest not found: ${MANIFEST}"

case "${WEALL_MODE:-prod}" in
  prod|production) ;;
  *) fail "production node preflight requires WEALL_MODE=prod or unset" ;;
esac

[ -z "${WEALL_ENABLE_DEMO_SEED_ROUTE:-}" ] || fail "WEALL_ENABLE_DEMO_SEED_ROUTE must not be set for production node preflight"
[ -z "${WEALL_ORACLE_PROFILE:-}" ] || [ "${WEALL_ORACLE_PROFILE}" = "production" ] || fail "WEALL_ORACLE_PROFILE must be production or unset"
[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "authority snapshot signer private key must not be present in a normal node environment"

export WEALL_MODE="prod"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-1}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"
export WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"
export WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"

bash "${ROOT_DIR}/scripts/prod_chain_manifest_check.sh" "${MANIFEST}" >/tmp/weall_prod_chain_manifest_preflight.json

if [ -n "${WEALL_CHAIN_AUTHORITY_URL:-}" ] || [ -n "${WEALL_ORACLE_AUTHORITY_PUBKEYS:-${WEALL_TRUSTED_AUTHORITY_PUBKEYS:-}}" ]; then
  bash "${ROOT_DIR}/scripts/prod_poh_email_oracle_operator_preflight.sh"
else
  echo "WARN: oracle operator variables not fully configured; skipped node-operator oracle preflight" >&2
fi

rm -f /tmp/weall_prod_chain_manifest_preflight.json
cat <<MSG
OK: production node preflight passed
- production chain manifest is pinned
- demo seed mode is not enabled
- oracle-service secrets are absent from the node environment
MSG
