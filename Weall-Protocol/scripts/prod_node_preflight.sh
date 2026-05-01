#!/usr/bin/env bash
set -euo pipefail

# Operator-side production preflight. This proves that the local node is pinned
# to the canonical chain manifest without requiring any external identity-provider service.

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
[ -z "${WEALL_AUTHORITY_PROFILE:-}" ] || [ "${WEALL_AUTHORITY_PROFILE}" = "production" ] || fail "WEALL_AUTHORITY_PROFILE must be production or unset"
[ -z "${WEALL_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "authority snapshot signer private key must not be present in a normal node environment"
[ -z "${WEALL_AUTHORITY_PRIVKEY:-}" ] || fail "authority private key must not be present in a normal node environment"
[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "legacy authority signer private key must not be present in a normal node environment"
[ -z "${WEALL_ORACLE_AUTHORITY_PRIVKEY:-}" ] || fail "legacy authority private key must not be present in a normal node environment"

export WEALL_MODE="prod"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-1}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"
export WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"
export WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR="${WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR:-1}"

bash "${ROOT_DIR}/scripts/prod_chain_manifest_check.sh" "${MANIFEST}" >/tmp/weall_prod_chain_manifest_preflight.json

rm -f /tmp/weall_prod_chain_manifest_preflight.json
cat <<MSG
OK: production node preflight passed
- production chain manifest is pinned
- demo seed mode is not enabled
- external identity-provider secrets are absent from the node environment
MSG
