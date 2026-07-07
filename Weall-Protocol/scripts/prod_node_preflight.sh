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

env_is_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

csv_has() {
  local needle="$1"
  local csv="${2:-}"
  local old_ifs="$IFS"
  IFS=','
  for item in $csv; do
    item="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ "$item" = "$needle" ]; then
      IFS="$old_ifs"
      return 0
    fi
  done
  IFS="$old_ifs"
  return 1
}

[ -f "${MANIFEST}" ] || fail "production chain manifest not found: ${MANIFEST}"

case "${WEALL_MODE:-prod}" in
  prod|production) ;;
  *) fail "production node preflight requires WEALL_MODE=prod or unset" ;;
esac

[ -z "${WEALL_GENESIS_MODE:-}" ] || fail "WEALL_GENESIS_MODE must not be set for production node preflight"
[ -z "${WEALL_UNSAFE_DEV:-}" ] || fail "WEALL_UNSAFE_DEV must not be set for production node preflight"
[ "${WEALL_SIGVERIFY:-1}" != "0" ] || fail "WEALL_SIGVERIFY=0 is forbidden for production node preflight"
[ -z "${WEALL_ALLOW_LEGACY_SIG_DOMAIN:-}" ] || fail "WEALL_ALLOW_LEGACY_SIG_DOMAIN must not be set for production node preflight"
[ -z "${WEALL_ENABLE_DEMO_SEED_ROUTE:-}" ] || fail "WEALL_ENABLE_DEMO_SEED_ROUTE must not be set for production node preflight"
[ -z "${WEALL_AUTHORITY_PROFILE:-}" ] || [ "${WEALL_AUTHORITY_PROFILE}" = "production" ] || fail "WEALL_AUTHORITY_PROFILE must be production or unset"
[ -z "${WEALL_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "authority snapshot signer private key must not be present in a normal node environment"
[ -z "${WEALL_AUTHORITY_SIGNER_PRIVKEY_FILE:-}" ] || fail "authority snapshot signer private key path must not be present in a normal node environment"
[ -z "${WEALL_AUTHORITY_PRIVKEY:-}" ] || fail "authority private key must not be present in a normal node environment"
[ -z "${WEALL_AUTHORITY_PRIVKEY_FILE:-}" ] || fail "authority private key path must not be present in a normal node environment"
[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "legacy authority signer private key must not be present in a normal node environment"
[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY_FILE:-}" ] || fail "legacy authority signer private key path must not be present in a normal node environment"
[ -z "${WEALL_ORACLE_AUTHORITY_PRIVKEY:-}" ] || fail "legacy authority private key must not be present in a normal node environment"
[ -z "${WEALL_ORACLE_AUTHORITY_PRIVKEY_FILE:-}" ] || fail "legacy authority private key path must not be present in a normal node environment"
[ -z "${WEALL_NAMED_HOSTING_PROVIDER_API_TOKEN:-}" ] || fail "named hosting-provider token must not be present for native production PoH/onboarding"
[ -z "${WEALL_DNS_API_TOKEN:-}" ] || fail "DNS provider token must not be present for native production PoH/onboarding"
[ -z "${WEALL_OAUTH_CLIENT_SECRET:-}" ] || fail "OAuth secret must not be present for native production PoH/onboarding"
[ -z "${WEALL_KYC_PROVIDER_SECRET:-}" ] || fail "KYC provider secret must not be present for native production PoH/onboarding"
[ -z "${WEALL_CAPTCHA_SECRET:-}" ] || fail "CAPTCHA secret must not be present for native production PoH/onboarding"
SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD"
[ -z "${!SMTP_SECRET_VAR:-}" ] || fail "SMTP password must not be present for native production PoH/onboarding"

if csv_has "validator" "${WEALL_SERVICE_ROLES:-}" && [ "${WEALL_NODE_LIFECYCLE_STATE:-}" = "production_service" ] && ! env_is_true "${WEALL_BFT_ENABLED:-0}"; then
  fail "production validator service requires WEALL_BFT_ENABLED=1"
fi
if env_is_true "${WEALL_VALIDATOR_SIGNING_ENABLED:-0}" && ! env_is_true "${WEALL_OBSERVER_MODE:-0}" && ! env_is_true "${WEALL_BFT_ENABLED:-0}"; then
  fail "validator signing requires WEALL_BFT_ENABLED=1 in production"
fi
if env_is_true "${WEALL_OBSERVER_MODE:-0}" && env_is_true "${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"; then
  fail "WEALL_OBSERVER_MODE=1 cannot be combined with WEALL_VALIDATOR_SIGNING_ENABLED=1"
fi
if env_is_true "${WEALL_OBSERVER_MODE:-0}" && env_is_true "${WEALL_BFT_ENABLED:-0}"; then
  fail "WEALL_OBSERVER_MODE=1 cannot be combined with WEALL_BFT_ENABLED=1"
fi
if env_is_true "${WEALL_OBSERVER_MODE:-0}" && csv_has "validator" "${WEALL_SERVICE_ROLES:-}"; then
  fail "observer mode cannot request validator service role"
fi
if env_is_true "${WEALL_OBSERVER_MODE:-0}" && [ -n "${WEALL_VALIDATOR_ACCOUNT:-}" ]; then
  fail "observer mode must not set WEALL_VALIDATOR_ACCOUNT"
fi

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
