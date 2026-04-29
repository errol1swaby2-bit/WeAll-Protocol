#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE="${WEALL_API_BASE:-http://127.0.0.1:8000}"
AUTHORITY_URL="${WEALL_CHAIN_AUTHORITY_URL:-${API_BASE}}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

read_secret_file() {
  local path="$1"
  if [ -n "${path}" ] && [ -f "${path}" ]; then
    tr -d '\r\n' < "${path}"
  fi
}

read_effective() {
  local var_name="$1"
  local file_var_name="${var_name}_FILE"
  local value="${!var_name:-}"
  local file_value="${!file_var_name:-}"
  if [ -n "${value}" ]; then
    printf '%s' "${value}"
  elif [ -n "${file_value}" ]; then
    read_secret_file "${file_value}"
  fi
}

# The authority signer is separate from the PoH email oracle service. It must not need email-sending credentials or oracle signing keys.

AUTHORITY_ACCOUNT="$(read_effective WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT)"
AUTHORITY_PUBKEY="$(read_effective WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY)"
AUTHORITY_PRIVKEY="$(read_effective WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY)"
TRUSTED_PUBKEYS="${WEALL_ORACLE_AUTHORITY_PUBKEYS:-${WEALL_TRUSTED_AUTHORITY_PUBKEYS:-}}"

[ -n "${AUTHORITY_ACCOUNT}" ] || fail "set WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT or WEALL_ORACLE_AUTHORITY_SIGNER_ACCOUNT_FILE"
[ -n "${AUTHORITY_PUBKEY}" ] || fail "set WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY or WEALL_ORACLE_AUTHORITY_SIGNER_PUBKEY_FILE"
[ -n "${AUTHORITY_PRIVKEY}" ] || fail "set WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY or WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY_FILE"
[ -n "${TRUSTED_PUBKEYS}" ] || fail "set WEALL_ORACLE_AUTHORITY_PUBKEYS or WEALL_TRUSTED_AUTHORITY_PUBKEYS"

case ",${TRUSTED_PUBKEYS}," in
  *",${AUTHORITY_PUBKEY},"*) ;;
  *) fail "authority signer pubkey is not listed in WEALL_ORACLE_AUTHORITY_PUBKEYS/WEALL_TRUSTED_AUTHORITY_PUBKEYS" ;;
esac

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
python3 "${ROOT_DIR}/scripts/prod_oracle_authority_snapshot_check.py" \
  --authority-url "${AUTHORITY_URL}" \
  --trusted-pubkeys "${TRUSTED_PUBKEYS}" \
  --expected-chain-id "${WEALL_EXPECTED_CHAIN_ID:-${WEALL_CHAIN_ID:-}}" \
  --expected-genesis-hash "${WEALL_EXPECTED_GENESIS_HASH:-${WEALL_ORACLE_GENESIS_HASH:-}}" \
  --expected-tx-index-hash "${WEALL_EXPECTED_TX_INDEX_HASH:-}" \
  --json >/tmp/weall_oracle_authority_signer_preflight.json

rm -f /tmp/weall_oracle_authority_signer_preflight.json

echo "OK: oracle authority signer preflight passed"
echo "- Dedicated authority signer env is present"
echo "- Authority signer pubkey is listed in trusted pubkeys"
echo "- oracle-service secrets are absent"
echo "- Published authority snapshot verifies against the trusted pubkey set"
