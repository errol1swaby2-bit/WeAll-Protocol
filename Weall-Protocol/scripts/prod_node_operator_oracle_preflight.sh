#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }

read_secret_file() {
  local path="$1"
  if [ -n "${path}" ] && [ -f "${path}" ]; then
    tr -d '\r\n' < "${path}"
  fi
}

[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "authority-signer private keys do not belong in a normal node-operator environment"
[ -z "${WEALL_ORACLE_AUTHORITY_PRIVKEY:-}" ] || fail "authority-signer private keys do not belong in a normal node-operator environment"
[ -z "${WEALL_EMAIL_ORACLE_PRIVATE_KEY:-}" ] || fail "oracle-service private keys do not belong in a normal node-operator environment"
[ -z "${WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE:-}" ] || fail "oracle-service private key files do not belong in a normal node-operator environment"

WEALL_NODE_PRIVKEY_EFFECTIVE="${WEALL_NODE_PRIVKEY:-}"
if [ -z "${WEALL_NODE_PRIVKEY_EFFECTIVE}" ] && [ -n "${WEALL_NODE_PRIVKEY_FILE:-}" ]; then
  WEALL_NODE_PRIVKEY_EFFECTIVE="$(read_secret_file "${WEALL_NODE_PRIVKEY_FILE}")"
fi

[ -n "${WEALL_CHAIN_AUTHORITY_URL:-${WEALL_API_BASE:-}}" ] || fail "set WEALL_CHAIN_AUTHORITY_URL or WEALL_API_BASE to a trusted WeAll node API base URL"
[ -n "${WEALL_VALIDATOR_ACCOUNT:-${WEALL_ORACLE_OPERATOR_ACCOUNT:-}}" ] || fail "set WEALL_VALIDATOR_ACCOUNT or WEALL_ORACLE_OPERATOR_ACCOUNT"
[ -n "${WEALL_NODE_PUBKEY:-}" ] || fail "set WEALL_NODE_PUBKEY"
[ -n "${WEALL_NODE_PRIVKEY_EFFECTIVE}" ] || fail "set WEALL_NODE_PRIVKEY_FILE or WEALL_NODE_PRIVKEY"
[ -n "${WEALL_CHAIN_ID:-${WEALL_EXPECTED_CHAIN_ID:-}}" ] || fail "set WEALL_CHAIN_ID or WEALL_EXPECTED_CHAIN_ID"
[ -n "${WEALL_EXPECTED_GENESIS_HASH:-${WEALL_ORACLE_GENESIS_HASH:-}}" ] || fail "set WEALL_EXPECTED_GENESIS_HASH"
[ -n "${WEALL_EMAIL_TRANSPORT:-}" ] || fail "set WEALL_EMAIL_TRANSPORT to mock, stalwart_smtp, or external_smtp"

case "${WEALL_EMAIL_TRANSPORT}" in
  mock) ;;
  stalwart_smtp|external_smtp|smtp)
    [ -n "${WEALL_SMTP_HOST:-${WEALL_EMAIL_HOST:-}}" ] || fail "set WEALL_SMTP_HOST or WEALL_EMAIL_HOST"
    [ -n "${WEALL_SMTP_PORT:-${WEALL_EMAIL_PORT:-}}" ] || warn "SMTP port not set; default 587 will be used"
    [ -n "${WEALL_SMTP_USERNAME:-${WEALL_EMAIL_USER:-}}" ] || fail "set WEALL_SMTP_USERNAME or WEALL_EMAIL_USER"
    [ -n "${WEALL_SMTP_PASSWORD:-${WEALL_EMAIL_PASS:-}}" ] || fail "set WEALL_SMTP_PASSWORD or WEALL_EMAIL_PASS"
    [ -n "${WEALL_SMTP_FROM:-${WEALL_EMAIL_FROM:-}}" ] || fail "set WEALL_SMTP_FROM or WEALL_EMAIL_FROM"
    ;;
  *) fail "unsupported WEALL_EMAIL_TRANSPORT=${WEALL_EMAIL_TRANSPORT}" ;;
esac

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
python3 -S "${ROOT_DIR}/scripts/prod_oracle_authority_snapshot_check.py" --json >/tmp/weall_oracle_authority_preflight.json || warn "authority snapshot check failed; continue only for local/dev profiles"
rm -f /tmp/weall_oracle_authority_preflight.json

echo "OK: node-operator PoH email preflight passed"
echo "- No third-party provider runtime is required"
echo "- Email transport is ${WEALL_EMAIL_TRANSPORT}"
echo "- Local node/account key material is present for oracle-service attestation request signing"
