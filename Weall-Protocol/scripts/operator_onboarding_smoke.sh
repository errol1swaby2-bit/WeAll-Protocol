#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DOC="$ROOT_DIR/docs/NEW_NODE_OPERATOR_QUICKSTART.md"
ONBOARDING="$ROOT_DIR/scripts/boot_onboarding_node.sh"
SERVICE="$ROOT_DIR/scripts/boot_node_operator.sh"
ACCOUNT_PAGE="$ROOT_DIR/../web/src/pages/Account.tsx"
NODE_KEYS="$ROOT_DIR/../web/src/auth/nodeKeys.ts"

fail() {
  echo "[operator-onboarding-smoke] FAIL: $*" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || fail "missing file: $1"
}

require_text() {
  file="$1"
  text="$2"
  grep -F "$text" "$file" >/dev/null || fail "missing text in $file: $text"
}

reject_text() {
  file="$1"
  text="$2"
  if grep -F "$text" "$file" >/dev/null; then
    fail "forbidden text in $file: $text"
  fi
}

require_file "$DOC"
require_file "$ONBOARDING"
require_file "$SERVICE"
require_file "$ACCOUNT_PAGE"
require_file "$NODE_KEYS"

sh -n "$ONBOARDING"
sh -n "$SERVICE"

require_text "$DOC" "./scripts/boot_onboarding_node.sh"
require_text "$DOC" "./scripts/boot_node_operator.sh"
require_text "$DOC" "save your recovery key"
require_text "$DOC" "Verified Person / Tier 1"
require_text "$DOC" "Trusted Verified Person / Tier 2"
require_text "$DOC" "Generate and download node key"
require_text "$DOC" "WEALL_NODE_PRIVKEY_FILE"
require_text "$DOC" "After enrollment, the protocol checks eligibility"
reject_text "$DOC" "WEALL_NODE_PRIVKEY=<account_secret>"
reject_text "$DOC" "WEALL_NODE_PRIVKEY=<localSecretKey>"

require_text "$ONBOARDING" 'WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-observer_onboarding}"'
require_text "$ONBOARDING" 'WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"'
require_text "$ONBOARDING" 'WEALL_VALIDATOR_SIGNING_ENABLED="${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"'
require_text "$ONBOARDING" 'WEALL_HELPER_MODE_ENABLED="${WEALL_HELPER_MODE_ENABLED:-0}"'
require_text "$ONBOARDING" "Blocked: validator signing, block proposal, helper authority"

require_text "$SERVICE" 'WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-production_service}"'
require_text "$SERVICE" 'WEALL_SERVICE_ROLES="${WEALL_SERVICE_ROLES:-node_operator}"'
require_text "$SERVICE" "WEALL_BOUND_ACCOUNT"
require_text "$SERVICE" "WEALL_NODE_PRIVKEY_FILE"
require_text "$SERVICE" "fail-closed"

require_text "$ACCOUNT_PAGE" "Generate and download node key"
require_text "$ACCOUNT_PAGE" "Submit node operator enrollment"
require_text "$ACCOUNT_PAGE" "Checking eligibility"
require_text "$ACCOUNT_PAGE" "WEALL_NODE_PRIVKEY_FILE="
require_text "$ACCOUNT_PAGE" "Validator Responsibility"
require_text "$ACCOUNT_PAGE" "Opt into validator responsibility"
require_text "$ACCOUNT_PAGE" "Baseline Node Operator status does not grant validator authority"
require_text "$ACCOUNT_PAGE" "Blocked until readiness"
require_text "$ACCOUNT_PAGE" "Storage Responsibility"
require_text "$ACCOUNT_PAGE" "Opt into storage responsibility"
require_text "$ACCOUNT_PAGE" "Declared capacity is not allocation authority"
require_text "$DOC" "Baseline Node Operator status does not grant validator authority"
require_text "$DOC" "Validator readiness and reputation checks must pass before consensus authority"
require_text "$DOC" "Declared capacity is not proven capacity"
require_text "$DOC" "Proof pending is not allocation eligible"
require_text "$DOC" "proven_capacity_bytes"
reject_text "$ACCOUNT_PAGE" 'WEALL_NODE_PRIVKEY=${'
reject_text "$ACCOUNT_PAGE" "ROLE_NODE_OPERATOR_ACTIVATE"

require_text "$NODE_KEYS" "weall_node_key"
require_text "$NODE_KEYS" "not your WeAll account recovery key"

echo "[operator-onboarding-smoke] OK"
