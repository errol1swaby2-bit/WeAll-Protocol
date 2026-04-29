#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <node-operator-onboarding-bundle.json>"
[ -f "${BUNDLE_PATH}" ] || fail "bundle not found: ${BUNDLE_PATH}"
[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"

# A normal node operator must never need PoH email oracle service or authority signer secrets.
[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "authority snapshot signer private key must not be present in a normal node environment"
[ -z "${WEALL_ORACLE_AUTHORITY_PRIVKEY:-}" ] || fail "authority snapshot signer private key must not be present in a normal node environment"

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
python3 "${ROOT_DIR}/scripts/verify_node_operator_onboarding_bundle.py" \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --json >/tmp/weall_node_operator_bundle_check.json

# shellcheck disable=SC2046
# shellcheck disable=SC1090
eval "$(python3 "${ROOT_DIR}/scripts/verify_node_operator_onboarding_bundle.py" \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --emit-shell-env)"

export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-1}"

bash "${ROOT_DIR}/scripts/prod_chain_manifest_check.sh" "${MANIFEST_PATH}" >/tmp/weall_node_operator_manifest_check.json

if [ -n "${WEALL_ORACLE_OPERATOR_ACCOUNT:-${WEALL_VALIDATOR_ACCOUNT:-}}" ] && \
   [ -n "${WEALL_NODE_PUBKEY:-}" ] && \
   { [ -n "${WEALL_NODE_PRIVKEY:-}" ] || [ -n "${WEALL_NODE_PRIVKEY_FILE:-}" ]; }; then
  bash "${ROOT_DIR}/scripts/prod_node_operator_oracle_preflight.sh"
else
  echo "WARN: node key/account variables not fully configured; skipped live oracle authority/key preflight" >&2
fi

rm -f /tmp/weall_node_operator_bundle_check.json /tmp/weall_node_operator_manifest_check.json
cat <<MSG
OK: node-operator onboarding bundle preflight passed
- public bundle matches local chain manifest
- production chain/oracle anchors exported
- oracle-service and authority-signer secrets are absent
MSG
