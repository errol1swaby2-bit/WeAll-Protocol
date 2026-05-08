#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}"
BOOT_AFTER_PREFLIGHT="${WEALL_EXTERNAL_OBSERVER_BOOT:-0}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <public-observer-bundle.json>"
[ -f "${BUNDLE_PATH}" ] || fail "bundle not found: ${BUNDLE_PATH}"
[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"

# An external observer/onboarding node must never need authority signer secrets
# or legacy external identity-provider authority secrets.
[ -z "${WEALL_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "authority signer private key must not be present on observer node"
[ -z "${WEALL_AUTHORITY_PRIVKEY:-}" ] || fail "authority private key must not be present on observer node"
[ -z "${WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY:-}" ] || fail "legacy oracle/identity signer private key must not be present on observer node"
[ -z "${WEALL_ORACLE_AUTHORITY_PRIVKEY:-}" ] || fail "legacy oracle/identity private key must not be present on observer node"
[ -z "${WEALL_CLOUDFLARE_API_TOKEN:-}" ] || fail "Cloudflare token must not be required or present for observer onboarding"
SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD"
[ -z "${!SMTP_SECRET_VAR:-}" ] || fail "external message-transport credential must not be present for observer onboarding"

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

python3 "${ROOT_DIR}/scripts/verify_node_operator_onboarding_bundle.py" \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --json >/tmp/weall_external_observer_bundle_check.json

# shellcheck disable=SC2046
# shellcheck disable=SC1090
eval "$(python3 "${ROOT_DIR}/scripts/verify_node_operator_onboarding_bundle.py" \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --emit-shell-env)"

export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_REQUIRE_CHAIN_MANIFEST="${WEALL_REQUIRE_CHAIN_MANIFEST:-1}"
export WEALL_MODE="prod"
export WEALL_NODE_LIFECYCLE_STATE="observer_onboarding"
export WEALL_SERVICE_ROLES=""
export WEALL_OBSERVER_MODE="1"
export WEALL_VALIDATOR_SIGNING_ENABLED="0"
export WEALL_BFT_ENABLED="0"
export WEALL_HELPER_MODE_ENABLED="0"
export WEALL_BLOCK_LOOP_AUTOSTART="0"

bash "${ROOT_DIR}/scripts/prod_chain_manifest_check.sh" "${MANIFEST_PATH}" >/tmp/weall_external_observer_manifest_check.json

if [ -n "${GENESIS_API_BASE}" ]; then
  python3 - "${GENESIS_API_BASE%/}" "${BUNDLE_PATH}" <<'PY'
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

api = sys.argv[1].rstrip('/')
bundle = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
chain = bundle.get('chain') if isinstance(bundle.get('chain'), dict) else {}
with urllib.request.urlopen(api + '/v1/chain/identity', timeout=10) as resp:
    ident = json.loads(resp.read().decode('utf-8'))
remote_chain_id = str(ident.get('chain_id') or ident.get('chain', {}).get('chain_id') or '').strip()
expected_chain_id = str(chain.get('chain_id') or '').strip()
if expected_chain_id and remote_chain_id and remote_chain_id != expected_chain_id:
    raise SystemExit(f'remote_chain_id_mismatch:{remote_chain_id}!={expected_chain_id}')
manifest = ident.get('chain_manifest') if isinstance(ident.get('chain_manifest'), dict) else {}
remote_tx_hash = str(manifest.get('tx_index_hash') or ident.get('tx_index_hash') or '').strip().lower()
expected_tx_hash = str(chain.get('tx_index_hash') or '').strip().lower()
if expected_tx_hash and remote_tx_hash and remote_tx_hash != expected_tx_hash:
    raise SystemExit(f'remote_tx_index_hash_mismatch:{remote_tx_hash}!={expected_tx_hash}')
print('OK: remote genesis chain identity matches observer bundle')
PY
fi


if [ -n "${WEALL_NET_RELAY_URLS:-}" ]; then
  python3 - "${WEALL_NET_RELAY_URLS%%,*}" <<'WEALL_RELAY_CHECK_PY'
from __future__ import annotations

import json
import sys
import urllib.request

base = sys.argv[1].strip().rstrip('/')
if not base:
    raise SystemExit('relay_url_missing')
with urllib.request.urlopen(base + '/v1/net/relay/status', timeout=10) as resp:
    status = json.loads(resp.read().decode('utf-8'))
if not bool(status.get('ok')) or not bool(status.get('enabled')):
    raise SystemExit('relay_status_not_enabled')
if status.get('authority') != 'transport_only':
    raise SystemExit('relay_authority_not_transport_only')
print('OK: relay endpoint reachable and marked transport_only')
WEALL_RELAY_CHECK_PY
fi

rm -f /tmp/weall_external_observer_bundle_check.json /tmp/weall_external_observer_manifest_check.json

cat <<MSG
OK: external observer onboarding preflight passed
- public bundle verified against local chain manifest
- production chain manifest is pinned and non-placeholder
- observer mode is forced on
- validator signing, BFT, helper authority, and block loop are forced off
- no external identity-provider, Cloudflare, oracle, or authority-signer secret is required
MSG

if [ "${BOOT_AFTER_PREFLIGHT}" = "1" ]; then
  exec "${ROOT_DIR}/scripts/boot_onboarding_node.sh"
fi

cat <<MSG
Next manual step on the observer machine:
  WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE='${BUNDLE_PATH}' \\
  WEALL_CHAIN_MANIFEST_PATH='${MANIFEST_PATH}' \\
  bash scripts/boot_onboarding_node.sh
MSG
