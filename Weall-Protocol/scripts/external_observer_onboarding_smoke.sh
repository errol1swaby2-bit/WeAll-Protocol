#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}"
BOOT_AFTER_PREFLIGHT="${WEALL_EXTERNAL_OBSERVER_BOOT:-0}"
REQUIRE_LIVE_API="${WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API:-0}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# Shared boundary rejects WEALL_AUTHORITY_SIGNER_PRIVKEY, WEALL_AUTHORITY_PRIVKEY,
# WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY, WEALL_ORACLE_AUTHORITY_PRIVKEY,
# WEALL_CLOUDFLARE_API_TOKEN, and SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD".
# It also rejects *_FILE variants and other external identity-provider secrets.
# shellcheck disable=SC1091
. "${ROOT_DIR}/scripts/lib/observer_secret_boundary.sh"
weall_check_observer_secret_boundary || exit $?

[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <public-observer-bundle.json>"
[ -f "${BUNDLE_PATH}" ] || fail "bundle not found: ${BUNDLE_PATH}"
[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"

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

GENESIS_API_BASE="${GENESIS_API_BASE:-${WEALL_GENESIS_API_BASE:-}}"

if [ "${REQUIRE_LIVE_API}" = "1" ]; then
  [ -n "${GENESIS_API_BASE}" ] || fail "WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API=1 requires WEALL_GENESIS_API_BASE or WEALL_API_BASE"
fi

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

if [ -n "${WEALL_NET_RELAY_URLS:-}" ]; then
  [ -n "${WEALL_NET_RELAY_RECIPIENT_PUBKEYS:-}" ] || fail "WEALL_NET_RELAY_RECIPIENT_PUBKEYS is required when relay URLs are configured for observer onboarding"
  python3 - "${WEALL_NET_RELAY_RECIPIENT_PUBKEYS}" <<'WEALL_RELAY_RECIPIENTS_PY'
from __future__ import annotations

import json
import re
import sys

try:
    mapping = json.loads(sys.argv[1])
except Exception as exc:
    raise SystemExit(f'relay_recipient_pubkeys_invalid_json:{exc}')
if not isinstance(mapping, dict) or not mapping:
    raise SystemExit('relay_recipient_pubkeys_empty')
for peer_id, pubkey in mapping.items():
    if not str(peer_id or '').strip():
        raise SystemExit('relay_recipient_pubkeys_empty_peer_id')
    if not re.fullmatch(r'[0-9a-fA-F]{64}', str(pubkey or '').strip()):
        raise SystemExit(f'relay_recipient_pubkey_invalid:{peer_id}')
print('OK: relay recipient pubkey map is present and valid')
WEALL_RELAY_RECIPIENTS_PY
fi

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

def fetch_json(path: str) -> dict:
    with urllib.request.urlopen(api + path, timeout=10) as resp:
        if resp.status >= 400:
            raise SystemExit(f'remote_endpoint_failed:{path}:{resp.status}')
        body = resp.read().decode('utf-8')
    try:
        obj = json.loads(body)
    except Exception as exc:
        raise SystemExit(f'remote_endpoint_non_json:{path}:{exc}')
    if not isinstance(obj, dict):
        raise SystemExit(f'remote_endpoint_not_object:{path}')
    return obj

for path in ('/v1/health', '/v1/status'):
    fetch_json(path)
try:
    fetch_json('/v1/ready')
except Exception:
    fetch_json('/v1/readyz')
ident = fetch_json('/v1/chain/identity')
remote_chain_id = str(ident.get('chain_id') or ident.get('chain', {}).get('chain_id') or '').strip()
expected_chain_id = str(chain.get('chain_id') or '').strip()
if expected_chain_id and remote_chain_id and remote_chain_id != expected_chain_id:
    raise SystemExit(f'remote_chain_id_mismatch:{remote_chain_id}!={expected_chain_id}')
manifest = ident.get('chain_manifest') if isinstance(ident.get('chain_manifest'), dict) else {}
remote_tx_hash = str(manifest.get('tx_index_hash') or ident.get('tx_index_hash') or '').strip().lower()
expected_tx_hash = str(chain.get('tx_index_hash') or '').strip().lower()
if expected_tx_hash and remote_tx_hash and remote_tx_hash != expected_tx_hash:
    raise SystemExit(f'remote_tx_index_hash_mismatch:{remote_tx_hash}!={expected_tx_hash}')
status = fetch_json('/v1/tx/status/external-observer-live-gate-nonexistent-tx')
if 'status' not in status:
    raise SystemExit('remote_tx_status_missing_status_field')
print('OK: remote genesis live API health/ready/status/identity/tx-status checks passed')
PY
fi


if [ -n "${WEALL_NET_RELAY_URLS:-}" ]; then
  IFS=',' read -r -a _relay_array <<< "${WEALL_NET_RELAY_URLS}"
  for relay in "${_relay_array[@]}"; do
    relay="${relay%/}"
    [ -n "${relay}" ] || continue
    python3 - "${relay}" <<'WEALL_RELAY_CHECK_PY'
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
limits = status.get('limits') if isinstance(status.get('limits'), dict) else {}
if limits.get('require_recipient_pubkey') is not True:
    raise SystemExit('relay_recipient_pubkey_not_required')
if limits.get('allow_unbound_recipient_fetch') is not False:
    raise SystemExit('relay_allows_unbound_recipient_fetch')
print(f'OK: relay endpoint reachable, transport_only, and recipient-bound: {base}')
WEALL_RELAY_CHECK_PY
  done
fi

rm -f /tmp/weall_external_observer_bundle_check.json /tmp/weall_external_observer_manifest_check.json

cat <<MSG
OK: external observer onboarding preflight passed
- public bundle verified against local chain manifest
- production chain manifest is pinned and non-placeholder
- observer mode is forced on
- validator signing, BFT, helper authority, and block loop are forced off
- relay recipient pubkey binding is required when relay URLs are configured
- no external identity-provider, Cloudflare, oracle, or authority-signer secret is required
MSG

if [ "${BOOT_AFTER_PREFLIGHT}" = "1" ]; then
  export WEALL_OBSERVER_PREFLIGHT_ALREADY_PASSED="1"
  exec "${ROOT_DIR}/scripts/boot_onboarding_node.sh"
fi

cat <<MSG
Next manual step on the observer machine:
  WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE='${BUNDLE_PATH}' \\
  WEALL_CHAIN_MANIFEST_PATH='${MANIFEST_PATH}' \\
  bash scripts/boot_onboarding_node.sh
MSG
