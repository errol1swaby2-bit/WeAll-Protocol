#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"

# Explicit production service boot path for already-approved node operators.
# This path is intentionally strict: the chain must show Tier 2 + active
# NodeOperator authority + authorized node key before service authority is active.

export WEALL_MODE="${WEALL_MODE:-prod}"
export WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-production_service}"
export WEALL_SERVICE_ROLES="${WEALL_SERVICE_ROLES:-node_operator}"
export WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-0}"
export WEALL_VALIDATOR_SIGNING_ENABLED="${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"
export WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"
export WEALL_HELPER_MODE_ENABLED="${WEALL_HELPER_MODE_ENABLED:-0}"

if [ "${WEALL_MODE}" != "prod" ]; then echo "ERROR: boot_node_operator.sh requires WEALL_MODE=prod" >&2; exit 2; fi
if [ "${WEALL_NODE_LIFECYCLE_STATE}" != "production_service" ]; then echo "ERROR: boot_node_operator.sh requires WEALL_NODE_LIFECYCLE_STATE=production_service" >&2; exit 2; fi
case ",${WEALL_SERVICE_ROLES}," in *,node_operator,*) ;; *) echo "ERROR: production node operator boot requires WEALL_SERVICE_ROLES to include node_operator" >&2; exit 2 ;; esac
if [ -z "${WEALL_BOUND_ACCOUNT:-${WEALL_VALIDATOR_ACCOUNT:-}}" ]; then echo "ERROR: set WEALL_BOUND_ACCOUNT to the activated node operator account" >&2; exit 2; fi
if [ -z "${WEALL_NODE_PRIVKEY_FILE:-}" ]; then echo "ERROR: set WEALL_NODE_PRIVKEY_FILE to the downloaded separate node key file; inline node private keys are refused for this reboot gate" >&2; exit 2; fi
if [ ! -f "${WEALL_NODE_PRIVKEY_FILE}" ]; then echo "ERROR: WEALL_NODE_PRIVKEY_FILE does not exist: ${WEALL_NODE_PRIVKEY_FILE}" >&2; exit 2; fi
if [ -z "${WEALL_NODE_PUBKEY_FILE:-${WEALL_NODE_PUBKEY:-}}" ]; then echo "ERROR: set WEALL_NODE_PUBKEY_FILE or WEALL_NODE_PUBKEY to the registered node public key" >&2; exit 2; fi
if [ -z "${WEALL_API_BASE:-${WEALL_GENESIS_API_BASE:-}}" ]; then echo "ERROR: set WEALL_API_BASE or WEALL_GENESIS_API_BASE so chain operator-promotion-status can be verified" >&2; exit 2; fi

cat >&2 <<'MSG'
[weall] Starting production node operator service boot.
[weall] WeAll is a pre-public-testnet protocol implementation under active hardening.
[weall] This mode is fail-closed: Tier 2, active baseline node-operator authority, and a matching registered node key are required.
[weall] Service mode does not imply validator authority.
MSG

python3 -S - "${WEALL_API_BASE:-${WEALL_GENESIS_API_BASE:-}}" "${WEALL_BOUND_ACCOUNT:-${WEALL_VALIDATOR_ACCOUNT:-}}" "${WEALL_NODE_PUBKEY:-}" "${WEALL_NODE_PUBKEY_FILE:-}" <<'PY'
from __future__ import annotations
import json, sys, urllib.parse, urllib.request
from pathlib import Path
api, account, node_pubkey, node_pubkey_file = sys.argv[1:5]
if not account:
    raise SystemExit('ERROR: WEALL_BOUND_ACCOUNT is required')
if not node_pubkey and node_pubkey_file:
    path = Path(node_pubkey_file).expanduser()
    text = path.read_text(encoding='utf-8').strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            node_pubkey = str(obj.get('public_key_hex') or obj.get('public_key_b64') or obj.get('pubkey') or obj.get('public_key') or '').strip()
    except Exception:
        node_pubkey = text
if not node_pubkey:
    raise SystemExit('ERROR: registered node public key is required')
url = api.rstrip('/') + '/v1/accounts/' + urllib.parse.quote(account, safe='') + '/operator-promotion-status?node_pubkey=' + urllib.parse.quote(node_pubkey, safe='')
with urllib.request.urlopen(url, timeout=15) as resp:
    if resp.status >= 400:
        raise SystemExit(f'ERROR: operator-promotion-status failed:{resp.status}')
    body = json.loads(resp.read().decode('utf-8'))
p = body.get('promotion') if isinstance(body.get('promotion'), dict) else {}
issues = []
for field in ('account_unrestricted', 'node_key_registered', 'node_operator_active', 'service_reboot_allowed'):
    if p.get(field) is not True:
        issues.append(f'{field}_false')
if p.get('node_pubkey') != node_pubkey:
    issues.append('node_pubkey_mismatch')
if issues:
    reasons = p.get('blocking_reasons') if isinstance(p.get('blocking_reasons'), list) else []
    raise SystemExit('ERROR: production service reboot blocked: ' + ','.join(issues + [str(r) for r in reasons if r]))
print('OK: production service reboot allowed by chain operator-promotion-status')
PY

bash "${SCRIPT_DIR}/prod_node_preflight.sh"
exec "${SCRIPT_DIR}/run_node_prod.sh"
