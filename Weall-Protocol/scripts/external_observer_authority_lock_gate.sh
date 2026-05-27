#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"
API_BASE="${WEALL_API_BASE:-${WEALL_OBSERVER_API_BASE:-}}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

env_truthy() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

# Force the same observer-only posture used by the live gate. The script may be
# run before boot as a local config proof or after boot with WEALL_API_BASE set as
# a runtime/status proof.
export WEALL_MODE="${WEALL_MODE:-prod}"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_NODE_LIFECYCLE_STATE="${WEALL_NODE_LIFECYCLE_STATE:-observer_onboarding}"
export WEALL_SERVICE_ROLES="${WEALL_SERVICE_ROLES:-}"
export WEALL_OBSERVER_MODE="${WEALL_OBSERVER_MODE:-1}"
export WEALL_VALIDATOR_SIGNING_ENABLED="${WEALL_VALIDATOR_SIGNING_ENABLED:-0}"
export WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"
export WEALL_HELPER_MODE_ENABLED="${WEALL_HELPER_MODE_ENABLED:-0}"
export WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-0}"

[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"

if ! env_truthy "${WEALL_OBSERVER_MODE}"; then
  fail "WEALL_OBSERVER_MODE must be 1 for an external observer authority-lock proof"
fi
if env_truthy "${WEALL_VALIDATOR_SIGNING_ENABLED}"; then
  fail "observer authority-lock refuses WEALL_VALIDATOR_SIGNING_ENABLED=1"
fi
if env_truthy "${WEALL_BFT_ENABLED}"; then
  fail "observer authority-lock refuses WEALL_BFT_ENABLED=1"
fi
if env_truthy "${WEALL_HELPER_MODE_ENABLED}"; then
  fail "observer authority-lock refuses WEALL_HELPER_MODE_ENABLED=1 for first external tester posture"
fi
if env_truthy "${WEALL_BLOCK_LOOP_AUTOSTART}"; then
  fail "observer authority-lock refuses WEALL_BLOCK_LOOP_AUTOSTART=1"
fi
case ",$(printf '%s' "${WEALL_SERVICE_ROLES:-}" | tr '[:upper:]' '[:lower:]' | tr -d ' ')," in
  *,validator,*|*,gov_executor,*|*,treasury_signer,*|*,authority,*|*,helper,*|*,storage_provider,*)
    fail "observer authority-lock refuses service authority roles: ${WEALL_SERVICE_ROLES}"
    ;;
esac
if [ -n "${WEALL_VALIDATOR_ACCOUNT:-}" ]; then
  fail "observer authority-lock refuses WEALL_VALIDATOR_ACCOUNT"
fi

bash "${ROOT_DIR}/scripts/prod_node_preflight.sh" >/tmp/weall_observer_authority_prod_preflight.txt
rm -f /tmp/weall_observer_authority_prod_preflight.txt

if [ -n "${API_BASE}" ]; then
  API_BASE="${API_BASE%/}"
  python3 - "${API_BASE}" <<'PY'
from __future__ import annotations
import json
import sys
import urllib.error
import urllib.request

api = sys.argv[1].rstrip('/')

def fetch(path: str) -> dict:
    try:
        with urllib.request.urlopen(api + path, timeout=10) as resp:
            raw = resp.read().decode('utf-8')
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode('utf-8', 'replace')
        raise SystemExit(f"observer_authority_status_probe_failed:{path}:HTTP{exc.code}:{raw[:400]}")
    except Exception as exc:
        raise SystemExit(f"observer_authority_status_probe_failed:{path}:{exc}")
    try:
        obj = json.loads(raw)
    except Exception as exc:
        raise SystemExit(f"observer_authority_status_probe_non_json:{path}:{exc}:{raw[:400]}")
    if not isinstance(obj, dict):
        raise SystemExit(f"observer_authority_status_probe_non_object:{path}")
    return obj

status = fetch('/v1/status')
readyz = fetch('/v1/readyz')
consensus = fetch('/v1/status/consensus')

mode = str(status.get('mode') or '').lower()
if mode and mode != 'observer':
    raise SystemExit(f"observer_status_mode_not_observer:{mode}")

consensus_flags = {
    'local_is_active_validator': consensus.get('local_is_active_validator'),
    'local_is_expected_leader': consensus.get('local_is_expected_leader'),
    'validator_active': consensus.get('validator_active'),
}
for key, value in consensus_flags.items():
    if value is True:
        raise SystemExit(f"observer_unexpected_consensus_authority:{key}")

node_lifecycle = consensus.get('node_lifecycle') if isinstance(consensus.get('node_lifecycle'), dict) else {}
if node_lifecycle.get('bft_enabled_effective') is True:
    raise SystemExit('observer_unexpected_bft_effective')
if node_lifecycle.get('validator_signing_enabled') is True:
    raise SystemExit('observer_unexpected_validator_signing_effective')

contract = readyz.get('authority_contract') if isinstance(readyz.get('authority_contract'), dict) else {}
if contract.get('validator_effective') is True:
    raise SystemExit('observer_unexpected_validator_authority_contract')
if contract.get('helper_effective') is True:
    raise SystemExit('observer_unexpected_helper_authority_contract')

print(json.dumps({
    'ok': True,
    'api': api,
    'mode': mode or 'unknown',
    'height': status.get('height'),
    'chain_id': status.get('chain_id'),
    'consensus_local_is_active_validator': consensus.get('local_is_active_validator'),
}, sort_keys=True))
PY
fi

cat <<MSG
OK: external observer authority lock gate passed
- production preflight accepted the manifest and rejected authority secrets
- observer mode is forced on
- validator signing, BFT, helper mode, and block-loop autostart are forced off
- validator/service authority roles are absent from the local observer environment
MSG
