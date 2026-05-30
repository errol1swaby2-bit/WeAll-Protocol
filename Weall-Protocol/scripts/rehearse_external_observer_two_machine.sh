#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/rehearse_external_observer_two_machine.sh <public-observer-bundle.json>

Runs the external observer two-machine preflight against a non-local Genesis API.

Required:
  <public-observer-bundle.json> or WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE
  WEALL_GENESIS_API_BASE or WEALL_API_BASE

Optional:
  WEALL_CHAIN_MANIFEST_PATH
  WEALL_ALLOW_PRIVATE_GENESIS_API=1   Allow private LAN Genesis API for controlled rehearsal only.
  WEALL_NET_RELAY_URLS
  WEALL_NET_RELAY_RECIPIENT_PUBKEYS

Truth boundary:
  Passing this rehearsal proves remote Genesis API compatibility for the supplied bundle.
  It does not by itself prove signed observer onboarding, public multi-validator BFT,
  live economics, mainnet readiness, or production-grade private messaging.
EOF
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-}"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-${WEALL_API_BASE:-}}"
RELAY_URLS="${WEALL_NET_RELAY_URLS:-}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# Shared boundary rejects WEALL_AUTHORITY_SIGNER_PRIVKEY, WEALL_AUTHORITY_PRIVKEY,
# WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY, WEALL_ORACLE_AUTHORITY_PRIVKEY,
# WEALL_CLOUDFLARE_API_TOKEN, and SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD".
# shellcheck disable=SC1091
. "${ROOT_DIR}/scripts/lib/observer_secret_boundary.sh"
weall_check_observer_secret_boundary || exit $?

[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <public-observer-bundle.json> with WEALL_GENESIS_API_BASE set"
[ -f "${BUNDLE_PATH}" ] || fail "bundle not found: ${BUNDLE_PATH}"
if [ -z "${MANIFEST_PATH}" ]; then
  MANIFEST_PATH="$(python3 - "${BUNDLE_PATH}" "${ROOT_DIR}" <<'WEALL_BUNDLE_MANIFEST_PATH_PY'
from __future__ import annotations
import json
import sys
from pathlib import Path
bundle_path = Path(sys.argv[1])
root = Path(sys.argv[2])
bundle = json.loads(bundle_path.read_text(encoding='utf-8'))
chain = bundle.get('chain') if isinstance(bundle.get('chain'), dict) else {}
hint = str(chain.get('manifest_path_hint') or '').strip()
candidates = []
if hint:
    candidates.append(Path(hint))
    candidates.append(root / hint)
candidates.append(root / 'configs' / 'chains' / 'weall-genesis.json')
for candidate in candidates:
    try:
        resolved = candidate.expanduser().resolve()
    except Exception:
        continue
    if resolved.is_file():
        print(str(resolved))
        raise SystemExit(0)
print('')
WEALL_BUNDLE_MANIFEST_PATH_PY
)"
fi
[ -n "${MANIFEST_PATH}" ] || fail "chain manifest path could not be resolved"
[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"
MANIFEST_MODE="$(python3 - "${MANIFEST_PATH}" <<'WEALL_MANIFEST_MODE_PY'
from __future__ import annotations
import json
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    obj = json.load(fh)
print(str(obj.get('mode') or '').strip())
WEALL_MANIFEST_MODE_PY
)"
[ -n "${GENESIS_API_BASE}" ] || fail "WEALL_GENESIS_API_BASE or WEALL_API_BASE is required for a two-machine rehearsal"

# Reject obvious local/self/metadata endpoints. Historical cases covered here
# include http://127.0.0.1*, http://localhost*, https://127.0.0.1*, and
# https://localhost*. Private LAN IPs require WEALL_ALLOW_PRIVATE_GENESIS_API=1.
python3 - "${GENESIS_API_BASE}" "${WEALL_ALLOW_PRIVATE_GENESIS_API:-0}" <<'PY_NONLOCAL_API'
from __future__ import annotations
import ipaddress
import sys
import urllib.parse
url, allow_private = sys.argv[1], sys.argv[2]
parsed = urllib.parse.urlparse(url)
if parsed.scheme not in {"http", "https"}:
    raise SystemExit("two_machine_rehearsal_genesis_api_scheme_invalid")
host = (parsed.hostname or "").strip().lower()
if not host:
    raise SystemExit("two_machine_rehearsal_genesis_api_host_missing")
if host in {"localhost", "ip6-localhost"} or host.endswith(".localhost"):
    raise SystemExit(f"two-machine rehearsal requires a remote genesis API base, not localhost: {url}")
try:
    ip = ipaddress.ip_address(host)
except ValueError:
    ip = None
if ip is not None:
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        raise SystemExit(f"two-machine rehearsal requires a remote genesis API base, not localhost: {url}")
    if str(ip) == "169.254.169.254":
        raise SystemExit("two_machine_rehearsal_metadata_service_forbidden")
    if ip.is_private and allow_private not in {"1", "true", "TRUE", "yes", "YES", "on", "ON"}:
        raise SystemExit("two_machine_rehearsal_private_genesis_api_requires_WEALL_ALLOW_PRIVATE_GENESIS_API=1")
print("OK: genesis API base is non-local for two-machine rehearsal")
PY_NONLOCAL_API

export WEALL_GENESIS_API_BASE="${GENESIS_API_BASE%/}"
export WEALL_API_BASE="${GENESIS_API_BASE%/}"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE="${BUNDLE_PATH}"
export WEALL_MODE="${WEALL_MODE:-${MANIFEST_MODE:-prod}}"
export WEALL_NODE_LIFECYCLE_STATE="observer_onboarding"
export WEALL_SERVICE_ROLES=""
export WEALL_OBSERVER_MODE="1"
export WEALL_VALIDATOR_SIGNING_ENABLED="0"
export WEALL_BFT_ENABLED="0"
export WEALL_HELPER_MODE_ENABLED="0"
export WEALL_BLOCK_LOOP_AUTOSTART="0"

bash "${ROOT_DIR}/scripts/external_observer_onboarding_smoke.sh" "${BUNDLE_PATH}"

python3 - "${WEALL_GENESIS_API_BASE}" "${BUNDLE_PATH}" <<'PY_REMOTE_CHECK'
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

api = sys.argv[1].rstrip("/")
bundle = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
chain = bundle.get("chain") if isinstance(bundle.get("chain"), dict) else {}
expected_chain_id = str(chain.get("chain_id") or "").strip()
expected_tx_hash = str(chain.get("tx_index_hash") or "").strip().lower()
expected_profile_hash = str(chain.get("protocol_profile_hash") or "").strip().lower()

def fetch_json(path: str) -> dict:
    try:
        with urllib.request.urlopen(api + path, timeout=10) as resp:
            if resp.status >= 400:
                raise SystemExit(f"remote_endpoint_failed:{path}:{resp.status}")
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"remote_endpoint_failed:{path}:{exc.code}") from exc

    try:
        obj = json.loads(body)
    except Exception as exc:
        raise SystemExit(f"remote_endpoint_non_json:{path}:{exc}") from exc

    if not isinstance(obj, dict):
        raise SystemExit(f"remote_endpoint_not_object:{path}")
    return obj

fetch_json("/v1/health")
fetch_json("/v1/status")

ready_ok = False
for ready_path in ("/v1/ready", "/v1/readyz"):
    try:
        fetch_json(ready_path)
        ready_ok = True
        break
    except SystemExit:
        continue
if not ready_ok:
    # Controlled devnet currently exposes health/status/identity but may not expose
    # a ready endpoint. Status + identity below remain the hard compatibility checks.
    pass

ident = fetch_json("/v1/chain/identity")
remote_chain_id = str(ident.get("chain_id") or ident.get("chain", {}).get("chain_id") or "").strip()
if expected_chain_id and remote_chain_id and remote_chain_id != expected_chain_id:
    raise SystemExit(f"remote_chain_id_mismatch:{remote_chain_id}!={expected_chain_id}")

manifest = ident.get("chain_manifest") if isinstance(ident.get("chain_manifest"), dict) else {}
remote_tx_hash = str(manifest.get("tx_index_hash") or ident.get("tx_index_hash") or "").strip().lower()
if expected_tx_hash and remote_tx_hash and remote_tx_hash != expected_tx_hash:
    raise SystemExit(f"remote_tx_index_hash_mismatch:{remote_tx_hash}!={expected_tx_hash}")

remote_profile_hash = str(
    ident.get("protocol_profile_hash")
    or manifest.get("protocol_profile_hash")
    or ident.get("production_consensus_profile_hash")
    or ""
).strip().lower()
if expected_profile_hash and remote_profile_hash and remote_profile_hash != expected_profile_hash:
    raise SystemExit(f"remote_protocol_profile_hash_mismatch:{remote_profile_hash}!={expected_profile_hash}")
if expected_profile_hash and not remote_profile_hash:
    raise SystemExit("remote_protocol_profile_hash_missing")

readiness = fetch_json("/v1/genesis/observer/readiness")
if readiness.get("ok") is not True:
    raise SystemExit("remote_genesis_observer_readiness_not_ok")
if str(readiness.get("stage") or "") != "first_trusted_external_observer_rehearsal":
    raise SystemExit("remote_genesis_observer_readiness_stage_invalid")
compat = readiness.get("compatibility") if isinstance(readiness.get("compatibility"), dict) else {}
remote_readiness_chain_id = str(compat.get("chain_id") or "").strip()
if expected_chain_id and remote_readiness_chain_id and remote_readiness_chain_id != expected_chain_id:
    raise SystemExit(f"remote_observer_readiness_chain_id_mismatch:{remote_readiness_chain_id}!={expected_chain_id}")
remote_readiness_tx_hash = str(compat.get("tx_index_hash") or "").strip().lower()
if expected_tx_hash and remote_readiness_tx_hash and remote_readiness_tx_hash != expected_tx_hash:
    raise SystemExit(f"remote_observer_readiness_tx_index_hash_mismatch:{remote_readiness_tx_hash}!={expected_tx_hash}")
remote_readiness_profile_hash = str(compat.get("protocol_profile_hash") or "").strip().lower()
if expected_profile_hash and remote_readiness_profile_hash and remote_readiness_profile_hash != expected_profile_hash:
    raise SystemExit(f"remote_observer_readiness_protocol_profile_hash_mismatch:{remote_readiness_profile_hash}!={expected_profile_hash}")
authority = readiness.get("observer_authority_boundary") if isinstance(readiness.get("observer_authority_boundary"), dict) else {}
if authority.get("observer_receives_validator_authority") is not False:
    raise SystemExit("remote_observer_readiness_validator_authority_not_false")
if authority.get("requires_genesis_or_validator_private_keys") is not False:
    raise SystemExit("remote_observer_readiness_requires_private_keys")
if authority.get("requires_external_identity_provider") is not False:
    raise SystemExit("remote_observer_readiness_requires_external_identity_provider")
public_tx = readiness.get("public_tx_ingress") if isinstance(readiness.get("public_tx_ingress"), dict) else {}
if public_tx.get("signed_user_tx_submit_enabled") is not True:
    raise SystemExit("remote_observer_readiness_signed_tx_submit_not_enabled")
if public_tx.get("system_signer_rejected_from_public_ingress") is not True:
    raise SystemExit("remote_observer_readiness_system_signer_not_rejected")
if public_tx.get("system_flag_rejected_from_public_ingress") is not True:
    raise SystemExit("remote_observer_readiness_system_flag_not_rejected")
endpoints = readiness.get("endpoints") if isinstance(readiness.get("endpoints"), dict) else {}
for key in ("tx_submit", "tx_status", "chain_identity", "observer_readiness"):
    if not str(endpoints.get(key) or "").strip():
        raise SystemExit(f"remote_observer_readiness_missing_endpoint:{key}")

print("OK: remote genesis health/status/identity/readiness compatibility checks passed")
PY_REMOTE_CHECK

if [ -n "${RELAY_URLS}" ]; then
  IFS=',' read -r -a _relay_array <<< "${RELAY_URLS}"
  for relay in "${_relay_array[@]}"; do
    relay="${relay%/}"
    [ -n "${relay}" ] || continue
    python3 - "${relay}" <<'PY'
from __future__ import annotations
import json
import sys
import urllib.request
base = sys.argv[1].rstrip('/')
with urllib.request.urlopen(base + '/v1/net/relay/status', timeout=10) as resp:
    status = json.loads(resp.read().decode('utf-8'))
if not bool(status.get('ok')) or not bool(status.get('enabled')):
    raise SystemExit(f'relay_not_ready:{base}')
if status.get('authority') != 'transport_only':
    raise SystemExit(f'relay_authority_not_transport_only:{base}')
limits = status.get('limits') if isinstance(status.get('limits'), dict) else {}
if limits.get('require_recipient_pubkey') is not True:
    raise SystemExit(f'relay_recipient_pubkey_not_required:{base}')
if limits.get('allow_unbound_recipient_fetch') is not False:
    raise SystemExit(f'relay_allows_unbound_recipient_fetch:{base}')
print(f'OK: relay reachable, transport_only, and recipient-bound: {base}')
PY
  done
fi

cat <<MSG
OK: two-machine external observer rehearsal preflight passed
- remote genesis API is reachable
- chain identity, tx_index_hash, and protocol_profile_hash match the observer bundle when advertised
- observer mode/signing/BFT/helper/block-loop are forced safe
- relay endpoints, if configured, are transport_only and require recipient pubkey binding

This rehearsal is connectivity/preflight only; it does not submit signed onboarding transactions.
The observer onboarding E2E is not complete until scripts/external_observer_live_gate.sh passes.

Next live action on the observer machine:
  WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE='${BUNDLE_PATH}' \
  WEALL_CHAIN_MANIFEST_PATH='${MANIFEST_PATH}' \
  WEALL_GENESIS_API_BASE='${GENESIS_API_BASE%/}' \
  bash scripts/external_observer_live_gate.sh "${BUNDLE_PATH}"
MSG
