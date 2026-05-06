#!/usr/bin/env bash
set -euo pipefail

# Fresh user -> node-operator candidate demo harness.
# Default is a safe structural smoke check. Set WEALL_FRESH_OPERATOR_DEMO_EXECUTE=1
# to drive a running local onboarding API. Execution stops at candidate / activation
# pending and does not grant production service authority.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${NODE1_API:-http://127.0.0.1:8001}}"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${ROOT}/.weall-devnet}"
WORK_DIR="${WEALL_FRESH_OPERATOR_DEMO_DIR:-${DEVNET_DIR}/fresh-node-operator-candidate}"
ACCOUNT_KEYFILE="${WEALL_KEYFILE:-${WORK_DIR}/account.json}"
NODE_KEYFILE="${WEALL_NODE_KEYFILE:-${WORK_DIR}/weall-node.key}"
ACCOUNT="${WEALL_ACCOUNT:-}"
WAIT_TIMEOUT="${WEALL_OPERATOR_CANDIDATE_WAIT_TIMEOUT:-60}"
RUN_EXECUTE="${WEALL_FRESH_OPERATOR_DEMO_EXECUTE:-0}"

mkdir -p "${WORK_DIR}"
cd "${ROOT}"

fail() { echo "[fresh-operator-candidate-demo] FAIL: $*" >&2; exit 1; }
info() { echo "[fresh-operator-candidate-demo] $*"; }
require_file() { [ -f "$1" ] || fail "missing file: $1"; }
require_text() { grep -F "$2" "$1" >/dev/null || fail "missing text in $1: $2"; }
reject_text() { if grep -F "$2" "$1" >/dev/null; then fail "forbidden text in $1: $2"; fi; }

structural_smoke() {
  quickstart="${ROOT}/docs/NEW_NODE_OPERATOR_QUICKSTART.md"
  onboarding_boot="${ROOT}/scripts/boot_onboarding_node.sh"
  service_boot="${ROOT}/scripts/boot_node_operator.sh"
  tier1_demo="${ROOT}/scripts/demo_native_async_tier1_e2e.sh"
  live_request="${ROOT}/scripts/devnet_request_live.sh"
  account_page="${ROOT}/../web/src/pages/Account.tsx"
  node_keys="${ROOT}/../web/src/auth/nodeKeys.ts"
  for f in "$quickstart" "$onboarding_boot" "$service_boot" "$tier1_demo" "$live_request" "$account_page" "$node_keys"; do require_file "$f"; done
  bash -n "$onboarding_boot" "$service_boot" "$tier1_demo" "$live_request"
  require_text "$onboarding_boot" "observer_onboarding"
  require_text "$onboarding_boot" "WEALL_OBSERVER_MODE"
  require_text "$service_boot" "production_service"
  require_text "$service_boot" "WEALL_NODE_PRIVKEY_FILE"
  require_text "$quickstart" "Create your account and save your recovery key"
  require_text "$quickstart" "Verified Person / Tier 1"
  require_text "$quickstart" "Trusted Verified Person / Tier 2"
  require_text "$quickstart" "Generate a separate node key"
  require_text "$quickstart" "Register the node public key"
  require_text "$quickstart" "Submit node-operator enrollment"
  require_text "$quickstart" "Wait for activation"
  require_text "$account_page" "Generate and download node key"
  require_text "$account_page" "Submit node operator enrollment"
  require_text "$account_page" "Awaiting network approval"
  require_text "$account_page" "ACCOUNT_DEVICE_REGISTER"
  require_text "$account_page" "ROLE_NODE_OPERATOR_ENROLL"
  require_text "$node_keys" "not your WeAll account recovery key"
  reject_text "$account_page" 'WEALL_NODE_PRIVKEY=${'
  info "structural smoke OK"
}

json_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path, key = sys.argv[1:]
try:
    data = json.load(open(path, 'r', encoding='utf-8'))
except FileNotFoundError:
    data = {}
print(str(data.get(key) or '').strip())
PY
}

generate_node_key() {
  python3 - "${NODE_KEYFILE}" <<'PY'
import json, sys, time
from pathlib import Path
from nacl.signing import SigningKey
path = Path(sys.argv[1]).expanduser(); path.parent.mkdir(parents=True, exist_ok=True)
if path.exists():
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
        if obj.get('public_key_hex') and obj.get('private_key_hex'):
            print(obj['public_key_hex']); raise SystemExit(0)
    except Exception:
        pass
sk = SigningKey.generate()
obj = {'type':'weall_node_key','version':1,'key_type':'ed25519','private_key_hex':sk.encode().hex(),'public_key_hex':sk.verify_key.encode().hex(),'created_at_ms':int(time.time()*1000),'warning':'This is an operational node key, not your WeAll account recovery key.'}
path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
try: path.chmod(0o600)
except OSError: pass
print(obj['public_key_hex'])
PY
}

role_state_json() {
  python3 - "$API" <<'PY'
import json, sys, urllib.request
api = sys.argv[1].rstrip('/')
for path in ('/v1/state/snapshot', '/v1/state'):
    try:
        out = json.loads(urllib.request.urlopen(api + path, timeout=20).read().decode('utf-8'))
        state = out.get('state') if isinstance(out, dict) else out
        if isinstance(state, dict):
            print(json.dumps(state.get('roles') if isinstance(state.get('roles'), dict) else {}, sort_keys=True)); raise SystemExit(0)
    except Exception:
        pass
print('{}')
PY
}

assert_activation_pending() {
  role_state_json | python3 - "$1" <<'PY'
import json, sys
acct = sys.argv[1]; roles = json.load(sys.stdin); ops = roles.get('node_operators') if isinstance(roles, dict) else {}
active = ops.get('active_set') if isinstance(ops, dict) else []
rec = (ops.get('by_id') or {}).get(acct) if isinstance(ops, dict) else {}
if acct in [str(x) for x in (active or [])] or (isinstance(rec, dict) and rec.get('active') is True):
    raise SystemExit('node operator unexpectedly active; candidate demo must stop at activation pending')
print('activation_pending')
PY
}

execute_candidate_path() {
  info "execution mode enabled; expecting onboarding node/API at ${API}"
  WEALL_API="$API" WEALL_KEYFILE="$ACCOUNT_KEYFILE" WEALL_ACCOUNT="$ACCOUNT" bash scripts/devnet_create_account.sh
  ACCOUNT="${ACCOUNT:-$(json_get "$ACCOUNT_KEYFILE" account)}"; [ -n "$ACCOUNT" ] || fail "could not resolve account"
  WEALL_API="$API" WEALL_KEYFILE="$ACCOUNT_KEYFILE" WEALL_ACCOUNT="$ACCOUNT" WEALL_NATIVE_ASYNC_WAIT_TIMEOUT="$WAIT_TIMEOUT" bash scripts/demo_native_async_tier1_e2e.sh
  WEALL_API="$API" WEALL_KEYFILE="$ACCOUNT_KEYFILE" WEALL_ACCOUNT="$ACCOUNT" bash scripts/devnet_request_live.sh
  NODE_PUBKEY="$(generate_node_key)"; NODE_DEVICE_ID="node:${ACCOUNT}:${NODE_PUBKEY:0:16}"
  python3 scripts/devnet_tx.py --api "$API" submit-tx --account "$ACCOUNT" --keyfile "$ACCOUNT_KEYFILE" --tx-type ACCOUNT_DEVICE_REGISTER --payload-json "{\"device_id\":\"$NODE_DEVICE_ID\",\"device_type\":\"node\",\"label\":\"Fresh operator candidate node\",\"pubkey\":\"$NODE_PUBKEY\"}" --wait
  python3 scripts/devnet_tx.py --api "$API" submit-tx --account "$ACCOUNT" --keyfile "$ACCOUNT_KEYFILE" --tx-type ROLE_NODE_OPERATOR_ENROLL --payload-json "{\"account_id\":\"$ACCOUNT\"}" --wait
  assert_activation_pending "$ACCOUNT"
  cat > "${WORK_DIR}/production-service.example.env" <<EOF_ENV
WEALL_BOUND_ACCOUNT=${ACCOUNT}
WEALL_NODE_PRIVKEY_FILE=${NODE_KEYFILE}
WEALL_NODE_PUBKEY=${NODE_PUBKEY}
# Run only after network approval activates the NodeOperator role:
# ./scripts/boot_node_operator.sh
EOF_ENV
  info "candidate demo complete; activation is pending; production service boot should remain blocked until network approval"
}

structural_smoke
if [[ "$RUN_EXECUTE" == "1" ]]; then execute_candidate_path; else info "dry-run only. Set WEALL_FRESH_OPERATOR_DEMO_EXECUTE=1 to drive a running onboarding API."; fi
