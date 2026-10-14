#!/usr/bin/env bash
set -euo pipefail

# Fresh user -> production service readiness E2E harness.
# Default mode is a safe structural/local smoke: it does not require a running API
# and does not grant service authority. Set WEALL_FRESH_SERVICE_E2E_EXECUTE=1 to
# drive the account/PoH/enrollment user-transaction portion against a running local
# onboarding API. System verification submissions remain explicit and are never
# bypassed by this harness.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${NODE1_API:-http://127.0.0.1:8001}}"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${ROOT}/.weall-devnet}"
WORK_DIR="${WEALL_FRESH_SERVICE_E2E_DIR:-${DEVNET_DIR}/fresh-node-to-service-e2e}"
ACCOUNT_KEYFILE="${WEALL_KEYFILE:-${WORK_DIR}/account.json}"
NODE_KEYFILE="${WEALL_NODE_KEYFILE:-${WORK_DIR}/weall-node.key}"
BFT_KEYFILE="${WEALL_BFT_KEYFILE:-${WORK_DIR}/weall-bft.key}"
STORAGE_ROOT="${WEALL_STORAGE_PROBE_ROOT:-${WORK_DIR}/storage-root}"
ACCOUNT="${WEALL_ACCOUNT:-}"
RUN_EXECUTE="${WEALL_FRESH_SERVICE_E2E_EXECUTE:-0}"
WAIT_TIMEOUT="${WEALL_FRESH_SERVICE_E2E_WAIT_TIMEOUT:-60}"
DECLARED_CAPACITY_BYTES="${WEALL_E2E_STORAGE_DECLARED_BYTES:-1048576}"
RESERVED_CAPACITY_BYTES="${WEALL_E2E_STORAGE_RESERVED_BYTES:-1048576}"
SAMPLE_SIZE_BYTES="${WEALL_E2E_STORAGE_SAMPLE_SIZE_BYTES:-1024}"
SAMPLE_COUNT="${WEALL_E2E_STORAGE_SAMPLE_COUNT:-3}"
READINESS_EXPIRES_HEIGHT="${WEALL_E2E_READINESS_EXPIRES_HEIGHT:-100000}"

mkdir -p "${WORK_DIR}" "${STORAGE_ROOT}"
cd "${ROOT}"
export PYTHONPATH="${ROOT}/src:${PYTHONPATH:-}"

fail() { echo "[fresh-node-to-service-e2e] FAIL: $*" >&2; exit 1; }
info() { echo "[fresh-node-to-service-e2e] $*"; }
require_file() { [ -f "$1" ] || fail "missing file: $1"; }
require_text() { grep -F "$2" "$1" >/dev/null || fail "missing text in $1: $2"; }
reject_text() { if grep -F "$2" "$1" >/dev/null; then fail "forbidden text in $1: $2"; fi; }

json_get() {
  python3 -S - "$1" "$2" <<'PY'
import json, sys
path, key = sys.argv[1:]
try:
    data = json.load(open(path, 'r', encoding='utf-8'))
except FileNotFoundError:
    data = {}
print(str(data.get(key) or '').strip())
PY
}

write_keypair() {
  python3 -S - "$1" "$2" <<'PY'
import hashlib, json, os, sys, time
from pathlib import Path
path = Path(sys.argv[1]).expanduser(); key_type = sys.argv[2]
path.parent.mkdir(parents=True, exist_ok=True)
if path.exists():
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
        if obj.get('public_key_hex') and obj.get('private_key_hex'):
            print(obj['public_key_hex']); raise SystemExit(0)
    except Exception:
        pass
private_hex = os.urandom(32).hex()
public_hex = hashlib.sha256((key_type + ':' + private_hex).encode('utf-8')).hexdigest()
obj = {
    'type': key_type,
    'version': 1,
    'key_type': 'mldsa-devnet-material',
    'private_key_hex': private_hex,
    'public_key_hex': public_hex,
    'created_at_ms': int(time.time() * 1000),
    'warning': 'Operational key material. This is not your WeAll account recovery key.',
}
path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n', encoding='utf-8')
try: path.chmod(0o600)
except OSError: pass
print(obj['public_key_hex'])
PY
}

generate_node_key() { write_keypair "${NODE_KEYFILE}" "weall_node_key"; }
generate_bft_key() { write_keypair "${BFT_KEYFILE}" "weall_bft_validator_readiness_key"; }

write_capacity_challenge() {
  python3 -S - "$WORK_DIR/capacity-challenge.json" "$1" "$2" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1]); account = sys.argv[2]; node_pubkey = sys.argv[3]
declared = int(__import__('os').environ.get('DECLARED_CAPACITY_BYTES', '1048576'))
reserved = int(__import__('os').environ.get('RESERVED_CAPACITY_BYTES', '1048576'))
sample_size = int(__import__('os').environ.get('SAMPLE_SIZE_BYTES', '1024'))
sample_count = int(__import__('os').environ.get('SAMPLE_COUNT', '3'))
max_offset = max(0, reserved - sample_size)
if sample_count <= 1:
    offsets = [0]
else:
    offsets = sorted({int(round(i * max_offset / (sample_count - 1))) for i in range(sample_count)})
while len(offsets) < sample_count:
    offsets.append(max_offset)
challenge = {
    'proof_scope': 'capacity_probe',
    'challenge_id': 'fresh-service-capacity-probe-1',
    'account_id': account,
    'node_pubkey': node_pubkey,
    'declared_capacity_bytes': declared,
    'reserved_capacity_bytes': reserved,
    'sample_count': sample_count,
    'sample_size_bytes': sample_size,
    'probe_offsets': offsets[:sample_count],
    'challenge_seed': 'fresh-node-to-service-e2e-seed-v1',
    'expires_height': 100000,
}
path.write_text(json.dumps(challenge, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print(path)
PY
}

run_local_storage_probe() {
  account="$1"; node_pubkey="$2"
  challenge_path="$(write_capacity_challenge "$account" "$node_pubkey")"
  prepare_out="${WORK_DIR}/storage-prepare.json"
  response_out="${WORK_DIR}/storage-response.json"
  verify_out="${WORK_DIR}/storage-verify.json"
  python3 -S scripts/storage_probe_runner_check.py prepare \
    --storage-root "${STORAGE_ROOT}" \
    --challenge "${challenge_path}" \
    --available-capacity-bytes "$((RESERVED_CAPACITY_BYTES * 2))" \
    --max-probe-bytes "$((SAMPLE_SIZE_BYTES * SAMPLE_COUNT * 2))" > "${prepare_out}"
  python3 -S scripts/storage_probe_runner_check.py respond \
    --storage-root "${STORAGE_ROOT}" \
    --challenge-id "fresh-service-capacity-probe-1" > "${response_out}"
  python3 -S scripts/storage_probe_runner_check.py verify \
    --challenge "${challenge_path}" \
    --response "${response_out}" > "${verify_out}"
  python3 -S - "${verify_out}" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
if obj.get('verification_status') != 'verified' or int(obj.get('verified_capacity_bytes') or 0) <= 0:
    raise SystemExit('storage probe did not verify')
PY
  info "storage probe local verification OK"
}

run_local_validator_readiness() {
  account="$1"; node_pubkey="$2"; bft_pubkey="$3"
  receipt="${WORK_DIR}/validator-readiness-receipt.json"
  verify="${WORK_DIR}/validator-readiness-verify.json"
  python3 -S scripts/validator_readiness_check.py generate \
    --account-id "${account}" \
    --node-pubkey "${node_pubkey}" \
    --bft-pubkey "${bft_pubkey}" \
    --chain-id "weall-dev" \
    --schema-version "1.25.0" \
    --protocol-version "1.25.0" \
    --manifest-hash "sha256:fresh-service-manifest" \
    --tx-index-hash "sha256:fresh-service-tx-index" \
    --runtime-profile-hash "sha256:fresh-service-runtime-profile" \
    --readiness-expires-height "${READINESS_EXPIRES_HEIGHT}" > "${receipt}"
  python3 -S scripts/validator_readiness_check.py verify \
    --receipt "${receipt}" \
    --account-id "${account}" \
    --node-pubkey "${node_pubkey}" \
    --current-height 1 > "${verify}"
  info "validator readiness local verification OK"
}

write_service_env() {
  account="$1"; node_pubkey="$2"; bft_pubkey="$3"
  cat > "${WORK_DIR}/production-service.example.env" <<EOF_ENV
WEALL_BOUND_ACCOUNT=${account}
WEALL_NODE_PRIVKEY_FILE=${NODE_KEYFILE}
WEALL_NODE_PUBKEY=${node_pubkey}
WEALL_BFT_PUBKEY=${bft_pubkey}
WEALL_STORAGE_ROOT=${STORAGE_ROOT}
# Run only after operator-status shows active baseline Node Operator and any requested
# storage/validator responsibilities are active from protocol verification:
# ./scripts/boot_node_operator.sh
EOF_ENV
}

structural_smoke() {
  quickstart="${ROOT}/docs/NEW_NODE_OPERATOR_QUICKSTART.md"
  onboarding_boot="${ROOT}/scripts/boot_onboarding_node.sh"
  service_boot="${ROOT}/scripts/boot_node_operator.sh"
  storage_runner="${ROOT}/scripts/storage_probe_runner_check.py"
  validator_runner="${ROOT}/scripts/validator_readiness_check.py"
  candidate_demo="${ROOT}/scripts/fresh_node_operator_candidate_demo.sh"
  account_page="${ROOT}/../web/src/pages/Account.tsx"
  for f in "$quickstart" "$onboarding_boot" "$service_boot" "$storage_runner" "$validator_runner" "$candidate_demo" "$account_page"; do require_file "$f"; done
  bash -n "$onboarding_boot" "$service_boot" "$candidate_demo" "$0"
  python3 -S -m py_compile "$storage_runner" "$validator_runner"
  require_text "$onboarding_boot" "observer_onboarding"
  require_text "$service_boot" "production_service"
  require_text "$service_boot" "WEALL_NODE_PRIVKEY_FILE"
  require_text "$storage_runner" "storage_probe_runner"
  require_text "$validator_runner" "validator_readiness_runner"
  require_text "$account_page" "NODE_OPERATOR_STORAGE_OPT_IN"
  require_text "$account_page" "NODE_OPERATOR_VALIDATOR_OPT_IN"
  require_text "$account_page" "operatorStatus"
  reject_text "$account_page" 'WEALL_NODE_PRIVKEY=${'
  reject_text "$quickstart" "WEALL_NODE_PRIVKEY=<account_""secret>"
  info "structural smoke OK"
}

execute_user_path() {
  info "execution mode enabled; expecting onboarding API at ${API}"
  WEALL_API="$API" WEALL_KEYFILE="$ACCOUNT_KEYFILE" WEALL_ACCOUNT="$ACCOUNT" bash scripts/devnet_create_account.sh
  ACCOUNT="${ACCOUNT:-$(json_get "$ACCOUNT_KEYFILE" account)}"; [ -n "$ACCOUNT" ] || fail "could not resolve account"
  WEALL_API="$API" WEALL_KEYFILE="$ACCOUNT_KEYFILE" WEALL_ACCOUNT="$ACCOUNT" WEALL_NATIVE_ASYNC_WAIT_TIMEOUT="$WAIT_TIMEOUT" bash scripts/demo_native_async_tier1_e2e.sh
  WEALL_API="$API" WEALL_KEYFILE="$ACCOUNT_KEYFILE" WEALL_ACCOUNT="$ACCOUNT" bash scripts/devnet_request_live.sh
  node_pubkey="$(generate_node_key)"; bft_pubkey="$(generate_bft_key)"; device_id="node:${ACCOUNT}:${node_pubkey:0:16}"
  python3 scripts/devnet_tx.py --api "$API" submit-tx --account "$ACCOUNT" --keyfile "$ACCOUNT_KEYFILE" --tx-type ACCOUNT_DEVICE_REGISTER --payload-json "{\"device_id\":\"$device_id\",\"device_type\":\"node\",\"label\":\"Fresh service node\",\"pubkey\":\"$node_pubkey\"}" --wait
  python3 scripts/devnet_tx.py --api "$API" submit-tx --account "$ACCOUNT" --keyfile "$ACCOUNT_KEYFILE" --tx-type ROLE_NODE_OPERATOR_ENROLL --payload-json "{\"account_id\":\"$ACCOUNT\"}" --wait
  python3 scripts/devnet_tx.py --api "$API" submit-tx --account "$ACCOUNT" --keyfile "$ACCOUNT_KEYFILE" --tx-type NODE_OPERATOR_STORAGE_OPT_IN --payload-json "{\"account_id\":\"$ACCOUNT\",\"node_pubkey\":\"$node_pubkey\",\"declared_capacity_bytes\":$DECLARED_CAPACITY_BYTES}" --wait
  python3 scripts/devnet_tx.py --api "$API" submit-tx --account "$ACCOUNT" --keyfile "$ACCOUNT_KEYFILE" --tx-type NODE_OPERATOR_VALIDATOR_OPT_IN --payload-json "{\"account_id\":\"$ACCOUNT\",\"node_pubkey\":\"$node_pubkey\"}" --wait
  run_local_storage_probe "$ACCOUNT" "$node_pubkey"
  run_local_validator_readiness "$ACCOUNT" "$node_pubkey" "$bft_pubkey"
  write_service_env "$ACCOUNT" "$node_pubkey" "$bft_pubkey"
  info "user path complete; system storage/validator verification payloads are in ${WORK_DIR}"
  info "production service boot remains fail-closed until operator-status reports active responsibilities"
}

structural_smoke
node_pubkey="$(generate_node_key)"
bft_pubkey="$(generate_bft_key)"
dry_account="${ACCOUNT:-@fresh-service-dryrun}"
run_local_storage_probe "$dry_account" "$node_pubkey"
run_local_validator_readiness "$dry_account" "$node_pubkey" "$bft_pubkey"
write_service_env "$dry_account" "$node_pubkey" "$bft_pubkey"

if [[ "$RUN_EXECUTE" == "1" ]]; then
  execute_user_path
else
  info "dry-run only. Set WEALL_FRESH_SERVICE_E2E_EXECUTE=1 to drive a running onboarding API."
fi
