#!/usr/bin/env bash
set -euo pipefail

# Controlled-devnet smoke for non-seeded onboarding and convergence:
# clean genesis node boot, account creation through normal tx submission,
# optional Tier-1 email verification through a bounded oracle receipt, node 2
# trusted-anchor sync, cross-node state-root comparison, account/tx parity,
# a Tier-1-gated transaction submitted through node 2 then synced back to node 1,
# and an optional Tier-2 async PoH review/finalization convergence proof.
# This script never calls demo seed routes.
#
# By default this script auto-starts the genesis devnet node on NODE1_API if it
# is not already running. When auto-starting, it also resets stale controlled
# devnet state by default so repeated smokes prove Tier 0 -> Tier 1 truthfully.
# Set WEALL_DEVNET_RESET_ON_AUTOSTART=0 to keep prior local devnet state.
# Set WEALL_DEVNET_AUTOSTART_NODE1=0 to require an already-running node.
# Set WEALL_DEVNET_KEEP_NODES=1 to leave auto-started nodes running.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE1_API="${NODE1_API:-http://127.0.0.1:8001}"
NODE2_API="${NODE2_API:-http://127.0.0.1:8002}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"
ACCOUNT="${WEALL_ACCOUNT:-}"
FRESH_ACCOUNT="${WEALL_DEVNET_FRESH_ACCOUNT:-1}"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${REPO_ROOT}/.weall-devnet}"
LOG_DIR="${WEALL_DEVNET_LOG_DIR:-${DEVNET_DIR}/logs}"
AUTOSTART_NODE1="${WEALL_DEVNET_AUTOSTART_NODE1:-1}"
RESET_ON_AUTOSTART="${WEALL_DEVNET_RESET_ON_AUTOSTART:-1}"
KEEP_NODES="${WEALL_DEVNET_KEEP_NODES:-0}"
NODE1_LOG="${LOG_DIR}/node1.log"
NODE1_PID=""
NODE2_LOG="${LOG_DIR}/node2.log"
NODE2_PID=""
AUTOSTART_NODE2="${WEALL_DEVNET_AUTOSTART_NODE2:-1}"

cd "${REPO_ROOT}"
mkdir -p "${LOG_DIR}"

_is_node_ready() {
  local api="$1"
  curl -fsS "${api%/}/v1/chain/identity" >/dev/null 2>&1
}

_account_from_keyfile() {
  python3 - "${KEYFILE}" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
print(str(data.get('account') or '').strip())
PY
}

_keyfile_field() {
  local field="$1"
  python3 - "${KEYFILE}" "${field}" <<'PY'
import json, sys
path, field = sys.argv[1], sys.argv[2]
try:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
except FileNotFoundError:
    data = {}
print(str(data.get(field) or '').strip())
PY
}

_assert_cross_node_account_and_tx_parity() {
  local account="$1"
  local label="$2"
  shift 2
  python3 - "${NODE1_API}" "${NODE2_API}" "${account}" "${label}" "$@" <<'PY'
import json, sys, urllib.parse, urllib.request
node1, node2, account, label, *tx_ids = sys.argv[1:]

def get_json(api: str, path: str):
    with urllib.request.urlopen(api.rstrip('/') + path, timeout=15) as resp:
        raw = resp.read().decode('utf-8')
        return json.loads(raw) if raw.strip() else {}

def acct(api: str):
    return get_json(api, '/v1/accounts/' + urllib.parse.quote(account, safe='')).get('state') or {}

left = acct(node1)
right = acct(node2)
if left != right:
    raise SystemExit('cross-node account mismatch after %s:\nnode1=%s\nnode2=%s' % (label, json.dumps(left, sort_keys=True), json.dumps(right, sort_keys=True)))

checked = []
for tx_id in [t for t in tx_ids if str(t or '').strip()]:
    path = '/v1/tx/status/' + urllib.parse.quote(tx_id, safe='')
    s1 = get_json(node1, path)
    s2 = get_json(node2, path)
    if str(s1.get('status') or '').lower() != 'confirmed' or str(s2.get('status') or '').lower() != 'confirmed':
        raise SystemExit('tx not confirmed on both nodes after %s: tx=%s node1=%s node2=%s' % (label, tx_id, json.dumps(s1, sort_keys=True), json.dumps(s2, sort_keys=True)))
    for key in ('height', 'block_id', 'tx_type', 'signer'):
        if s1.get(key) != s2.get(key):
            raise SystemExit('tx status mismatch after %s: tx=%s field=%s node1=%s node2=%s' % (label, tx_id, key, json.dumps(s1, sort_keys=True), json.dumps(s2, sort_keys=True)))
    checked.append(tx_id)
print('==> OK: cross-node account/tx parity after %s account=%s tx_count=%d' % (label, account, len(checked)))
PY
}

_submit_node2_convergence_tx() {
  local account="$1"
  local payload_file="${DEVNET_DIR}/node2-follow-payload.json"
  local out_file="${DEVNET_DIR}/node2-follow-submit.json"
  mkdir -p "${DEVNET_DIR}"
  python3 - "${payload_file}" <<'PY'
import json, sys
payload = {"target": "@devnet-genesis", "active": True}
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    json.dump(payload, f, sort_keys=True)
PY
  echo "==> Submitting Tier-1-gated FOLLOW_SET through node 2 normal tx flow" >&2
  WEALL_KEYFILE="${KEYFILE}" bash ./scripts/devnet_submit_tx_node2.sh \
    --keyfile "${KEYFILE}" \
    --tx-type FOLLOW_SET \
    --payload-json "@${payload_file}" \
    --wait \
    --timeout "${WEALL_TX_WAIT_TIMEOUT:-30}" \
    --poll "${WEALL_TX_WAIT_POLL:-0.5}" | tee "${out_file}" >&2
  python3 - "${out_file}" <<'PY'
import json, sys
raw = open(sys.argv[1], 'r', encoding='utf-8').read()
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    decoder = json.JSONDecoder()
    data = None
    for idx, ch in enumerate(raw):
        if ch != '{':
            continue
        try:
            candidate, _end = decoder.raw_decode(raw[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and candidate.get('tx_id'):
            data = candidate
            break
    if data is None:
        raise
tx_id = str(data.get('tx_id') or '').strip()
status = (data.get('tx_status') or {}).get('status') if isinstance(data.get('tx_status'), dict) else ''
if not tx_id:
    raise SystemExit('node2 convergence tx missing tx_id')
if str(status or '').lower() != 'confirmed':
    raise SystemExit('node2 convergence tx was not confirmed: ' + json.dumps(data, sort_keys=True))
print(tx_id)
PY
}

_json_file_field() {
  local file="$1"
  local field="$2"
  python3 - "${file}" "${field}" <<'PY_JSON_FIELD'
import json, sys
path, field = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
cur = data
for part in field.split('.'):
    if isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break
print(str(cur or '').strip())
PY_JSON_FIELD
}

_submit_devnet_tick() {
  local api="$1"
  local label="$2"
  local out_file="${DEVNET_DIR}/tick-${label}.json"
  WEALL_API="${api}" WEALL_KEYFILE="${KEYFILE}" python3 scripts/devnet_tx.py --api "${api}" tick \
    --keyfile "${KEYFILE}" \
    --label "${label}" \
    --wait \
    --timeout "${WEALL_TX_WAIT_TIMEOUT:-30}" \
    --poll "${WEALL_TX_WAIT_POLL:-0.5}" > "${out_file}"
}

_wait_tier2_case_assigned() {
  local api="$1"
  local case_id="$2"
  local tick_api="$3"
  local attempts="${WEALL_TIER2_ASSIGN_ATTEMPTS:-6}"
  local i
  for ((i=1; i<=attempts; i++)); do
    if python3 - "${api}" "${case_id}" <<'PY_TIER2_ASSIGNED'
import json, sys, urllib.parse, urllib.request
api, case_id = sys.argv[1].rstrip('/'), sys.argv[2]
try:
    with urllib.request.urlopen(api + '/v1/poh/tier2/case/' + urllib.parse.quote(case_id, safe=''), timeout=15) as resp:
        out = json.loads(resp.read().decode('utf-8'))
except Exception:
    raise SystemExit(1)
case = out.get('case') if isinstance(out, dict) else {}
jurors = case.get('jurors') if isinstance(case, dict) else {}
status = str((case or {}).get('status') or '').lower()
if isinstance(jurors, dict) and jurors and status in {'assigned', 'reviewed', 'awarded', 'rejected'}:
    raise SystemExit(0)
raise SystemExit(1)
PY_TIER2_ASSIGNED
    then
      return 0
    fi
    echo "==> Tier-2 case ${case_id} not assigned yet; advancing system queue tick ${i}/${attempts}"
    _submit_devnet_tick "${tick_api}" "tier2-assign-${i}"
  done
  echo "ERROR: Tier-2 case was not assigned: ${case_id}" >&2
  python3 scripts/devnet_tx.py --api "${api}" tier2-case "${case_id}" || true
  exit 1
}

_wait_account_tier_at_least() {
  local api="$1"
  local account="$2"
  local min_tier="$3"
  local tick_api="$4"
  local label="$5"
  local attempts="${WEALL_TIER_WAIT_ATTEMPTS:-8}"
  local i
  for ((i=1; i<=attempts; i++)); do
    if python3 - "${api}" "${account}" "${min_tier}" <<'PY_TIER_WAIT'
import json, sys, urllib.parse, urllib.request
api, account, min_tier = sys.argv[1].rstrip('/'), sys.argv[2], int(sys.argv[3])
with urllib.request.urlopen(api + '/v1/accounts/' + urllib.parse.quote(account, safe=''), timeout=15) as resp:
    out = json.loads(resp.read().decode('utf-8'))
state = out.get('state') if isinstance(out, dict) else {}
tier = int((state or {}).get('poh_tier') or 0)
if tier >= min_tier:
    print(f'==> Verified canonical Tier-{min_tier} account state: account={account} poh_tier={tier}')
    raise SystemExit(0)
raise SystemExit(1)
PY_TIER_WAIT
    then
      return 0
    fi
    echo "==> Account ${account} has not reached Tier-${min_tier}; advancing system queue tick ${i}/${attempts}"
    _submit_devnet_tick "${tick_api}" "${label}-${i}"
  done
  echo "ERROR: account did not reach Tier-${min_tier}: ${account}" >&2
  WEALL_API="${api}" bash ./scripts/devnet_account_status.sh "${account}" || true
  exit 1
}

_run_tier2_devnet_flow() {
  local account="$1"
  local t2_out="${DEVNET_DIR}/tier2-request.json"
  local review_out="${DEVNET_DIR}/tier2-review.json"

  echo "==> Requesting Tier-2 async video PoH through node 1 normal tx flow"
  WEALL_API="${NODE1_API}" WEALL_KEYFILE="${KEYFILE}" bash ./scripts/devnet_request_tier2.sh | tee "${t2_out}"
  local case_id
  case_id="$(_json_file_field "${t2_out}" case_id)"
  local request_tx_id
  request_tx_id="$(_json_file_field "${t2_out}" tx_id)"
  if [[ -z "${case_id}" ]]; then
    echo "ERROR: Tier-2 request did not return case_id" >&2
    cat "${t2_out}" >&2
    exit 1
  fi

  _wait_tier2_case_assigned "${NODE1_API}" "${case_id}" "${NODE1_API}"

  echo "==> Submitting protocol-assigned Tier-2 juror accept + review through normal tx flow"
  WEALL_API="${NODE1_API}" WEALL_TIER2_CASE_ID="${case_id}" WEALL_TIER2_VERDICT="pass" bash ./scripts/devnet_review_tier2.sh | tee "${review_out}"
  local accept_tx_id
  local review_tx_id
  accept_tx_id="$(_json_file_field "${review_out}" accept.tx_id)"
  review_tx_id="$(_json_file_field "${review_out}" review.tx_id)"

  _wait_account_tier_at_least "${NODE1_API}" "${account}" 2 "${NODE1_API}" "tier2-finalize"

  echo "==> Syncing node 2 from node 1 after Tier-2 finalization"
  bash ./scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}"
  echo "==> Comparing node roots after Tier-2 finalization"
  bash ./scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}"
  echo "==> Verifying Tier-2 account/tx parity across nodes"
  _assert_cross_node_account_and_tx_parity "${account}" "tier2-finalization" "${request_tx_id}" "${accept_tx_id}" "${review_tx_id}"
}
_cleanup() {
  local status=$?
  if [[ -n "${NODE2_PID}" && "${KEEP_NODES}" != "1" ]]; then
    echo "==> Stopping auto-started node 2 pid=${NODE2_PID}"
    kill "${NODE2_PID}" >/dev/null 2>&1 || true
    wait "${NODE2_PID}" >/dev/null 2>&1 || true
  elif [[ -n "${NODE2_PID}" ]]; then
    echo "==> Auto-started node 2 left running pid=${NODE2_PID} log=${NODE2_LOG}"
  fi
  if [[ -n "${NODE1_PID}" && "${KEEP_NODES}" != "1" ]]; then
    echo "==> Stopping auto-started node 1 pid=${NODE1_PID}"
    kill "${NODE1_PID}" >/dev/null 2>&1 || true
    wait "${NODE1_PID}" >/dev/null 2>&1 || true
  elif [[ -n "${NODE1_PID}" ]]; then
    echo "==> Auto-started node 1 left running pid=${NODE1_PID} log=${NODE1_LOG}"
  fi
  exit "${status}"
}
trap _cleanup EXIT INT TERM

_start_node1_if_needed() {
  if _is_node_ready "${NODE1_API}"; then
    echo "==> Node 1 already reachable at ${NODE1_API}"
    return 0
  fi

  if [[ "${AUTOSTART_NODE1}" != "1" ]]; then
    echo "ERROR: node 1 is not reachable at ${NODE1_API}" >&2
    echo "Start it in another terminal with:" >&2
    echo "  cd ${REPO_ROOT}" >&2
    echo "  bash scripts/devnet_boot_genesis_node.sh" >&2
    exit 1
  fi

  if [[ "${RESET_ON_AUTOSTART}" == "1" ]]; then
    echo "==> Resetting controlled devnet state before auto-start"
    WEALL_DEVNET_DIR="${DEVNET_DIR}" bash scripts/devnet_reset_state.sh
    mkdir -p "${LOG_DIR}"
  fi

  echo "==> Node 1 not reachable at ${NODE1_API}; auto-starting genesis devnet node"
  : > "${NODE1_LOG}"
  (
    export GUNICORN_BIND="${NODE1_BIND:-127.0.0.1:8001}"
    export WEALL_DEVNET_DIR="${DEVNET_DIR}"
    export WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_BLOCK_LOOP_AUTOSTART:-1}"
    export WEALL_BLOCK_INTERVAL_MS="${WEALL_BLOCK_INTERVAL_MS:-1000}"
    export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
    export WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"
    export WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE="1"
    exec bash scripts/devnet_boot_genesis_node.sh
  ) >"${NODE1_LOG}" 2>&1 &
  NODE1_PID="$!"
  export WEALL_NODE_WAIT_LOG="${NODE1_LOG}"
  bash scripts/devnet_wait_node.sh "${NODE1_API}" "${WEALL_NODE_WAIT_TIMEOUT:-45}" "${WEALL_NODE_WAIT_POLL:-0.5}"
}

_start_node2_if_needed() {
  if _is_node_ready "${NODE2_API}"; then
    echo "==> Node 2 already reachable at ${NODE2_API}"
    return 0
  fi

  if [[ "${AUTOSTART_NODE2}" != "1" ]]; then
    echo "==> Node 2 not reachable at ${NODE2_API}; skipped cross-node root comparison"
    return 1
  fi

  echo "==> Node 2 not reachable at ${NODE2_API}; auto-starting joining devnet node"
  : > "${NODE2_LOG}"
  (
    export GUNICORN_BIND="${NODE2_BIND:-127.0.0.1:8002}"
    export WEALL_DEVNET_DIR="${DEVNET_DIR}"
    export NODE1_API="${NODE1_API}"
    export WEALL_BLOCK_LOOP_AUTOSTART="${WEALL_NODE2_BLOCK_LOOP_AUTOSTART:-1}"
    export WEALL_BLOCK_INTERVAL_MS="${WEALL_BLOCK_INTERVAL_MS:-1000}"
    export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
    export WEALL_NET_LOOP_AUTOSTART="${WEALL_NET_LOOP_AUTOSTART:-0}"
    export WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE="1"
    exec bash scripts/devnet_boot_joining_node.sh
  ) >"${NODE2_LOG}" 2>&1 &
  NODE2_PID="$!"
  export WEALL_NODE_WAIT_LOG="${NODE2_LOG}"
  bash scripts/devnet_wait_node.sh "${NODE2_API}" "${WEALL_NODE_WAIT_TIMEOUT:-45}" "${WEALL_NODE_WAIT_POLL:-0.5}"
}

_start_node1_if_needed

echo "==> Node 1 chain identity"
bash ./scripts/devnet_smoke_chain_identity.sh "${NODE1_API}"

echo "==> Creating fresh account through node 1 normal tx flow"
WEALL_API="${NODE1_API}" WEALL_KEYFILE="${KEYFILE}" WEALL_ACCOUNT="${ACCOUNT}" WEALL_DEVNET_FRESH_ACCOUNT="${FRESH_ACCOUNT}" bash ./scripts/devnet_create_account.sh

if [[ -n "${WEALL_EMAIL:-}" ]]; then
  echo "==> Requesting bounded Tier-1 email verification challenge"
  WEALL_API="${NODE1_API}" WEALL_KEYFILE="${KEYFILE}" bash ./scripts/devnet_request_email_verification.sh

  echo "==> Submitting Tier-1 email oracle attestation through normal tx flow"
  WEALL_API="${NODE1_API}" WEALL_KEYFILE="${KEYFILE}" bash ./scripts/devnet_submit_email_attestation.sh

  ACCOUNT_FROM_KEYFILE_FOR_TIER="$(_account_from_keyfile)"
  if [[ -n "${ACCOUNT_FROM_KEYFILE_FOR_TIER}" ]]; then
    python3 - "${NODE1_API}" "${ACCOUNT_FROM_KEYFILE_FOR_TIER}" <<'PY'
import json, sys, urllib.parse, urllib.request
api = sys.argv[1].rstrip('/')
account = sys.argv[2]
url = api + '/v1/accounts/' + urllib.parse.quote(account, safe='')
with urllib.request.urlopen(url, timeout=15) as resp:
    out = json.loads(resp.read().decode('utf-8'))
state = out.get('state') if isinstance(out, dict) else {}
tier = int((state or {}).get('poh_tier') or 0)
if tier < 1:
    raise SystemExit(f'Tier-1 email verification did not elevate account: account={account} poh_tier={tier}')
print(f'==> Verified canonical Tier-1 account state: account={account} poh_tier={tier}')
PY
  fi
else
  echo "==> WEALL_EMAIL not set; skipped Tier-1 email oracle attestation"
fi

if _is_node_ready "${NODE2_API}" || _start_node2_if_needed; then
  echo "==> Syncing node 2 from node 1 trusted anchor"
  bash ./scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}"
  echo "==> Comparing node roots after onboarding txs"
  bash ./scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}"

  ACCOUNT_FROM_KEYFILE_FOR_PARITY="$(_account_from_keyfile)"
  REGISTER_TX_ID="$(_keyfile_field last_account_register_tx_id)"
  EMAIL_TX_ID="$(_keyfile_field last_poh_email_receipt_tx_id)"
  if [[ -n "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}" ]]; then
    echo "==> Verifying node 2 can read the same account and tx statuses"
    _assert_cross_node_account_and_tx_parity "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}" "initial-node2-sync" "${REGISTER_TX_ID}" "${EMAIL_TX_ID}"

    NODE2_CONVERGENCE_TX_ID="$(_submit_node2_convergence_tx "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}")"
    echo "==> Syncing node 1 from node 2 after node-2-submitted tx"
    bash ./scripts/devnet_sync_from_peer.sh "${NODE2_API}" "${NODE1_API}"
    echo "==> Comparing node roots after node-2-submitted tx"
    bash ./scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}"
    echo "==> Verifying node 1 can read node-2-submitted tx and updated account state"
    _assert_cross_node_account_and_tx_parity "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}" "node2-submit-convergence" "${REGISTER_TX_ID}" "${EMAIL_TX_ID}" "${NODE2_CONVERGENCE_TX_ID}"

    if [[ "${WEALL_DEVNET_RUN_TIER2:-1}" == "1" ]]; then
      _run_tier2_devnet_flow "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}"
    else
      echo "==> WEALL_DEVNET_RUN_TIER2=0; skipped Tier-2 devnet PoH flow"
    fi
  fi
else
  echo "==> Node 2 unavailable; skipped cross-node root comparison"
fi

if [[ -f "${KEYFILE}" ]]; then
  ACCOUNT_FROM_KEYFILE="$(_account_from_keyfile)"
  if [[ -n "${ACCOUNT_FROM_KEYFILE}" ]]; then
    echo "==> Final canonical account state"
    WEALL_API="${NODE1_API}" bash ./scripts/devnet_account_status.sh "${ACCOUNT_FROM_KEYFILE}"
  fi
fi
