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
OPERATOR_ACCOUNT="${WEALL_GENESIS_BOOTSTRAP_ACCOUNT:-${WEALL_VALIDATOR_ACCOUNT:-@devnet-genesis}}"
OPERATOR_KEYFILE="${WEALL_GENESIS_OPERATOR_KEYFILE:-${DEVNET_DIR}/genesis-operator.json}"
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

_bool_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

activate_repo_venv() {
  if ! _bool_true "${WEALL_DEVNET_AUTO_VENV:-1}"; then
    return 0
  fi
  if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    echo "==> Using active Python virtualenv: ${VIRTUAL_ENV}"
    return 0
  fi
  local activate_path="${REPO_ROOT}/.venv/bin/activate"
  if [[ -f "${activate_path}" ]]; then
    # shellcheck disable=SC1090
    source "${activate_path}"
    echo "==> Activated Python virtualenv: ${VIRTUAL_ENV:-${REPO_ROOT}/.venv}"
    return 0
  fi
  echo "ERROR: Python virtualenv not active and ${activate_path} was not found." >&2
  echo "Run: cd ${REPO_ROOT} && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 2
}

activate_repo_venv
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

_tx_status_json() {
  local api="$1"
  local tx_id="$2"
  python3 - "${api}" "${tx_id}" <<'PY_TX_STATUS'
import json, sys, urllib.parse, urllib.request
api, tx_id = sys.argv[1].rstrip('/'), sys.argv[2]
with urllib.request.urlopen(api + '/v1/tx/status/' + urllib.parse.quote(tx_id, safe=''), timeout=15) as resp:
    raw = resp.read().decode('utf-8')
print(raw.strip() or '{}')
PY_TX_STATUS
}

_tx_status_field() {
  local file="$1"
  local field="$2"
  python3 - "${file}" "${field}" <<'PY_TX_STATUS_FIELD'
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
PY_TX_STATUS_FIELD
}

_node2_convergence_tx_id_from_file() {
  local file="$1"
  python3 - "${file}" <<'PY_NODE2_CONVERGENCE_TX_ID'
import json, sys

raw = open(sys.argv[1], 'r', encoding='utf-8').read()
decoder = json.JSONDecoder()
tx_id = ''
idx = 0
while idx < len(raw):
    while idx < len(raw) and raw[idx].isspace():
        idx += 1
    if idx >= len(raw):
        break
    try:
        obj, end = decoder.raw_decode(raw, idx)
    except json.JSONDecodeError:
        idx += 1
        continue
    if isinstance(obj, dict):
        tx_id = str(obj.get('tx_id') or '').strip()
        if tx_id:
            break
    idx = max(end, idx + 1)
print(tx_id)
PY_NODE2_CONVERGENCE_TX_ID
}

_submit_signed_tx_file_and_wait() {
  local api="$1"
  local tx_path="$2"
  local out_file="$3"
  python3 - "${api}" "${tx_path}" "${out_file}" "${WEALL_TX_WAIT_TIMEOUT:-30}" "${WEALL_TX_WAIT_POLL:-0.5}" <<'PY_SIGNED_RELAY'
import json, sys, time, urllib.parse, urllib.request
api, tx_path, out_file, timeout_s, poll_s = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
with open(tx_path, 'r', encoding='utf-8') as f:
    tx = json.load(f)
body = json.dumps(tx, sort_keys=True, separators=(',', ':')).encode('utf-8')
req = urllib.request.Request(api + '/v1/tx/submit', data=body, method='POST', headers={'content-type': 'application/json'})
with urllib.request.urlopen(req, timeout=15) as resp:
    submitted = json.loads(resp.read().decode('utf-8') or '{}')
tx_id = str(submitted.get('tx_id') or '').strip()
result = {'ok': bool(submitted.get('ok')), 'api': api, 'tx_id': tx_id, 'submit': submitted}
if tx_id:
    deadline = time.time() + timeout_s
    status = {'ok': True, 'status': 'pending', 'tx_id': tx_id}
    while time.time() <= deadline:
        url = api + '/v1/tx/status/' + urllib.parse.quote(tx_id, safe='')
        with urllib.request.urlopen(url, timeout=15) as resp:
            status = json.loads(resp.read().decode('utf-8') or '{}')
        if str(status.get('status') or '').lower() in {'confirmed', 'invalid', 'rejected', 'failed'}:
            break
        time.sleep(poll_s)
    result['tx_status'] = status
with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(result, f, sort_keys=True)
    f.write('\n')
print(json.dumps(result, sort_keys=True))
PY_SIGNED_RELAY
}

_submit_node2_convergence_tx() {
  local account="$1"
  local payload_file="${DEVNET_DIR}/node2-convergence-payload.json"
  local out_file="${DEVNET_DIR}/node2-convergence-submit.json"
  local tx_file="${DEVNET_DIR}/node2-convergence.signed-tx.json"
  local relay_out_file="${DEVNET_DIR}/node2-convergence-relay-submit.json"
  local node2_status_file="${DEVNET_DIR}/node2-convergence-status.json"
  mkdir -p "${DEVNET_DIR}"

  local tx_type
  local label
  if [[ -n "${WEALL_EMAIL:-}" ]]; then
    tx_type="FOLLOW_SET"
    label="Tier-1-gated FOLLOW_SET"
    python3 - "${payload_file}" <<'PY_NODE2_FOLLOW_PAYLOAD'
import json, sys
payload = {"target": "@devnet-genesis", "active": True}
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    json.dump(payload, f, sort_keys=True)
PY_NODE2_FOLLOW_PAYLOAD
  else
    tx_type="PROFILE_UPDATE"
    label="Tier-0 PROFILE_UPDATE"
    python3 - "${payload_file}" <<'PY_NODE2_PROFILE_PAYLOAD'
import json, sys, time
payload = {"bio": "controlled devnet edge convergence " + str(int(time.time() * 1000))}
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    json.dump(payload, f, sort_keys=True)
PY_NODE2_PROFILE_PAYLOAD
  fi

  if [[ "${tx_type}" == "FOLLOW_SET" ]]; then
    echo "==> Submitting Tier-1-gated FOLLOW_SET through node 2 normal tx flow" >&2
  else
    echo "==> Submitting Tier-0 PROFILE_UPDATE through node 2 normal tx flow" >&2
  fi
  WEALL_KEYFILE="${KEYFILE}" bash ./scripts/devnet_submit_tx_node2.sh \
    --keyfile "${KEYFILE}" \
    --tx-type "${tx_type}" \
    --payload-json "@${payload_file}" \
    --tx-out "${tx_file}" \
    --wait \
    --timeout "${WEALL_NODE2_CONVERGENCE_WAIT_TIMEOUT:-5}" \
    --poll "${WEALL_TX_WAIT_POLL:-0.5}" > "${out_file}"
  cat "${out_file}" >&2

  local tx_id
  tx_id="$(_node2_convergence_tx_id_from_file "${out_file}")"
  local status
  status="$(_tx_status_field "${out_file}" tx_status.status)"
  if [[ -z "${tx_id}" ]]; then
    echo "ERROR: node2 convergence tx missing tx_id" >&2
    cat "${out_file}" >&2
    exit 1
  fi

  if [[ "${status}" == "confirmed" ]]; then
    echo "==> Node 2 confirmed convergence tx locally; Syncing node 1 from node 2 after node-2-submitted tx" >&2
    bash ./scripts/devnet_sync_from_peer.sh "${NODE2_API}" "${NODE1_API}" >&2
    echo "==> Comparing node roots after node-2-submitted tx" >&2
    bash ./scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}" >&2
    printf '%s\n' "${tx_id}"
    return 0
  fi

  echo "==> Node 2 accepted convergence tx but did not confirm it locally; relaying exact signed tx to canonical producer" >&2
  _submit_signed_tx_file_and_wait "${NODE1_API}" "${tx_file}" "${relay_out_file}" >&2
  local relay_status
  relay_status="$(_tx_status_field "${relay_out_file}" tx_status.status)"
  if [[ "${relay_status}" != "confirmed" ]]; then
    echo "ERROR: relayed node2-signed convergence tx was not confirmed by node 1: status=${relay_status}" >&2
    cat "${relay_out_file}" >&2
    exit 1
  fi

  _tx_status_json "${NODE2_API}" "${tx_id}" > "${node2_status_file}" || true
  echo "==> Syncing node 2 from node 1 after edge relay confirmation" >&2
  bash ./scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}" >&2
  echo "==> Comparing node roots after edge-relayed node-2-submitted tx" >&2
  bash ./scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}" >&2
  printf '%s\n' "${tx_id}"
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

_wait_tier3_case_assigned() {
  local api="$1"
  local case_id="$2"
  local tick_api="$3"
  local attempts="${WEALL_TIER3_ASSIGN_ATTEMPTS:-10}"
  local i
  for ((i=1; i<=attempts; i++)); do
    if python3 - "${api}" "${case_id}" <<'PY_TIER3_ASSIGNED'
import json, sys, urllib.parse, urllib.request
api, case_id = sys.argv[1].rstrip('/'), sys.argv[2]
try:
    with urllib.request.urlopen(api + '/v1/poh/tier3/case/' + urllib.parse.quote(case_id, safe=''), timeout=15) as resp:
        out = json.loads(resp.read().decode('utf-8'))
except Exception:
    raise SystemExit(1)
case = out.get('case') if isinstance(out, dict) else {}
jurors = case.get('jurors') if isinstance(case, dict) else []
status = str((case or {}).get('status') or '').lower()
session_commitment = str((case or {}).get('session_commitment') or '').strip()
if isinstance(jurors, list) and len(jurors) == 10 and status in {'init', 'open', 'awarded', 'rejected'} and session_commitment:
    raise SystemExit(0)
raise SystemExit(1)
PY_TIER3_ASSIGNED
    then
      return 0
    fi
    echo "==> Tier-3 case ${case_id} not ready yet; advancing system queue tick ${i}/${attempts}"
    _submit_devnet_tick "${tick_api}" "tier3-assign-${i}"
  done
  echo "ERROR: Tier-3 case was not initialized/assigned: ${case_id}" >&2
  python3 scripts/devnet_tx.py --api "${api}" tier3-case "${case_id}" || true
  exit 1
}

_tier3_juror_keyfile() {
  local juror="$1"
  if [[ "${juror}" == "${OPERATOR_ACCOUNT}" ]]; then
    echo "${OPERATOR_KEYFILE}"
    return 0
  fi
  local prefix="${WEALL_TIER3_JUROR_PREFIX:-@devnet-tier3-juror-}"
  local key_prefix="${WEALL_TIER3_JUROR_KEY_PREFIX:-tier3-juror-}"
  if [[ "${juror}" == "${prefix}"* ]]; then
    local suffix="${juror#${prefix}}"
    echo "${DEVNET_DIR}/accounts/${key_prefix}${suffix}.json"
    return 0
  fi
  echo "ERROR: no controlled-devnet keyfile mapping for assigned Tier-3 juror ${juror}" >&2
  return 1
}

_tier3_case_juror_lines() {
  local api="$1"
  local case_id="$2"
  python3 - "${api}" "${case_id}" <<'PY_TIER3_JUROR_LINES'
import json, sys, urllib.parse, urllib.request
api, case_id = sys.argv[1].rstrip('/'), sys.argv[2]
with urllib.request.urlopen(api + '/v1/poh/tier3/case/' + urllib.parse.quote(case_id, safe=''), timeout=15) as resp:
    out = json.loads(resp.read().decode('utf-8'))
case = out.get('case') if isinstance(out, dict) else {}
for j in case.get('jurors') or []:
    if not isinstance(j, dict):
        continue
    jid = str(j.get('juror_id') or '').strip()
    role = str(j.get('role') or '').strip()
    if jid and role:
        print(jid + '\t' + role)
PY_TIER3_JUROR_LINES
}

_run_tier3_devnet_flow() {
  local account="$1"
  local t3_out="${DEVNET_DIR}/tier3-request.json"
  local review_dir="${DEVNET_DIR}/tier3-reviews"
  mkdir -p "${review_dir}"

  echo "==> Preparing 10 controlled-devnet Tier-3 reviewer accounts through normal tx flow"
  WEALL_API="${NODE1_API}" WEALL_DEVNET_DIR="${DEVNET_DIR}" bash ./scripts/devnet_prepare_tier3_jurors.sh

  echo "==> Requesting protocol-native Tier-3 live PoH through node 1 normal tx flow"
  WEALL_API="${NODE1_API}" WEALL_KEYFILE="${KEYFILE}" bash ./scripts/devnet_request_tier3.sh | tee "${t3_out}"
  local case_id
  case_id="$(_json_file_field "${t3_out}" case_id)"
  local request_tx_id
  request_tx_id="$(_json_file_field "${t3_out}" tx_id)"
  if [[ -z "${case_id}" ]]; then
    echo "ERROR: Tier-3 request did not return case_id" >&2
    cat "${t3_out}" >&2
    exit 1
  fi

  _wait_tier3_case_assigned "${NODE1_API}" "${case_id}" "${NODE1_API}"

  echo "==> Submitting assigned Tier-3 reviewer attendance/verdict txs through normal tx flow"
  while IFS=$'\t' read -r juror role; do
    [[ -n "${juror}" ]] || continue
    local juror_keyfile
    juror_keyfile="$(_tier3_juror_keyfile "${juror}")"
    local safe_juror
    safe_juror="$(printf '%s' "${juror}" | tr -c 'A-Za-z0-9_.@-' '_')"
    local out_file="${review_dir}/${safe_juror}.json"
    if [[ "${role}" == "interacting" ]]; then
      WEALL_API="${NODE1_API}" WEALL_TIER3_CASE_ID="${case_id}" WEALL_TIER3_JUROR_ACCOUNT="${juror}" WEALL_TIER3_JUROR_KEYFILE="${juror_keyfile}" WEALL_TIER3_VERDICT="pass" \
        bash ./scripts/devnet_review_tier3.sh | tee "${out_file}"
    else
      WEALL_API="${NODE1_API}" WEALL_TIER3_CASE_ID="${case_id}" WEALL_TIER3_JUROR_ACCOUNT="${juror}" WEALL_TIER3_JUROR_KEYFILE="${juror_keyfile}" WEALL_TIER3_SUBMIT_VERDICT="0" \
        bash ./scripts/devnet_review_tier3.sh | tee "${out_file}"
    fi
  done < <(_tier3_case_juror_lines "${NODE1_API}" "${case_id}")

  echo "==> Tier-3 live session state after reviewer attestations"
  WEALL_API="${NODE1_API}" WEALL_TIER3_CASE_ID="${case_id}" bash ./scripts/devnet_tier3_session.sh

  _wait_account_tier_at_least "${NODE1_API}" "${account}" 3 "${NODE1_API}" "tier3-finalize"

  echo "==> Syncing node 2 from node 1 after Tier-3 finalization"
  bash ./scripts/devnet_sync_from_peer.sh "${NODE1_API}" "${NODE2_API}"
  echo "==> Comparing node roots after Tier-3 finalization"
  bash ./scripts/devnet_compare_state_roots.sh "${NODE1_API}" "${NODE2_API}"
  echo "==> Verifying Tier-3 account/tx parity across nodes"
  _assert_cross_node_account_and_tx_parity "${account}" "tier3-finalization" "${request_tx_id}"
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
    echo "==> Verifying both nodes can read node-2-submitted tx and updated account state"
    _assert_cross_node_account_and_tx_parity "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}" "node2-submit-convergence" "${REGISTER_TX_ID}" "${EMAIL_TX_ID}" "${NODE2_CONVERGENCE_TX_ID}"

    if [[ "${WEALL_DEVNET_RUN_TIER2:-1}" == "1" ]]; then
      _run_tier2_devnet_flow "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}"
      if [[ "${WEALL_DEVNET_RUN_TIER3:-0}" == "1" ]]; then
        _run_tier3_devnet_flow "${ACCOUNT_FROM_KEYFILE_FOR_PARITY}"
      else
        echo "==> WEALL_DEVNET_RUN_TIER3=0; skipped Tier-3 devnet PoH flow"
      fi
    else
      echo "==> WEALL_DEVNET_RUN_TIER2=0; skipped Tier-2 devnet PoH flow"
      if [[ "${WEALL_DEVNET_RUN_TIER3:-0}" == "1" ]]; then
        echo "ERROR: WEALL_DEVNET_RUN_TIER3=1 requires WEALL_DEVNET_RUN_TIER2=1 in this full onboarding harness" >&2
        exit 1
      fi
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
