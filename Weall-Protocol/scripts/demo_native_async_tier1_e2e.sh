#!/usr/bin/env bash
set -euo pipefail

# Fresh-demo native async Tier-1 verification proof.
# This harness uses normal public tx submission for applicant and juror actions.
# System-owned assignment/finalize/receipt are produced by the deterministic
# native async PoH scheduler during block production.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${NODE1_API:-http://127.0.0.1:8001}}"
DEVNET_DIR="${WEALL_DEVNET_DIR:-${ROOT}/.weall-devnet}"
KEYFILE="${WEALL_KEYFILE:-${DEVNET_DIR}/accounts/native-async-applicant.json}"
ACCOUNT="${WEALL_ACCOUNT:-}"
ASYNC_JUROR_COUNT="${WEALL_ASYNC_JUROR_COUNT:-${WEALL_POH_ASYNC_N_JURORS:-1}}"
ASYNC_JUROR_PREFIX="${WEALL_LIVE_JUROR_PREFIX:-@devnet-live-juror-}"
ASYNC_JUROR_KEY_PREFIX="${WEALL_LIVE_JUROR_KEY_PREFIX:-live-juror-}"
WAIT_TIMEOUT="${WEALL_NATIVE_ASYNC_WAIT_TIMEOUT:-300}"
POLL="${WEALL_NATIVE_ASYNC_WAIT_POLL:-1}"
CREATE_ACCOUNT="${WEALL_NATIVE_ASYNC_CREATE_ACCOUNT:-1}"

mkdir -p "${DEVNET_DIR}/accounts"
cd "${ROOT}"

_json_get() {
  local path="$1"
  local key="$2"
  /usr/bin/env python3 - "$path" "$key" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(path, encoding='utf-8'))
except Exception:
    data = {}
print(str(data.get(key) or '').strip())
PY
}

_account_state_json() {
  local account="$1"
  /usr/bin/env python3 - "$API" "$account" <<'PY'
import json, sys, urllib.parse, urllib.request
api, account = sys.argv[1].rstrip('/'), sys.argv[2]
url = api + '/v1/accounts/' + urllib.parse.quote(account, safe='')
try:
    with urllib.request.urlopen(url, timeout=15) as resp:
        out = json.loads(resp.read().decode('utf-8'))
except Exception:
    print('{}')
    raise SystemExit(0)
state = out.get('state') if isinstance(out, dict) else {}
print(json.dumps(state if isinstance(state, dict) else {}, sort_keys=True))
PY
}

_account_registered() {
  local account="$1"
  _account_state_json "$account" | /usr/bin/env python3 -c "import json,sys; s=json.load(sys.stdin); print('1' if (s.get('pubkey') or s.get('pubkeys') or s.get('keys') or s.get('active_keys')) else '0')"
}

_account_tier() {
  local account="$1"
  _account_state_json "$account" | /usr/bin/env python3 -c "import json,sys; s=json.load(sys.stdin); print(int(s.get('poh_tier') or 0))"
}

_wait_case_predicate() {
  local case_id="$1"
  local mode="$2"
  /usr/bin/env python3 - "$API" "$case_id" "$mode" "$WAIT_TIMEOUT" "$POLL" <<'PY'
import json, sys, time, urllib.parse, urllib.request
api, case_id, mode, timeout_s, poll_s = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3], float(sys.argv[4]), float(sys.argv[5])
deadline = time.time() + timeout_s
last = {}
while True:
    try:
        url = api + '/v1/poh/async/case/' + urllib.parse.quote(case_id, safe='')
        with urllib.request.urlopen(url, timeout=15) as resp:
            out = json.loads(resp.read().decode('utf-8'))
        case = out.get('case') if isinstance(out, dict) else {}
        last = case if isinstance(case, dict) else {}
    except Exception as exc:
        last = {'error': str(exc)}
    ok = False
    if mode == 'assigned':
        assigned = [j for j in last.get('assigned_jurors', []) if str(j).strip()]
        try:
            expected = int(last.get('assigned_juror_count') or last.get('configured_assigned_juror_count') or 1)
        except Exception:
            expected = 1
        ok = len(assigned) >= max(1, expected)
    elif mode == 'approved':
        ok = str(last.get('outcome') or '').lower() == 'approved' and int(last.get('tier_awarded') or 0) >= 1
    elif mode == 'receipt':
        ok = bool(last.get('receipt')) or bool(last.get('receipt_id'))
    if ok:
        print(json.dumps({'ok': True, 'case': last}, indent=2, sort_keys=True))
        raise SystemExit(0)
    if time.time() >= deadline:
        print(json.dumps({'ok': False, 'timed_out': True, 'case': last}, indent=2, sort_keys=True))
        raise SystemExit(2)
    time.sleep(max(0.1, poll_s))
PY
}

_wait_account_tier1() {
  local account="$1"
  /usr/bin/env python3 - "$API" "$account" "$WAIT_TIMEOUT" "$POLL" <<'PY'
import json, sys, time, urllib.parse, urllib.request
api, account, timeout_s, poll_s = sys.argv[1].rstrip('/'), sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
deadline = time.time() + timeout_s
last = {}
while True:
    try:
        url = api + '/v1/accounts/' + urllib.parse.quote(account, safe='')
        with urllib.request.urlopen(url, timeout=15) as resp:
            out = json.loads(resp.read().decode('utf-8'))
        state = out.get('state') if isinstance(out, dict) else {}
        last = state if isinstance(state, dict) else {}
    except Exception as exc:
        last = {'error': str(exc)}
    try:
        if int(last.get('poh_tier') or 0) >= 1:
            print(json.dumps({'ok': True, 'account': account, 'state': last}, indent=2, sort_keys=True))
            raise SystemExit(0)
    except Exception:
        pass
    if time.time() >= deadline:
        print(json.dumps({'ok': False, 'timed_out': True, 'account': account, 'state': last}, indent=2, sort_keys=True))
        raise SystemExit(2)
    time.sleep(max(0.1, poll_s))
PY
}

_juror_keyfile_for_account() {
  local juror="$1"
  if [[ "$juror" == "${ASYNC_JUROR_PREFIX}"* ]]; then
    local suffix="${juror#${ASYNC_JUROR_PREFIX}}"
    echo "${DEVNET_DIR}/accounts/${ASYNC_JUROR_KEY_PREFIX}${suffix}.json"
    return 0
  fi
  if [[ "$juror" == "${WEALL_GENESIS_BOOTSTRAP_ACCOUNT:-@devnet-genesis}" ]]; then
    echo "${WEALL_GENESIS_OPERATOR_KEYFILE:-${DEVNET_DIR}/genesis-operator.json}"
    return 0
  fi
  echo "${DEVNET_DIR}/accounts/${juror//@/}.json"
}

_submit() {
  local account="$1"
  local keyfile="$2"
  local tx_type="$3"
  local payload="$4"
  python3 scripts/devnet_tx.py --api "$API" submit-tx \
    --account "$account" \
    --keyfile "$keyfile" \
    --tx-type "$tx_type" \
    --payload-json "$payload" \
    --wait
}

if [[ "$CREATE_ACCOUNT" == "1" ]]; then
  if [[ -f "$KEYFILE" ]]; then
    ACCOUNT="${ACCOUNT:-$(_json_get "$KEYFILE" account)}"
  fi
  if [[ -z "$ACCOUNT" || "$(_account_registered "$ACCOUNT")" != "1" ]]; then
    echo "==> Creating fresh async applicant account"
    WEALL_API="$API" WEALL_KEYFILE="$KEYFILE" WEALL_ACCOUNT="$ACCOUNT" bash scripts/devnet_create_account.sh >/dev/null
  fi
fi

ACCOUNT="${ACCOUNT:-$(_json_get "$KEYFILE" account)}"
if [[ -z "$ACCOUNT" ]]; then
  echo "ERROR: missing applicant account; set WEALL_ACCOUNT or provide WEALL_KEYFILE" >&2
  exit 1
fi

initial_tier="$(_account_tier "$ACCOUNT")"
echo "==> Applicant ${ACCOUNT} initial poh_tier=${initial_tier}"
if [[ "$initial_tier" =~ ^[0-9]+$ && "$initial_tier" -ge 1 ]]; then
  echo "==> Applicant is already Verified Person; skipping native async flow"
  exit 0
fi

echo "==> Preparing ${ASYNC_JUROR_COUNT} Live Verified reviewer accounts"
WEALL_API="$API" WEALL_LIVE_JUROR_COUNT="$ASYNC_JUROR_COUNT" WEALL_LIVE_JUROR_PREFIX="$ASYNC_JUROR_PREFIX" WEALL_LIVE_JUROR_KEY_PREFIX="$ASYNC_JUROR_KEY_PREFIX" \
  bash scripts/devnet_prepare_live_jurors.sh

stamp="$(/usr/bin/env python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
)"
case_id="${WEALL_NATIVE_ASYNC_CASE_ID:-pohasync:${ACCOUNT}:${stamp}}"
evidence_id="async-evidence:${stamp}"
challenge_id="prompt:${stamp}"
challenge_commitment="sha256:$(printf '%s' "weall:native-async:challenge:${ACCOUNT}:${challenge_id}" | sha256sum | awk '{print $1}')"
response_commitment="sha256:$(printf '%s' "weall:native-async:response:${ACCOUNT}:${case_id}" | sha256sum | awk '{print $1}')"
evidence_commitment="sha256:$(printf '%s' "weall:native-async:evidence:${ACCOUNT}:${case_id}" | sha256sum | awk '{print $1}')"

echo "==> Opening native async Tier-1 case ${case_id}"
_submit "$ACCOUNT" "$KEYFILE" "POH_ASYNC_REQUEST_OPEN" \
  "{\"account_id\":\"${ACCOUNT}\",\"case_id\":\"${case_id}\",\"challenge_id\":\"${challenge_id}\",\"challenge_commitment\":\"${challenge_commitment}\",\"response_commitment\":\"${response_commitment}\",\"note\":\"fresh_demo_native_async_tier1\",\"ts_ms\":0}" >/dev/null

_submit "$ACCOUNT" "$KEYFILE" "POH_ASYNC_EVIDENCE_DECLARE" \
  "{\"case_id\":\"${case_id}\",\"evidence_id\":\"${evidence_id}\",\"evidence_commitment\":\"${evidence_commitment}\",\"response_commitment\":\"${response_commitment}\",\"kind\":\"fresh_demo_commitment_v1\",\"ts_ms\":0}" >/dev/null

_submit "$ACCOUNT" "$KEYFILE" "POH_ASYNC_EVIDENCE_BIND" \
  "{\"case_id\":\"${case_id}\",\"evidence_id\":\"${evidence_id}\",\"target_id\":\"${case_id}\",\"ts_ms\":0}" >/dev/null

echo "==> Waiting for deterministic native async juror assignment"
assigned_json="$(_wait_case_predicate "$case_id" assigned)"
echo "$assigned_json"

mapfile -t jurors < <(ASSIGNED_JSON="$assigned_json" /usr/bin/env python3 - <<'PY'
import json, os
out = json.loads(os.environ.get("ASSIGNED_JSON") or "{}")
case = out.get("case") if isinstance(out, dict) else {}
for juror in case.get("assigned_jurors", []):
    juror = str(juror).strip()
    if juror:
        print(juror)
PY
)
if [[ "${#jurors[@]}" -lt 1 ]]; then
  echo "ERROR: expected at least 1 assigned juror, got ${#jurors[@]}" >&2
  exit 1
fi

echo "==> Accepting and voting native async verification case"
for idx in "${!jurors[@]}"; do
  juror="${jurors[$idx]}"
  keyfile="$(_juror_keyfile_for_account "$juror")"
  if [[ ! -f "$keyfile" ]]; then
    echo "ERROR: missing keyfile for assigned juror ${juror}: ${keyfile}" >&2
    exit 1
  fi
  _submit "$juror" "$keyfile" "POH_ASYNC_JUROR_ACCEPT" "{\"case_id\":\"${case_id}\"}" >/dev/null
  verdict="approve"
  _submit "$juror" "$keyfile" "POH_ASYNC_REVIEW_SUBMIT" "{\"case_id\":\"${case_id}\",\"verdict\":\"${verdict}\",\"reason_code\":\"fresh_demo_review\",\"ts_ms\":0}" >/dev/null
  echo "==> Juror ${juror} submitted ${verdict}"
done

echo "==> Waiting for native async finalization and Tier-1 account state"
_wait_case_predicate "$case_id" approved
_wait_account_tier1 "$ACCOUNT"
_wait_case_predicate "$case_id" receipt || true

echo "==> Native async Tier-1 flow complete: ${ACCOUNT} is Verified Person via ${case_id}"
