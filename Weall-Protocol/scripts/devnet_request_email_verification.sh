#!/usr/bin/env bash
set -euo pipefail

# Controlled-devnet email request helper.
# Default mode is local-devnet: generate a chain-bound request id without
# contacting demo/seed routes. Set WEALL_USE_NODE_EMAIL_ORACLE=1 to call the
# node's bounded email oracle /v1/poh/email/begin route instead.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${NODE_API:-http://127.0.0.1:8001}}"
KEYFILE="${WEALL_KEYFILE:-${REPO_ROOT}/.weall-devnet/accounts/devnet-account.json}"
ACCOUNT="${WEALL_ACCOUNT:-}"
EMAIL="${WEALL_EMAIL:-}"
OUT="${WEALL_EMAIL_REQUEST_FILE:-${REPO_ROOT}/.weall-devnet/email-request.json}"

if [[ -z "${EMAIL}" ]]; then
  echo "ERROR: set WEALL_EMAIL to the address being verified." >&2
  exit 2
fi

cd "${REPO_ROOT}"
if [[ ! -f "${KEYFILE}" ]]; then
  echo "ERROR: account keyfile not found: ${KEYFILE}" >&2
  echo "Run scripts/devnet_create_account.sh first." >&2
  exit 2
fi

ACCOUNT_FROM_FILE="$(python3 - "${KEYFILE}" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
print(str(data.get('account') or '').strip())
PY
)"
ACCOUNT="${ACCOUNT:-${ACCOUNT_FROM_FILE}}"
mkdir -p "$(dirname "${OUT}")"

if [[ "${WEALL_USE_NODE_EMAIL_ORACLE:-0}" == "1" ]]; then
  python3 - "${API}" "${ACCOUNT}" "${EMAIL}" "${OUT}" <<'PY'
import json, sys, urllib.request
api, account, email, out = sys.argv[1:5]
body = json.dumps({"account": account, "email": email}).encode("utf-8")
req = urllib.request.Request(
    api.rstrip('/') + '/v1/poh/email/begin',
    data=body,
    method='POST',
    headers={"content-type": "application/json", "accept": "application/json"},
)
with urllib.request.urlopen(req, timeout=15) as resp:
    data = json.loads(resp.read().decode('utf-8'))
request_id = str(data.get('request_id') or '').strip()
if not request_id:
    raise SystemExit('node email oracle did not return request_id')
record = {"ok": True, "mode": "node_email_oracle", "api": api, "account": account, "request_id": request_id, "response": data}
with open(out, 'w', encoding='utf-8') as f:
    json.dump(record, f, indent=2, sort_keys=True)
    f.write('\n')
print(json.dumps(record, indent=2, sort_keys=True))
PY
else
  python3 - "${API}" "${ACCOUNT}" "${EMAIL}" "${OUT}" <<'PY'
import hashlib, json, sys, time, urllib.request
api, account, email, out = sys.argv[1:5]
with urllib.request.urlopen(api.rstrip('/') + '/v1/chain/identity', timeout=15) as resp:
    ident = json.loads(resp.read().decode('utf-8'))
chain_id = str(ident.get('chain_id') or '').strip()
if not chain_id:
    raise SystemExit('node did not expose chain_id')
email_norm = email.strip().lower()
material = f"{chain_id}|{account}|{email_norm}|{int(time.time() * 1000)}".encode('utf-8')
request_id = 'email:' + hashlib.sha256(material).hexdigest()[:32]
record = {
    "ok": True,
    "mode": "local_devnet_bounded_oracle_request",
    "api": api,
    "chain_id": chain_id,
    "account": account,
    "request_id": request_id,
}
with open(out, 'w', encoding='utf-8') as f:
    json.dump(record, f, indent=2, sort_keys=True)
    f.write('\n')
print(json.dumps(record, indent=2, sort_keys=True))
PY
fi
