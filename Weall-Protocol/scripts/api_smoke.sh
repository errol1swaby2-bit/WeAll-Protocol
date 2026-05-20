#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
ACCOUNT="${ACCOUNT:-alice}"

echo "==> API smoke against: ${BASE_URL}"
echo "==> Account: ${ACCOUNT}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }; }
need curl
need python3

# Wait for OpenAPI
echo "==> Waiting for API OpenAPI to be reachable..."
for i in $(seq 1 60); do
  if curl -sS "${BASE_URL}/openapi.json" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Helper: extract JSON field from stdin. Prints empty string if not found.
py_get() {
python3 - "$1" <<'PY'
import sys, json
key = sys.argv[1]
try:
    obj = json.load(sys.stdin)
except Exception:
    print("")
    sys.exit(0)
val = obj
for part in key.split("."):
    if isinstance(val, dict) and part in val:
        val = val[part]
    else:
        print("")
        sys.exit(0)
if isinstance(val, (dict, list)):
    print(json.dumps(val))
else:
    print(val)
PY
}

# Wait for nonce endpoint to return JSON
echo "==> Waiting for nonce endpoint to return JSON..."
for i in $(seq 1 60); do
  if curl -sS "${BASE_URL}/v1/account/${ACCOUNT}/nonce" | python3 -c "import sys,json; json.load(sys.stdin); print('ok')" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "==> Fetching current nonce..."
NONCE_BEFORE="$(curl -sS "${BASE_URL}/v1/account/${ACCOUNT}/nonce" | py_get nonce)"
if [[ -z "${NONCE_BEFORE}" ]]; then
  echo "ERROR: nonce endpoint returned non-JSON or missing 'nonce' field."
  echo "Raw response:"
  curl -sS "${BASE_URL}/v1/account/${ACCOUNT}/nonce" || true
  exit 1
fi
echo "==> nonce before: ${NONCE_BEFORE}"

echo "==> Fetching chain identity..."
CHAIN_ID="$(curl -sS "${BASE_URL}/v1/chain/identity" | py_get chain_id)"
if [[ -z "${CHAIN_ID}" ]]; then
  CHAIN_ID="${WEALL_CHAIN_ID:-weall-dev}"
fi
echo "==> chain id: ${CHAIN_ID}"

NEXT_NONCE=$(( NONCE_BEFORE + 1 ))

# Use a Tier0+ tx to avoid Tier gating failures (e.g., TREASURY_CREATE is Tier2+)
TX_JSON="$(cat <<JSON
{
  "tx_type": "PROFILE_UPDATE",
  "chain_id": "${CHAIN_ID}",
  "signer": "${ACCOUNT}",
  "nonce": ${NEXT_NONCE},
  "payload": {
    "display_name": "smoke-${ACCOUNT}",
    "bio": "api_smoke"
  },
  "sig": "",
  "parent": null,
  "system": false
}
JSON
)"

echo "==> Submitting public tx PROFILE_UPDATE (nonce=${NEXT_NONCE})..."

# Capture body + status code
RESP_AND_CODE="$(curl -sS -X POST "${BASE_URL}/v1/tx/submit" \
  -H "Content-Type: application/json" \
  -d "${TX_JSON}" \
  -w $'\n%{http_code}\n' || true)"

HTTP_CODE="$(echo "${RESP_AND_CODE}" | tail -n 1)"
BODY="$(echo "${RESP_AND_CODE}" | sed '$d')"

if [[ "${HTTP_CODE}" != "200" ]]; then
  echo "ERROR: /v1/tx/submit failed (HTTP ${HTTP_CODE})"
  echo "Response body:"
  echo "${BODY}"
  echo ""
  echo "Submitted tx:"
  echo "${TX_JSON}"
  exit 1
fi

OK_FIELD="$(echo "${BODY}" | python3 -c 'import sys,json; print(str(json.load(sys.stdin).get("ok","")))' 2>/dev/null || echo "")"
if [[ "${OK_FIELD}" != "True" && "${OK_FIELD}" != "true" ]]; then
  echo "ERROR: submit response ok!=true"
  echo "${BODY}"
  exit 1
fi
echo "==> public tx submit ok"

echo "==> Waiting for block loop to include the tx (nonce advances)..."

NONCE_AFTER=""
for i in $(seq 1 60); do
  NONCE_AFTER="$(curl -sS "${BASE_URL}/v1/account/${ACCOUNT}/nonce" | py_get nonce)"
  if [[ -n "${NONCE_AFTER}" ]] && (( NONCE_AFTER >= NEXT_NONCE )); then
    break
  fi
  sleep 1
done

echo "==> nonce after: ${NONCE_AFTER}"
if [[ -z "${NONCE_AFTER}" ]]; then
  echo "ERROR: failed to read nonce after."
  exit 1
fi

if (( NONCE_AFTER < NEXT_NONCE )); then
  echo "ERROR: nonce did not advance as expected."
  echo "Hint: check /v1/status -> block_loop.started and block_loop.enabled"
  curl -sS "${BASE_URL}/v1/status" || true
  exit 1
fi

echo "==> SMOKE PASSED"
