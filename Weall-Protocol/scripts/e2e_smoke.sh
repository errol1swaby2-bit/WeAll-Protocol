#!/usr/bin/env bash
set -euo pipefail

# scripts/e2e_smoke.sh
#
# End-to-end smoke for a single node (local):
# - boots API + block loop
# - submits ACCOUNT_REGISTER
# - waits for tx confirmation
# - verifies account is NOT "registered" for posting (PoH tier < 3)
#
# This is meant to be repeatable and human-friendly (runbook in a script).

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
need curl
need python3

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PORT="${PORT:-18000}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${PORT}}"

# Keep this DEV by default so local smoke doesn't require real key management.
WEALL_MODE="${WEALL_MODE:-dev}"
WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-0}"

CHAIN_ID="${WEALL_CHAIN_ID:-smoke-$(date +%s)}"
NODE_ID="${WEALL_NODE_ID:-@smoke-node}"
ACCOUNT="${ACCOUNT:-@smoke}"

# Fast blocks so confirmation is quick.
BLOCK_INTERVAL_MS="${WEALL_BLOCK_INTERVAL_MS:-500}"

TMP_DIR="${TMP_DIR:-$(mktemp -d)}"
DB_PATH="${WEALL_DB_PATH:-${TMP_DIR}/weall_smoke.db}"

# Ensure generated tx index exists (many endpoints depend on it).
TX_INDEX_PATH="${WEALL_TX_INDEX_PATH:-${REPO_ROOT}/generated/tx_index.json}"
if [ ! -f "$TX_INDEX_PATH" ]; then
  echo "ERROR: missing tx index at: $TX_INDEX_PATH" >&2
  echo "Hint: run the generator build step used by your repo (generated/tx_index.json)." >&2
  exit 2
fi

echo "==> Single-node E2E smoke"
echo "    BASE_URL:   $BASE_URL"
echo "    CHAIN_ID:   $CHAIN_ID"
echo "    NODE_ID:    $NODE_ID"
echo "    ACCOUNT:    $ACCOUNT"
echo "    DB_PATH:    $DB_PATH"
echo "    MODE:       $WEALL_MODE (SIGVERIFY=$WEALL_SIGVERIFY)"
echo

# Start the API server in background.
# Use 1 worker for deterministic local smoke.
echo "==> Starting API node..."
(
  export WEALL_MODE="$WEALL_MODE"
  export WEALL_SIGVERIFY="$WEALL_SIGVERIFY"
  export WEALL_CHAIN_ID="$CHAIN_ID"
  export WEALL_NODE_ID="$NODE_ID"
  export WEALL_DB_PATH="$DB_PATH"
  export WEALL_TX_INDEX_PATH="$TX_INDEX_PATH"

  export WEALL_BLOCK_LOOP_ENABLED="${WEALL_BLOCK_LOOP_ENABLED:-1}"
  export WEALL_BLOCK_INTERVAL_MS="$BLOCK_INTERVAL_MS"
  export WEALL_BLOCK_MAX_TXS="${WEALL_BLOCK_MAX_TXS:-1000}"
  export WEALL_PRODUCE_EMPTY_BLOCKS="${WEALL_PRODUCE_EMPTY_BLOCKS:-1}"

  # Keep networking disabled for this single-node smoke.
  export WEALL_NET_ENABLED="${WEALL_NET_ENABLED:-0}"
  export WEALL_BFT_ENABLED="${WEALL_BFT_ENABLED:-0}"

  exec gunicorn weall.api.app:app \
    -k uvicorn.workers.UvicornWorker \
    --bind "127.0.0.1:${PORT}" \
    --workers 1 \
    --timeout 60 \
    --graceful-timeout 30 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile -
) &
NODE_PID="$!"

cleanup() {
  echo
  echo "==> Shutting down node (pid=$NODE_PID)..."
  kill "$NODE_PID" >/dev/null 2>&1 || true
  wait "$NODE_PID" >/dev/null 2>&1 || true
  echo "==> Cleaning temp dir: $TMP_DIR"
  rm -rf "$TMP_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Wait for /v1/status
echo "==> Waiting for /v1/status..."
for i in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/v1/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

echo "==> Node is up."

# Submit ACCOUNT_REGISTER
echo "==> Submitting ACCOUNT_REGISTER for ${ACCOUNT}..."

TX_JSON="$(python3 - <<PY
import json, os
acct = os.environ.get("ACCOUNT", "@smoke")
tx = {"tx_type":"ACCOUNT_REGISTER","signer":acct,"nonce":1,"payload":{"pubkey":"k:smoke"},"sig":"","parent":None,"system":False}
print(json.dumps(tx))
PY
)"

RESP="$(curl -fsS "${BASE_URL}/v1/tx/submit" -H 'content-type: application/json' -d "$TX_JSON")"
TX_ID="$(python3 - <<PY
import json, sys
obj=json.loads(sys.argv[1])
print(obj.get("tx_id",""))
PY
"$RESP")"

if [ -z "$TX_ID" ]; then
  echo "ERROR: submit did not return tx_id"
  echo "Response: $RESP"
  exit 1
fi

echo "==> tx_id: $TX_ID"
echo "==> Waiting for confirmation..."

# Wait for tx confirmation
for i in $(seq 1 120); do
  S="$(curl -fsS "${BASE_URL}/v1/tx/status/${TX_ID}")"
  STATUS="$(python3 - <<PY
import json, sys
print(json.loads(sys.argv[1]).get("status",""))
PY
"$S")"
  if [ "$STATUS" = "confirmed" ]; then
    echo "==> Confirmed."
    break
  fi
  sleep 0.25
done

if [ "${STATUS:-}" != "confirmed" ]; then
  echo "ERROR: tx did not confirm in time."
  echo "Last status: $S"
  exit 1
fi

# Verify registered (Tier3+) is false
echo "==> Checking posting eligibility (registered=false expected)..."
R="$(curl -fsS "${BASE_URL}/v1/accounts/${ACCOUNT}/registered")"
REG="$(python3 - <<PY
import json, sys
print(str(bool(json.loads(sys.argv[1]).get("registered", False))).lower())
PY
"$R")"

if [ "$REG" != "false" ]; then
  echo "ERROR: expected registered=false, got: $R"
  exit 1
fi

echo "==> PASS: account exists but is not Tier-3 registered (as expected)."
