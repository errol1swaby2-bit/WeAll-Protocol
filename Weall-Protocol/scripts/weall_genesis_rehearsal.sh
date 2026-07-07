#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBKEY_FILE="${WEALL_GENESIS_PRODUCER_PUBKEY_FILE:-}"
PRIVKEY_FILE="${WEALL_GENESIS_PRODUCER_PRIVKEY_FILE:-}"
GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-http://127.0.0.1:8000}"
ALLOW_PRIVATE="0"
INTERVAL_MS="${WEALL_PRODUCER_INTERVAL_MS:-2000}"

usage() {
  cat <<'USAGE'
Usage: scripts/weall_genesis_rehearsal.sh --producer-pubkey-file <path> --producer-privkey-file <path> [options]

Founder/operator-only private Genesis rehearsal helper. Starts Docker Genesis API
and producer using the canonical Genesis validator key. This is not for normal
external testers and never writes secrets to the repository.

Options:
  --producer-pubkey-file <path>   Public key file matching canonical Genesis validator.
  --producer-privkey-file <path>  Private key file for that public key; never printed.
  --genesis-api-base <url>        API base to display/test; default http://127.0.0.1:8000.
  --allow-lan-genesis-api     Required for private/LAN Genesis API rehearsal.
  --producer-interval-ms <ms>     Producer interval; default 2000.
  -h, --help                      Show this help.
USAGE
}

fail() { echo "ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --producer-pubkey-file) PUBKEY_FILE="${2:-}"; shift 2 ;;
    --producer-privkey-file) PRIVKEY_FILE="${2:-}"; shift 2 ;;
    --genesis-api-base) GENESIS_API_BASE="${2:-}"; shift 2 ;;
    --allow-lan-genesis-api) ALLOW_PRIVATE="1"; shift ;;
    --producer-interval-ms) INTERVAL_MS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${PUBKEY_FILE}" && -f "${PUBKEY_FILE}" ]] || fail "producer public key file is required"
[[ -n "${PRIVKEY_FILE}" && -f "${PRIVKEY_FILE}" ]] || fail "producer private key file is required"
case "${GENESIS_API_BASE}" in
  http://127.*|http://localhost*|https://127.*|https://localhost*) ;;
  http://10.*|http://172.*|http://192.168.*) [[ "${ALLOW_PRIVATE}" == "1" ]] || fail "private Genesis API requires --allow-lan-genesis-api" ;;
  https://*) ;;
  http://*) fail "public Genesis rehearsal should use HTTPS unless --allow-lan-genesis-api is used for a private network" ;;
esac

EXPECTED_PUBKEY="$(python3 - "${ROOT_DIR}/configs/genesis.ledger.prod.json" <<'PY'
import json, sys
from pathlib import Path
ledger = json.loads(Path(sys.argv[1]).read_text())
validators = ledger.get('validators', {}).get('registry', {})
for item in validators.values():
    if isinstance(item, dict) and item.get('status') == 'active' and item.get('pubkey'):
        print(str(item['pubkey']).strip())
        raise SystemExit(0)
raise SystemExit('active genesis validator pubkey not found')
PY
)"
ACTUAL_PUBKEY="$(tr -d '[:space:]' < "${PUBKEY_FILE}")"
[[ "${ACTUAL_PUBKEY}" == "${EXPECTED_PUBKEY}" ]] || fail "producer public key does not match canonical Genesis validator"

export WEALL_NODE_PUBKEY="${ACTUAL_PUBKEY}"
export WEALL_NODE_PRIVKEY="$(tr -d '[:space:]' < "${PRIVKEY_FILE}")"
export WEALL_VALIDATOR_SIGNING_ENABLED=1
export WEALL_REQUIRE_VRF=1
export WEALL_PRODUCER_INTERVAL_MS="${INTERVAL_MS}"
export WEALL_PRODUCER_ALLOW_EMPTY=1
export WEALL_GENESIS_API_BASE="${GENESIS_API_BASE}"
[[ "${ALLOW_PRIVATE}" == "1" ]] && export WEALL_ALLOW_LAN_GENESIS_API=1

OVERRIDE="$(mktemp /tmp/weall-genesis-rehearsal.XXXXXX.yml)"
trap 'rm -f "${OVERRIDE}"' EXIT
cat > "${OVERRIDE}" <<'YAML'
services:
  weall-producer:
    environment:
      WEALL_NODE_PUBKEY: "${WEALL_NODE_PUBKEY:?WEALL_NODE_PUBKEY is required}"
      WEALL_NODE_PRIVKEY: "${WEALL_NODE_PRIVKEY:?WEALL_NODE_PRIVKEY is required}"
      WEALL_VALIDATOR_SIGNING_ENABLED: "1"
      WEALL_REQUIRE_VRF: "1"
      WEALL_PRODUCER_INTERVAL_MS: "${WEALL_PRODUCER_INTERVAL_MS:-2000}"
      WEALL_PRODUCER_ALLOW_EMPTY: "1"
YAML

cd "${ROOT_DIR}"
docker compose -f docker-compose.genesis.yml -f "${OVERRIDE}" up --build -d weall-api weall-producer
sleep 5

curl -fsS "${GENESIS_API_BASE%/}/v1/readyz" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("OK: Genesis API", "height=", d.get("height"), "tip=", d.get("tip"))'
cat <<MSG
OK: private Genesis producer rehearsal is running.
- Genesis API: ${GENESIS_API_BASE}
- producer pubkey matches canonical Genesis validator
- producer private key was supplied from local file and was not printed
- normal observers must still run without producer secrets
MSG
