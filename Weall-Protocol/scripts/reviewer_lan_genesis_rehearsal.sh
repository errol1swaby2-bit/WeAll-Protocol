#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

API_PORT="${WEALL_REVIEWER_API_PORT:-8000}"
FRONTEND_PORT="${WEALL_REVIEWER_FRONTEND_PORT:-5173}"
WORK_DIR="${WEALL_REVIEWER_WORK_DIR:-/tmp/weall-reviewer-lan-genesis}"
PUBLIC_DIR="${WEALL_REVIEWER_PUBLIC_ARTIFACTS_DIR:-${WORK_DIR}/public}"
BUNDLE_OUT="${WEALL_REVIEWER_BUNDLE_OUT:-${PUBLIC_DIR}/weall-external-observer-bundle.json}"
PUBLIC_MANIFEST_OUT="${WEALL_REVIEWER_PUBLIC_MANIFEST_OUT:-${PUBLIC_DIR}/reviewer-chain-manifest.json}"
ARTIFACT_INDEX_OUT="${WEALL_REVIEWER_ARTIFACT_INDEX_OUT:-${PUBLIC_DIR}/artifact-index.json}"
AUTHORITY_URL="${WEALL_REVIEWER_AUTHORITY_URL:-https://weall-rehearsal-authority.invalid}"
NO_BOOT="${WEALL_REVIEWER_GENESIS_NO_BOOT:-0}"
HEIGHT_WAIT_SECONDS="${WEALL_REVIEWER_HEIGHT_WAIT_SECONDS:-75}"
CHAIN_ID="${WEALL_REVIEWER_CHAIN_ID:-weall-reviewer-lan}"
ACCOUNT="${WEALL_REVIEWER_GENESIS_ACCOUNT:-@reviewer-genesis}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/reviewer_lan_genesis_rehearsal.sh [options]

Options:
  --lan-ip <ip>              LAN IP reviewers/observers should use.
  --wsl-ip <ip>              WSL IP used for Windows port forwarding.
  --api-port <port>          Genesis API port. Default: 8000.
  --frontend-port <port>     Frontend port used for CORS. Default: 5173.
  --work-dir <path>          Local disposable reviewer chain directory.
  --public-dir <path>        Directory containing public observer artifacts.
  --bundle-out <path>        Public observer bundle output path.
  --chain-id <id>            Disposable reviewer chain id.
  --account <account>        Disposable reviewer Genesis account.
  --authority-url <url>      HTTPS public authority metadata URL.
  --height-wait-seconds <n>  Seconds to wait for height to advance.
  --no-boot                  Prepare files and print commands, but do not boot Genesis.
  -h, --help                 Show this help.

Purpose:
  Prepare a reviewer-friendly LAN Genesis API using a disposable reviewer chain,
  publish public reviewer artifacts, boot Genesis with generated local-only keys,
  and wait for block height to advance before printing the observer command.

Truth boundary:
  Disposable reviewer rehearsal chain only. This is not canonical production
  Genesis, not public mainnet readiness, and not public multi-validator BFT.
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

truthy() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

LAN_IP="${WEALL_REVIEWER_LAN_IP:-}"
WSL_IP="${WEALL_REVIEWER_WSL_IP:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lan-ip) LAN_IP="${2:-}"; shift 2 ;;
    --wsl-ip) WSL_IP="${2:-}"; shift 2 ;;
    --api-port) API_PORT="${2:-}"; shift 2 ;;
    --frontend-port) FRONTEND_PORT="${2:-}"; shift 2 ;;
    --work-dir)
      WORK_DIR="${2:-}"
      PUBLIC_DIR="${WEALL_REVIEWER_PUBLIC_ARTIFACTS_DIR:-${WORK_DIR}/public}"
      BUNDLE_OUT="${WEALL_REVIEWER_BUNDLE_OUT:-${PUBLIC_DIR}/weall-external-observer-bundle.json}"
      PUBLIC_MANIFEST_OUT="${WEALL_REVIEWER_PUBLIC_MANIFEST_OUT:-${PUBLIC_DIR}/reviewer-chain-manifest.json}"
      ARTIFACT_INDEX_OUT="${WEALL_REVIEWER_ARTIFACT_INDEX_OUT:-${PUBLIC_DIR}/artifact-index.json}"
      shift 2
      ;;
    --public-dir)
      PUBLIC_DIR="${2:-}"
      BUNDLE_OUT="${WEALL_REVIEWER_BUNDLE_OUT:-${PUBLIC_DIR}/weall-external-observer-bundle.json}"
      PUBLIC_MANIFEST_OUT="${WEALL_REVIEWER_PUBLIC_MANIFEST_OUT:-${PUBLIC_DIR}/reviewer-chain-manifest.json}"
      ARTIFACT_INDEX_OUT="${WEALL_REVIEWER_ARTIFACT_INDEX_OUT:-${PUBLIC_DIR}/artifact-index.json}"
      shift 2
      ;;
    --bundle-out) BUNDLE_OUT="${2:-}"; shift 2 ;;
    --chain-id) CHAIN_ID="${2:-}"; shift 2 ;;
    --account) ACCOUNT="${2:-}"; shift 2 ;;
    --authority-url) AUTHORITY_URL="${2:-}"; shift 2 ;;
    --height-wait-seconds) HEIGHT_WAIT_SECONDS="${2:-}"; shift 2 ;;
    --no-boot) NO_BOOT="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

if [[ -z "${WSL_IP}" ]]; then
  WSL_IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -n 1 || true)"
fi

if [[ -z "${LAN_IP}" ]] && command -v powershell.exe >/dev/null 2>&1; then
  LAN_IP="$(powershell.exe -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.IPAddress -notlike '127.*' -and \$_.IPAddress -notlike '169.254*' -and \$_.InterfaceAlias -notlike 'vEthernet*' } | Select-Object -First 1 -ExpandProperty IPAddress" 2>/dev/null | tr -d '\r' | head -n 1 || true)"
fi

if [[ -z "${LAN_IP}" ]]; then
  LAN_IP="$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -n 1 || true)"
fi

[[ -n "${LAN_IP}" ]] || fail "LAN IP could not be detected; pass --lan-ip <ip>"
[[ -n "${WSL_IP}" ]] || fail "WSL/local IP could not be detected; pass --wsl-ip <ip>"

GENESIS_API_BASE="http://${LAN_IP}:${API_PORT}"
LOCAL_API_BASE="http://127.0.0.1:${API_PORT}"

if [[ -f ".venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate
fi

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}" "${PUBLIC_DIR}"

echo "[reviewer-genesis] Building disposable reviewer Genesis chain in ${WORK_DIR}"

python3 scripts/build_reviewer_lan_genesis.py \
  --out-dir "${WORK_DIR}" \
  --chain-id "${CHAIN_ID}" \
  --account "${ACCOUNT}" \
  --force | tee "${WORK_DIR}/build-summary.json"

MANIFEST_PATH="$(python3 - "${WORK_DIR}/build-summary.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(obj["manifest_path"])
PY
)"

LEDGER_PATH="$(python3 - "${WORK_DIR}/build-summary.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(obj["ledger_path"])
PY
)"

ENV_PATH="$(python3 - "${WORK_DIR}/build-summary.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(obj["env_path"])
PY
)"

[[ -f "${MANIFEST_PATH}" ]] || fail "generated manifest not found: ${MANIFEST_PATH}"
[[ -f "${LEDGER_PATH}" ]] || fail "generated ledger not found: ${LEDGER_PATH}"
[[ -f "${ENV_PATH}" ]] || fail "generated env not found: ${ENV_PATH}"

if command -v powershell.exe >/dev/null 2>&1; then
  cat <<MSG

[reviewer-genesis] Windows/WSL detected.

Run this once in Windows PowerShell as Administrator if another machine cannot reach ${GENESIS_API_BASE}:

  \$listenIp = "${LAN_IP}"
  \$wslIp = "${WSL_IP}"
  netsh interface portproxy delete v4tov4 listenaddress=\$listenIp listenport=${API_PORT}
  netsh interface portproxy add v4tov4 listenaddress=\$listenIp listenport=${API_PORT} connectaddress=\$wslIp connectport=${API_PORT}
  if (-not (Get-NetFirewallRule -DisplayName "WeAll Reviewer Genesis API ${API_PORT}" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "WeAll Reviewer Genesis API ${API_PORT}" -Direction Inbound -Action Allow -Protocol TCP -LocalPort ${API_PORT}
  }
  netsh interface portproxy show all

MSG
fi

echo "[reviewer-genesis] Building public observer bundle with sanitized environment"

env \
  -u WEALL_VALIDATOR_ACCOUNT \
  -u WEALL_VALIDATOR_ACCOUNT_FILE \
  -u WEALL_VALIDATOR_PRIVKEY \
  -u WEALL_VALIDATOR_PRIVKEY_FILE \
  -u WEALL_NODE_PRIVKEY \
  -u WEALL_NODE_PRIVKEY_FILE \
  -u WEALL_AUTHORITY_SIGNER_PRIVKEY \
  -u WEALL_AUTHORITY_SIGNER_PRIVKEY_FILE \
  -u WEALL_AUTHORITY_PRIVKEY \
  -u WEALL_AUTHORITY_PRIVKEY_FILE \
  python3 scripts/build_external_observer_bundle.py \
    --manifest "${MANIFEST_PATH}" \
    --genesis-api-base "${GENESIS_API_BASE}" \
    --authority-url "${AUTHORITY_URL}" \
    --out "${BUNDLE_OUT}"

cp "${MANIFEST_PATH}" "${PUBLIC_MANIFEST_OUT}"

python3 - "${PUBLIC_DIR}" "${BUNDLE_OUT}" "${PUBLIC_MANIFEST_OUT}" "${ARTIFACT_INDEX_OUT}" "${GENESIS_API_BASE}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

public_dir = Path(sys.argv[1]).resolve()
bundle_path = Path(sys.argv[2]).resolve()
manifest_path = Path(sys.argv[3]).resolve()
index_path = Path(sys.argv[4]).resolve()
genesis_api_base = sys.argv[5].rstrip("/")

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

obj = {
    "ok": True,
    "type": "weall_reviewer_public_artifact_index",
    "version": 1,
    "truth_boundary": (
        "Disposable reviewer rehearsal artifacts only. Public bundle and manifest "
        "may be downloaded by observers. Local env, private keys, ledgers, and DBs "
        "must not be exposed."
    ),
    "genesis_api_base": genesis_api_base,
    "public_dir": str(public_dir),
    "artifacts": {
        "bundle": {
            "filename": bundle_path.name,
            "url": "/v1/reviewer/artifacts/bundle",
            "sha256": digest(bundle_path),
            "bytes": bundle_path.stat().st_size,
        },
        "manifest": {
            "filename": manifest_path.name,
            "url": "/v1/reviewer/artifacts/manifest",
            "sha256": digest(manifest_path),
            "bytes": manifest_path.stat().st_size,
        },
    },
}
index_path.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY

WEALL_ALLOW_LAN_GENESIS_API=1 \
python3 scripts/verify_node_operator_onboarding_bundle.py \
  --bundle "${BUNDLE_OUT}" \
  --manifest "${PUBLIC_MANIFEST_OUT}" \
  --json | tee "${WORK_DIR}/bundle-verify.json"

cat <<MSG

OK: disposable reviewer Genesis prepared
- Genesis API base: ${GENESIS_API_BASE}
- Work dir: ${WORK_DIR}
- Public artifact dir: ${PUBLIC_DIR}
- Observer bundle: ${BUNDLE_OUT}
- Reviewer manifest: ${PUBLIC_MANIFEST_OUT}
- Artifact index: ${ARTIFACT_INDEX_OUT}

Observer pull command:
  bash scripts/reviewer_observer_rehearsal.sh \\
    --genesis-api-base ${GENESIS_API_BASE} \\
    --pull-reviewer-artifacts \\
    --allow-lan-genesis-api

MSG

if truthy "${NO_BOOT}"; then
  echo "[reviewer-genesis] --no-boot set; not starting Genesis API."
  exit 0
fi

# shellcheck disable=SC1090
. "${ENV_PATH}"

export WEALL_MODE=prod
export WEALL_CHAIN_ID="${CHAIN_ID}"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_GENESIS_LEDGER_PATH="${LEDGER_PATH}"
export WEALL_REQUIRE_PRODUCTION_GENESIS_LEDGER=1
export WEALL_NODE_LIFECYCLE_STATE=production_service
export WEALL_OBSERVER_MODE=0
export WEALL_BLOCK_LOOP_AUTOSTART=1
export WEALL_NET_ENABLED=0
export WEALL_NET_LOOP_AUTOSTART=0
export WEALL_BFT_ENABLED=0
export WEALL_VALIDATOR_SIGNING_ENABLED=0
export WEALL_REVIEWER_ARTIFACTS_ENABLED=1
export WEALL_REVIEWER_ARTIFACTS_DIR="${PUBLIC_DIR}"
export WEALL_CORS_ORIGINS="http://localhost:${FRONTEND_PORT},http://127.0.0.1:${FRONTEND_PORT},http://${LAN_IP}:${FRONTEND_PORT}"
export GUNICORN_BIND="0.0.0.0:${API_PORT}"

rm -f "${WEALL_DB_PATH}" "${WEALL_DB_PATH}-wal" "${WEALL_DB_PATH}-shm"
rm -f "${WEALL_AUX_DB_PATH}" "${WEALL_AUX_DB_PATH}-wal" "${WEALL_AUX_DB_PATH}-shm"

cat <<MSG
[reviewer-genesis] Starting disposable reviewer Genesis API.
[reviewer-genesis] Local health check:
  curl -fsS ${LOCAL_API_BASE}/v1/health
[reviewer-genesis] LAN health check:
  curl -fsS ${GENESIS_API_BASE}/v1/health
[reviewer-genesis] Public reviewer artifact checks:
  curl -fsS ${GENESIS_API_BASE}/v1/reviewer/artifacts
  curl -fsS ${GENESIS_API_BASE}/v1/reviewer/artifacts/bundle
  curl -fsS ${GENESIS_API_BASE}/v1/reviewer/artifacts/manifest

MSG

bash scripts/boot_weall_node.sh &
SERVER_PID="$!"

cleanup() {
  status=$?
  if [[ ${status} -ne 0 ]]; then
    echo "[reviewer-genesis] stopping Genesis API after failure"
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  return "${status}"
}
trap cleanup EXIT

echo "[reviewer-genesis] Waiting for local health..."
deadline=$((SECONDS + 30))
until curl -fsS "${LOCAL_API_BASE}/v1/health" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    fail "Genesis API did not become healthy on ${LOCAL_API_BASE}"
  fi
  sleep 1
done

echo "[reviewer-genesis] Waiting for reviewer artifact routes..."
deadline=$((SECONDS + 30))
until curl -fsS "${LOCAL_API_BASE}/v1/reviewer/artifacts" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    fail "reviewer artifact route did not become healthy on ${LOCAL_API_BASE}"
  fi
  sleep 1
done

echo "[reviewer-genesis] Waiting for block height to advance..."
deadline=$((SECONDS + HEIGHT_WAIT_SECONDS))
height="0"
until [[ "${height}" =~ ^[0-9]+$ ]] && (( height > 0 )); do
  height="$(curl -fsS "${LOCAL_API_BASE}/v1/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("height", 0))' 2>/dev/null || echo 0)"
  if [[ "${height}" =~ ^[0-9]+$ ]] && (( height > 0 )); then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "[reviewer-genesis] consensus status:"
    curl -fsS "${LOCAL_API_BASE}/v1/status/consensus" | python3 -m json.tool || true
    fail "Genesis height did not advance above 0 within ${HEIGHT_WAIT_SECONDS}s"
  fi
  sleep 2
done

cat <<MSG

OK: disposable reviewer Genesis is producing blocks
- local API: ${LOCAL_API_BASE}
- LAN API: ${GENESIS_API_BASE}
- current height: ${height}
- public artifact index: ${GENESIS_API_BASE}/v1/reviewer/artifacts

Observer command:
  bash scripts/reviewer_observer_rehearsal.sh \\
    --genesis-api-base ${GENESIS_API_BASE} \\
    --pull-reviewer-artifacts \\
    --allow-lan-genesis-api

Truth boundary:
  Disposable reviewer rehearsal chain.
  This is a disposable reviewer rehearsal chain. It proves reviewer LAN setup,
  signed observer onboarding, and tx confirmation on a generated local chain.
  It does not prove canonical production Genesis authority, public mainnet
  readiness, public multi-validator BFT readiness, or live economics.

[reviewer-genesis] Leave this terminal running.

MSG

wait "${SERVER_PID}"
