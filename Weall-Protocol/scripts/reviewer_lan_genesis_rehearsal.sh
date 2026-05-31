#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

API_PORT="${WEALL_REVIEWER_API_PORT:-8000}"
FRONTEND_PORT="${WEALL_REVIEWER_FRONTEND_PORT:-5173}"
BUNDLE_OUT="${WEALL_REVIEWER_BUNDLE_OUT:-/tmp/weall-external-observer-bundle.json}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-configs/chains/weall-genesis.json}"
AUTHORITY_URL="${WEALL_REVIEWER_AUTHORITY_URL:-https://weall-rehearsal-authority.invalid}"
NO_BOOT="${WEALL_REVIEWER_GENESIS_NO_BOOT:-0}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/reviewer_lan_genesis_rehearsal.sh [options]

Options:
  --lan-ip <ip>              LAN IP reviewers/observers should use.
  --wsl-ip <ip>              WSL IP used for Windows port forwarding.
  --api-port <port>          Genesis API port. Default: 8000.
  --frontend-port <port>     Frontend port used for CORS. Default: 5173.
  --bundle-out <path>        Public observer bundle output path.
  --manifest <path>          Chain manifest path.
  --authority-url <url>      HTTPS public authority metadata URL.
  --no-boot                  Prepare and print commands, but do not boot Genesis.
  -h, --help                 Show this help.

Purpose:
  Prepare a reviewer-friendly LAN Genesis API, build a public observer bundle,
  verify it, and print the exact observer command.
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
    --bundle-out) BUNDLE_OUT="${2:-}"; shift 2 ;;
    --manifest) MANIFEST_PATH="${2:-}"; shift 2 ;;
    --authority-url) AUTHORITY_URL="${2:-}"; shift 2 ;;
    --no-boot) NO_BOOT="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -f "${MANIFEST_PATH}" ]] || fail "manifest not found: ${MANIFEST_PATH}"

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

# shellcheck disable=SC1091
if [[ -x ".venv/bin/activate" ]]; then
  . .venv/bin/activate
fi

python3 scripts/build_external_observer_bundle.py \
  --manifest "${MANIFEST_PATH}" \
  --genesis-api-base "${GENESIS_API_BASE}" \
  --authority-url "${AUTHORITY_URL}" \
  --out "${BUNDLE_OUT}"

WEALL_ALLOW_PRIVATE_GENESIS_API=1 \
python3 scripts/verify_node_operator_onboarding_bundle.py \
  --bundle "${BUNDLE_OUT}" \
  --manifest "${MANIFEST_PATH}" \
  --json

cat <<MSG

OK: public observer bundle prepared
- Genesis API base: ${GENESIS_API_BASE}
- Observer bundle: ${BUNDLE_OUT}
- Manifest: ${MANIFEST_PATH}

Copy the observer bundle to the observer machine, for example:
  ~/weall-observer/weall-external-observer-bundle.json

Observer command:
  bash scripts/reviewer_observer_rehearsal.sh \\
    --genesis-api-base ${GENESIS_API_BASE} \\
    --bundle ~/weall-observer/weall-external-observer-bundle.json \\
    --allow-private-genesis-api

MSG

if truthy "${NO_BOOT}"; then
  echo "[reviewer-genesis] --no-boot set; not starting Genesis API."
  exit 0
fi

export WEALL_MODE=prod
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_CORS_ORIGINS="http://localhost:${FRONTEND_PORT},http://127.0.0.1:${FRONTEND_PORT},http://${LAN_IP}:${FRONTEND_PORT}"
export GUNICORN_BIND="0.0.0.0:${API_PORT}"

cat <<MSG
[reviewer-genesis] Starting Genesis API.
[reviewer-genesis] Leave this terminal running.
[reviewer-genesis] Health check from another terminal:
  curl -fsS ${GENESIS_API_BASE}/v1/health
  curl -fsS ${GENESIS_API_BASE}/v1/genesis/observer/readiness

MSG

exec bash scripts/boot_weall_node.sh
