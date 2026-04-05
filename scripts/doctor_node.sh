#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_ENV="$ROOT_DIR/secrets/runtime.env"
TUNNEL_NAME="weall-cloudflared"

ok() { printf '✅ %s\n' "$1"; }
warn() { printf '⚠️  %s\n' "$1"; }
fail() { printf '❌ %s\n' "$1"; }

if [[ ! -f "$RUNTIME_ENV" ]]; then
  fail "Missing $RUNTIME_ENV"
  exit 1
fi

# shellcheck disable=SC1090
source "$RUNTIME_ENV"

printf 'WeAll doctor\n\n'

if [[ "$(stat -c '%a' "$RUNTIME_ENV")" == "600" ]]; then
  ok "runtime.env permissions are 600"
else
  warn "runtime.env permissions are $(stat -c '%a' "$RUNTIME_ENV"), expected 600"
fi

required=(
  WEALL_MODE
  WEALL_NODE_ID
  WEALL_VALIDATOR_ACCOUNT
  WEALL_NODE_PUBKEY
  WEALL_NODE_PRIVKEY
  WEALL_POH_EMAIL_SECRET
  WEALL_API_HOST
  WEALL_API_PORT
)

for var_name in "${required[@]}"; do
  if [[ -n "${!var_name:-}" ]]; then
    ok "$var_name is set"
  else
    fail "$var_name is missing"
  fi
done

if curl -fsS "http://${WEALL_API_HOST}:${WEALL_API_PORT}/v1/status" >/tmp/weall_status.json 2>/dev/null; then
  ok "Local backend reachable at http://${WEALL_API_HOST}:${WEALL_API_PORT}/v1/status"
else
  warn "Local backend not reachable at http://${WEALL_API_HOST}:${WEALL_API_PORT}/v1/status"
fi

if curl -fsS 'https://api.weallprotocol.xyz/v1/status' >/tmp/weall_public_status.json 2>/dev/null; then
  ok 'Public API reachable at https://api.weallprotocol.xyz/v1/status'
else
  warn 'Public API not reachable at https://api.weallprotocol.xyz/v1/status'
fi

if curl -fsS 'https://api.weallprotocol.xyz/v1/poh/email/oracle-authority' >/tmp/weall_oracle_authority.json 2>/dev/null; then
  ok 'Oracle authority endpoint reachable'
  if grep -q '"@satoshi"' /tmp/weall_oracle_authority.json; then
    ok 'Oracle authority currently includes @satoshi'
  else
    warn 'Oracle authority endpoint does not currently show @satoshi'
  fi
else
  warn 'Oracle authority endpoint not reachable'
fi

if docker ps --format '{{.Names}}' | grep -qx "$TUNNEL_NAME"; then
  ok "Cloudflare tunnel container is running ($TUNNEL_NAME)"
else
  warn "Cloudflare tunnel container is not running ($TUNNEL_NAME)"
fi

printf '\nDoctor completed.\n'
