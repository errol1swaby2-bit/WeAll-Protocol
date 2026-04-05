#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="$ROOT_DIR/secrets"
RUNTIME_ENV="$SECRETS_DIR/runtime.env"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

if [[ -f "$RUNTIME_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$RUNTIME_ENV"
fi

generate_secret() {
  python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

prompt_value() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="${3-}"
  local input=""
  if [[ -n "$default_value" ]]; then
    read -r -p "$prompt_text [$default_value]: " input
  else
    read -r -p "$prompt_text: " input
  fi
  if [[ -z "$input" ]]; then
    input="$default_value"
  fi
  printf -v "$var_name" '%s' "$input"
}

prompt_secret() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="${3-}"
  local allow_generate="${4-0}"
  local input=""
  if [[ -n "$default_value" ]]; then
    read -r -s -p "$prompt_text [saved value present, Enter keeps it]: " input
  else
    read -r -s -p "$prompt_text: " input
  fi
  printf '\n'
  if [[ -z "$input" ]]; then
    input="$default_value"
  fi
  if [[ -z "$input" && "$allow_generate" == "1" ]]; then
    input="$(generate_secret)"
    printf '🔐 Generated %s automatically.\n' "$var_name"
  fi
  printf -v "$var_name" '%s' "$input"
}

prompt_yes_no() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="${3-}"
  local default_display="y/N"
  case "${default_value,,}" in
    y|yes|1|true|on) default_value='y'; default_display='Y/n' ;;
    *) default_value='n'; default_display='y/N' ;;
  esac
  local input=''
  read -r -p "$prompt_text [$default_display]: " input
  input="${input:-$default_value}"
  case "${input,,}" in
    y|yes|1|true|on) printf -v "$var_name" '%s' '1' ;;
    *) printf -v "$var_name" '%s' '0' ;;
  esac
}

printf 'WeAll runtime provisioning\n'
printf 'This writes operator-only settings to %s\n\n' "$RUNTIME_ENV"

prompt_value WEALL_MODE 'WEALL_MODE' "${WEALL_MODE:-prod}"
prompt_value WEALL_GENESIS_MODE 'WEALL_GENESIS_MODE' "${WEALL_GENESIS_MODE:-1}"
prompt_value WEALL_CORS_ORIGINS 'WEALL_CORS_ORIGINS' "${WEALL_CORS_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173,https://weallprotocol.xyz}"
prompt_value WEALL_NODE_ID 'WEALL_NODE_ID' "${WEALL_NODE_ID:-@satoshi}"
prompt_value WEALL_VALIDATOR_ACCOUNT 'WEALL_VALIDATOR_ACCOUNT' "${WEALL_VALIDATOR_ACCOUNT:-@satoshi}"
prompt_value WEALL_NODE_PUBKEY 'WEALL_NODE_PUBKEY' "${WEALL_NODE_PUBKEY:-}"
prompt_secret WEALL_NODE_PRIVKEY 'WEALL_NODE_PRIVKEY' "${WEALL_NODE_PRIVKEY:-}"
prompt_secret WEALL_POH_EMAIL_SECRET 'WEALL_POH_EMAIL_SECRET' "${WEALL_POH_EMAIL_SECRET:-}" 1
prompt_value WEALL_POH_EMAIL_ORACLE_URL 'WEALL_POH_EMAIL_ORACLE_URL' "${WEALL_POH_EMAIL_ORACLE_URL:-https://weall-email-oracle.errol1swaby2.workers.dev}"
prompt_value WEALL_API_HOST 'Backend bind host' "${WEALL_API_HOST:-127.0.0.1}"
prompt_value WEALL_API_PORT 'Backend bind port' "${WEALL_API_PORT:-8000}"
prompt_value WEALL_FRONTEND_HOST 'Frontend bind host' "${WEALL_FRONTEND_HOST:-0.0.0.0}"
prompt_value WEALL_FRONTEND_PORT 'Frontend bind port' "${WEALL_FRONTEND_PORT:-5173}"
prompt_yes_no START_BACKEND 'Start backend during boot' "${START_BACKEND:-1}"
prompt_yes_no START_FRONTEND 'Start frontend during boot' "${START_FRONTEND:-1}"
prompt_yes_no START_TUNNEL 'Start Cloudflare tunnel during boot' "${START_TUNNEL:-0}"

if [[ "$START_TUNNEL" == '1' ]]; then
  prompt_secret CLOUDFLARE_TUNNEL_TOKEN 'CLOUDFLARE_TUNNEL_TOKEN' "${CLOUDFLARE_TUNNEL_TOKEN:-}"
else
  CLOUDFLARE_TUNNEL_TOKEN="${CLOUDFLARE_TUNNEL_TOKEN:-}"
fi

cat > "$RUNTIME_ENV" <<EOF_ENV
export WEALL_MODE=$(printf '%q' "$WEALL_MODE")
export WEALL_GENESIS_MODE=$(printf '%q' "$WEALL_GENESIS_MODE")
export WEALL_CORS_ORIGINS=$(printf '%q' "$WEALL_CORS_ORIGINS")
export WEALL_NODE_ID=$(printf '%q' "$WEALL_NODE_ID")
export WEALL_VALIDATOR_ACCOUNT=$(printf '%q' "$WEALL_VALIDATOR_ACCOUNT")
export WEALL_NODE_PUBKEY=$(printf '%q' "$WEALL_NODE_PUBKEY")
export WEALL_NODE_PRIVKEY=$(printf '%q' "$WEALL_NODE_PRIVKEY")
export WEALL_POH_EMAIL_SECRET=$(printf '%q' "$WEALL_POH_EMAIL_SECRET")
export WEALL_POH_EMAIL_ORACLE_URL=$(printf '%q' "$WEALL_POH_EMAIL_ORACLE_URL")
export WEALL_API_HOST=$(printf '%q' "$WEALL_API_HOST")
export WEALL_API_PORT=$(printf '%q' "$WEALL_API_PORT")
export WEALL_FRONTEND_HOST=$(printf '%q' "$WEALL_FRONTEND_HOST")
export WEALL_FRONTEND_PORT=$(printf '%q' "$WEALL_FRONTEND_PORT")
export START_BACKEND=$(printf '%q' "$START_BACKEND")
export START_FRONTEND=$(printf '%q' "$START_FRONTEND")
export START_TUNNEL=$(printf '%q' "$START_TUNNEL")
export CLOUDFLARE_TUNNEL_TOKEN=$(printf '%q' "$CLOUDFLARE_TUNNEL_TOKEN")
EOF_ENV

chmod 600 "$RUNTIME_ENV"
printf '\n✅ Saved runtime config to %s\n' "$RUNTIME_ENV"
printf 'Next steps:\n'
printf '  %s start\n' "$ROOT_DIR/boot_weall.sh"
printf '  %s doctor\n' "$ROOT_DIR/boot_weall.sh"
