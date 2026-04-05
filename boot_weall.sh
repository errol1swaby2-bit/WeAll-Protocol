#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$HOME/WeAll-Protocol"
API_DIR="$ROOT_DIR/Weall-Protocol"
WEB_DIR="$ROOT_DIR/web"
SECRETS_DIR="$ROOT_DIR/secrets"
RUNTIME_ENV="$SECRETS_DIR/runtime.env"
PROMPT_SCRIPT="$ROOT_DIR/scripts/prompt_runtime_env.sh"
DOCTOR_SCRIPT="$ROOT_DIR/scripts/doctor_node.sh"

BACKEND_LOG="$API_DIR/backend.log"
FRONTEND_LOG="$WEB_DIR/frontend.log"
TUNNEL_NAME="weall-cloudflared"

usage() {
  cat <<USAGE
Usage: $(basename "$0") <command>

Commands:
  init      Interactive one-time provisioning of runtime secrets and boot settings
  start     Start backend, frontend, and optional Cloudflare tunnel from secrets/runtime.env
  stop      Stop backend, frontend, and Cloudflare tunnel
  restart   Stop then start services
  doctor    Validate runtime env, local services, tunnel, and public endpoints
  show-env  Print the non-secret runtime values currently saved

Notes:
  - Production boots should normally use: $(basename "$0") start
  - Interactive prompts are reserved for:  $(basename "$0") init
USAGE
}

require_runtime_env() {
  if [[ ! -f "$RUNTIME_ENV" ]]; then
    printf '❌ Missing %s\n' "$RUNTIME_ENV" >&2
    printf 'Run %s init first.\n' "$(basename "$0")" >&2
    exit 1
  fi
}

load_runtime_env() {
  require_runtime_env
  # shellcheck disable=SC1090
  source "$RUNTIME_ENV"
}

ensure_exec() {
  local path="$1"
  if [[ -f "$path" && ! -x "$path" ]]; then
    chmod +x "$path"
  fi
}

start_backend() {
  if [[ "${START_BACKEND:-1}" != "1" ]]; then
    printf '⏭️  Backend disabled by runtime config.\n'
    return
  fi

  printf '🧠 Starting backend...\n'
  cd "$API_DIR"
  source .venv/bin/activate

  pkill -f 'gunicorn.*weall.api.app:app' || true
  pkill -f 'uvicorn.*weall.api.app:app' || true
  rm -f gunicorn.ctl

  export WEALL_GENESIS_MODE WEALL_MODE WEALL_CORS_ORIGINS
  export WEALL_NODE_ID WEALL_VALIDATOR_ACCOUNT WEALL_NODE_PUBKEY WEALL_NODE_PRIVKEY
  export WEALL_POH_EMAIL_SECRET WEALL_POH_EMAIL_ORACLE_URL
  export WEALL_API_HOST WEALL_API_PORT

  nohup ./scripts/run_node.sh > "$BACKEND_LOG" 2>&1 &
  local backend_pid=$!
  disown "$backend_pid" || true
  printf '✅ Backend started (pid=%s, logs=%s)\n' "$backend_pid" "$BACKEND_LOG"
}

start_frontend() {
  if [[ "${START_FRONTEND:-1}" != "1" ]]; then
    printf '⏭️  Frontend disabled by runtime config.\n'
    return
  fi

  printf '🌐 Starting frontend...\n'
  cd "$WEB_DIR"

  pkill -f 'vite.*WeAll-Protocol/web' || true
  nohup npm run dev -- --host "${WEALL_FRONTEND_HOST}" --port "${WEALL_FRONTEND_PORT}" > "$FRONTEND_LOG" 2>&1 &
  local frontend_pid=$!
  disown "$frontend_pid" || true
  printf '✅ Frontend started (pid=%s, logs=%s)\n' "$frontend_pid" "$FRONTEND_LOG"
  printf '✅ Frontend URL: http://localhost:%s\n' "$WEALL_FRONTEND_PORT"
}

start_tunnel() {
  if [[ "${START_TUNNEL:-0}" != "1" ]]; then
    printf '⏭️  Tunnel disabled by runtime config.\n'
    return
  fi

  if [[ -z "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]]; then
    printf '❌ START_TUNNEL=1 but CLOUDFLARE_TUNNEL_TOKEN is empty.\n' >&2
    exit 1
  fi

  printf '🌍 Starting Cloudflare tunnel...\n'
  docker rm -f "$TUNNEL_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$TUNNEL_NAME" \
    --network host \
    --restart unless-stopped \
    cloudflare/cloudflared:latest \
    tunnel --no-autoupdate run --token "$CLOUDFLARE_TUNNEL_TOKEN" >/dev/null
  printf '✅ Tunnel started (container=%s)\n' "$TUNNEL_NAME"
}

stop_services() {
  printf '🛑 Stopping services...\n'
  pkill -f 'gunicorn.*weall.api.app:app' || true
  pkill -f 'uvicorn.*weall.api.app:app' || true
  pkill -f 'vite.*WeAll-Protocol/web' || true
  docker rm -f "$TUNNEL_NAME" >/dev/null 2>&1 || true
  printf '✅ Stop complete.\n'
}

print_health_hints() {
  printf '\n📋 Health checks:\n'
  printf '  Backend: curl http://%s:%s/v1/status\n' "${WEALL_API_HOST}" "${WEALL_API_PORT}"
  printf '  Public:  curl https://api.weallprotocol.xyz/v1/status\n'
  if [[ "${START_FRONTEND:-1}" == "1" ]]; then
    printf '  Frontend: http://localhost:%s\n' "${WEALL_FRONTEND_PORT}"
  fi
  if [[ "${START_TUNNEL:-0}" == "1" ]]; then
    printf '  Tunnel logs: docker logs -f %s\n' "$TUNNEL_NAME"
  fi
  printf '\n'
}

show_env() {
  load_runtime_env
  printf 'Runtime env file: %s\n\n' "$RUNTIME_ENV"
  printf 'WEALL_MODE=%s\n' "${WEALL_MODE:-}"
  printf 'WEALL_GENESIS_MODE=%s\n' "${WEALL_GENESIS_MODE:-}"
  printf 'WEALL_CORS_ORIGINS=%s\n' "${WEALL_CORS_ORIGINS:-}"
  printf 'WEALL_NODE_ID=%s\n' "${WEALL_NODE_ID:-}"
  printf 'WEALL_VALIDATOR_ACCOUNT=%s\n' "${WEALL_VALIDATOR_ACCOUNT:-}"
  printf 'WEALL_NODE_PUBKEY=%s\n' "${WEALL_NODE_PUBKEY:-}"
  printf 'WEALL_POH_EMAIL_ORACLE_URL=%s\n' "${WEALL_POH_EMAIL_ORACLE_URL:-}"
  printf 'WEALL_API_HOST=%s\n' "${WEALL_API_HOST:-}"
  printf 'WEALL_API_PORT=%s\n' "${WEALL_API_PORT:-}"
  printf 'WEALL_FRONTEND_HOST=%s\n' "${WEALL_FRONTEND_HOST:-}"
  printf 'WEALL_FRONTEND_PORT=%s\n' "${WEALL_FRONTEND_PORT:-}"
  printf 'START_BACKEND=%s\n' "${START_BACKEND:-}"
  printf 'START_FRONTEND=%s\n' "${START_FRONTEND:-}"
  printf 'START_TUNNEL=%s\n' "${START_TUNNEL:-}"
}

command="${1:-start}"

ensure_exec "$PROMPT_SCRIPT"
ensure_exec "$DOCTOR_SCRIPT"

case "$command" in
  init)
    printf '🛠️  Provisioning WeAll runtime config...\n'
    bash "$PROMPT_SCRIPT"
    printf '✅ Provisioning complete. Next run: %s start\n' "$(basename "$0")"
    ;;
  start)
    load_runtime_env
    printf '🚀 Starting WeAll Protocol from %s\n' "$RUNTIME_ENV"
    start_backend
    start_frontend
    start_tunnel
    print_health_hints
    printf '🎉 WeAll start completed.\n'
    ;;
  stop)
    stop_services
    ;;
  restart)
    stop_services
    load_runtime_env
    start_backend
    start_frontend
    start_tunnel
    print_health_hints
    printf '🎉 WeAll restart completed.\n'
    ;;
  doctor)
    exec bash "$DOCTOR_SCRIPT"
    ;;
  show-env)
    show_env
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    printf 'Unknown command: %s\n\n' "$command" >&2
    usage >&2
    exit 1
    ;;
esac
