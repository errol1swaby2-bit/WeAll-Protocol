#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${ROOT_DIR}/Weall-Protocol"
FRONTEND_DIR="${ROOT_DIR}/web"
API_URL="${WEALL_API_URL:-http://127.0.0.1:8000}"
FRONTEND_URL="${WEALL_FRONTEND_URL:-http://127.0.0.1:5173}"

log() {
  printf '\n[%s] %s\n' "repo-quickstart" "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

need_cmd bash
need_cmd docker
need_cmd python3
need_cmd curl
need_cmd npm

if [ ! -d "${BACKEND_DIR}" ]; then
  echo "ERROR: backend directory not found: ${BACKEND_DIR}" >&2
  exit 1
fi

log "starting canonical backend quickstart from ${BACKEND_DIR}"
(
  cd "${BACKEND_DIR}"
  ./scripts/quickstart_tester.sh
)

cat <<MSG

Repository-level quickstart complete.

Next terminal for frontend:
  cd ${FRONTEND_DIR}
  cp .env.example .env.local
  npm ci
  npm run dev -- --host 127.0.0.1 --port 5173

Then run the demo bootstrap:
  cd ${BACKEND_DIR}
  ./scripts/demo_bootstrap_tester.sh

Expected local URLs:
  Backend ready: ${API_URL}/v1/readyz
  Backend docs:  ${API_URL}/docs
  Frontend:      ${FRONTEND_URL}

If frontend startup fails, confirm Node.js 20+ and npm are installed.
MSG
