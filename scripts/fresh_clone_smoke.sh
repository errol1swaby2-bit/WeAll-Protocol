#!/usr/bin/env bash
set -euo pipefail

REPO_SSH_URL="${REPO_SSH_URL:-git@github.com:errol1swaby2-bit/WeAll-Protocol.git}"
REPO_HTTPS_URL="${REPO_HTTPS_URL:-https://github.com/errol1swaby2-bit/WeAll-Protocol.git}"
WORKDIR="${WORKDIR:-/tmp/weall-fresh-clone-smoke}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
BACKEND_DIR_NAME="Weall-Protocol"
FRONTEND_DIR_NAME="web"

log() {
  printf '[fresh-clone] %s\n' "$*"
}

die() {
  printf '[fresh-clone] ERROR: %s\n' "$*" >&2
  exit 1
}

choose_clone_url() {
  if ssh -T git@github.com >/dev/null 2>&1; then
    printf '%s' "$REPO_SSH_URL"
  else
    printf '%s' "$REPO_HTTPS_URL"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

main() {
  require_cmd git
  require_cmd "$PYTHON_BIN"

  local clone_url
  clone_url="$(choose_clone_url)"

  log "using clone URL: $clone_url"
  log "workdir: $WORKDIR"

  rm -rf "$WORKDIR"
  git clone "$clone_url" "$WORKDIR"

  cd "$WORKDIR/$BACKEND_DIR_NAME"
  log "entered backend repo: $(pwd)"

  "$PYTHON_BIN" -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate

  python -m pip install --upgrade pip >/dev/null
  pip install -r requirements.lock

  log "regenerating tx index"
  python scripts/gen_tx_index.py

  if git diff --quiet -- generated/tx_index.json; then
    log "OK: generated/tx_index.json is stable after regeneration"
  else
    git diff -- generated/tx_index.json || true
    die "generated/tx_index.json drifted in fresh clone"
  fi

  log "running backend tests"
  pytest -q

  cd "$WORKDIR/$FRONTEND_DIR_NAME"
  if command -v npm >/dev/null 2>&1; then
    log "Node detected; running frontend install/build"
    npm ci
    npm run build
  else
    log "npm not found; skipping frontend build"
  fi

  log "fresh clone smoke passed"
  log "clone remains at: $WORKDIR"
}

main "$@"
