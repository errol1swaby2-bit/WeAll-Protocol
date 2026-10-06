#!/usr/bin/env bash
set -euo pipefail

REPO_SSH_URL="${REPO_SSH_URL:-git@github.com:errol1swaby2-bit/WeAll-Protocol.git}"
REPO_HTTPS_URL="${REPO_HTTPS_URL:-https://github.com/errol1swaby2-bit/WeAll-Protocol.git}"
WORKDIR="${WORKDIR:-/tmp/weall-fresh-clone-smoke}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
BACKEND_DIR_NAME="Weall-Protocol"
FRONTEND_DIR_NAME="web"
REVIEW_COMMIT="${WEALL_FRESH_CLONE_COMMIT:-}"

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
  require_cmd npm

  [[ "${REVIEW_COMMIT}" =~ ^[0-9a-fA-F]{40}$ ]] || die "WEALL_FRESH_CLONE_COMMIT must be the exact 40-hex commit under review"

  local clone_url
  clone_url="$(choose_clone_url)"

  log "using clone URL: $clone_url"
  log "workdir: $WORKDIR"

  rm -rf "$WORKDIR"
  git clone --no-checkout "$clone_url" "$WORKDIR"
  git -C "$WORKDIR" fetch --depth 1 origin "$REVIEW_COMMIT"
  git -C "$WORKDIR" checkout --detach "$REVIEW_COMMIT"

  local actual_commit
  actual_commit="$(git -C "$WORKDIR" rev-parse HEAD)"
  [[ "$actual_commit" == "${REVIEW_COMMIT,,}" ]] || die "checked-out commit mismatch: expected ${REVIEW_COMMIT,,}, got $actual_commit"
  log "review commit: $actual_commit"

  cd "$WORKDIR/$BACKEND_DIR_NAME"
  log "entered backend repo: $(pwd)"

  "$PYTHON_BIN" -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate

  python -m pip install --upgrade pip >/dev/null
  pip install --require-hashes -r requirements.lock

  log "verifying locked backend/frontend release dependencies"
  bash scripts/verify_release_dependencies.sh

  log "checking tx canon artifacts"
  python3 -S scripts/check_tx_canon_artifacts.py

  log "regenerating tx index"
  python scripts/gen_tx_index.py

  if git diff --quiet -- generated/tx_index.json generated/tx_contract_map.json generated/helper_contract_map.json src/weall/runtime/tx_schema.py; then
    log "OK: generated tx artifacts are stable after regeneration"
  else
    git diff -- generated/tx_index.json generated/tx_contract_map.json generated/helper_contract_map.json src/weall/runtime/tx_schema.py || true
    die "generated tx artifacts drifted in fresh clone"
  fi

  log "running backend tests"
  pytest -q

  cd "$WORKDIR/$FRONTEND_DIR_NAME"
  log "running mandatory frontend install/safety/build"
  npm ci
  npm run production-safety-check
  npm run build

  log "fresh clone smoke passed for exact commit: $actual_commit"
  log "clone remains at: $WORKDIR"
}

main "$@"
