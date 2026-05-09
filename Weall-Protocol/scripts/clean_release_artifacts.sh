#!/usr/bin/env bash
set -euo pipefail

# Remove local runtime/build artifacts that must not be shipped to external testers.
# This script is intentionally conservative about source/spec/generated canon files:
# it preserves generated/tx_index.json, generated/tx_contract_map.json, and
# generated/helper_contract_map.json, and it never removes docs, tests, specs, or src.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTER_ROOT="$(cd "$ROOT/.." && pwd)"
WEB_ROOT="$OUTER_ROOT/web"
cd "$ROOT"

if [[ ! -f "specs/tx_canon/tx_canon.yaml" || ! -f "scripts/verify_release_tree.sh" ]]; then
  echo "[clean-release] refusing to run: $ROOT does not look like the WeAll protocol repo" >&2
  exit 2
fi

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--dry-run]" >&2
  exit 2
fi

log() {
  printf '[clean-release] %s\n' "$*"
}

rm_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
      log "would remove $path"
    else
      rm -rf -- "$path"
      log "removed $path"
    fi
  fi
}

find_remove_files() {
  local label="$1"
  shift
  local matches=()
  while IFS= read -r -d '' item; do
    matches+=("$item")
  done < <(find "$@" -print0)

  if [[ ${#matches[@]} -eq 0 ]]; then
    log "no $label"
    return
  fi

  for item in "${matches[@]}"; do
    if [[ "$DRY_RUN" == "1" ]]; then
      log "would remove $item"
    else
      rm -f -- "$item"
      log "removed $item"
    fi
  done
}

find_remove_dirs() {
  local label="$1"
  shift
  local matches=()
  while IFS= read -r -d '' item; do
    matches+=("$item")
  done < <(find "$@" -print0)

  if [[ ${#matches[@]} -eq 0 ]]; then
    log "no $label"
    return
  fi

  for item in "${matches[@]}"; do
    if [[ "$DRY_RUN" == "1" ]]; then
      log "would remove $item"
    else
      rm -rf -- "$item"
      log "removed $item"
    fi
  done
}

log "repo: $ROOT"

# Local runtime directories and state roots.
rm_path ".weall-devnet"
rm_path ".weall"
rm_path "data"
rm_path "data_local"
rm_path "data.backup.test"
rm_path "data.before-restore"
rm_path "dev"
rm_path "tmp"
rm_path ".provider-cli"

# Local env files that can hold secrets or machine-specific settings.
rm_path ".env"
rm_path ".env.local"

# Raw node/operator keys are intentionally not deleted automatically here.
# They may be real production keys, so a release check must fail until the
# operator moves them outside the repo or removes them intentionally.
if [[ -d "secrets" ]]; then
  log "secrets/ exists; release verification will fail unless it contains only README/.gitignore placeholders"
fi

# Python caches/build artifacts.
rm_path ".pytest_cache"
rm_path ".mypy_cache"
rm_path ".ruff_cache"
rm_path ".pyright"
rm_path ".tox"
rm_path ".nox"
rm_path "build"
rm_path "dist"
find_remove_dirs "Python bytecode cache directories" . -path './.git' -prune -o -path './.venv' -prune -o -type d -name '__pycache__'
find_remove_dirs "Python egg-info directories" . -path './.git' -prune -o -path './.venv' -prune -o -type d -name '*.egg-info'
find_remove_files "Python bytecode files" . -path './.git' -prune -o -path './.venv' -prune -o -type f \( -name '*.pyc' -o -name '*.pyo' \)

# Runtime database/journal/helper scratch artifacts.
find_remove_files "SQLite/runtime database files" . -path './.git' -prune -o -path './.venv' -prune -o -type f \( -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' -o -name '*.sqlite' -o -name '*.aux.sqlite' \)
find_remove_files "BFT journal files" . -path './.git' -prune -o -path './.venv' -prune -o -type f -name '*.db.bft_journal.jsonl'
find_remove_dirs "helper lane temp directories" . -path './.git' -prune -o -path './.venv' -prune -o -type d -name '*.aux_helper_lanes'

# Local generated secret/result artifacts only. Preserve canon-generated JSON files.
rm_path "generated/demo_bootstrap_secret.json"
rm_path "generated/demo_bootstrap_result.json"
find_remove_files "generated JSON secret artifacts" generated -type f -name '*secret*.json' 2>/dev/null || true

# Backend TypeScript/build artifacts that can appear in mixed trees.
find_remove_files "TypeScript build info files" . -path './.git' -prune -o -path './.venv' -prune -o -type f -name '*.tsbuildinfo'
find_remove_dirs "backend node_modules directories" . -path './.git' -prune -o -path './.venv' -prune -o -type d -name 'node_modules'

# Outer frontend tree lives next to Weall-Protocol in this project layout.
if [[ -d "$WEB_ROOT" ]]; then
  log "outer web: $WEB_ROOT"
  rm_path "$WEB_ROOT/.env"
  rm_path "$WEB_ROOT/.env.local"
  rm_path "$WEB_ROOT/node_modules"
  rm_path "$WEB_ROOT/dist"
  find_remove_files "outer web TypeScript build info files" "$WEB_ROOT" -type f -name '*.tsbuildinfo'
else
  log "outer web tree not present; skipping outer web cleanup"
fi

if [[ "$DRY_RUN" == "1" ]]; then
  log "dry run complete"
else
  log "cleanup complete"
fi
