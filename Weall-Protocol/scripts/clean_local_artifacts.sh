#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf '
[%s] %s
' 'clean-local' "$*"
}

remove_path() {
  local path="$1"
  if [ -e "$path" ] || [ -L "$path" ]; then
    rm -rf "$path"
    echo "removed $path"
  fi
}

log 'removing local runtime artifacts that must not ship to external testers'
remove_path .env
remove_path .venv
remove_path .venv-release-check
remove_path .venv-tools
remove_path .pytest_cache
remove_path .ruff_cache
remove_path .mypy_cache
remove_path data
remove_path data_local
remove_path data.backup.test
remove_path data.before-restore
remove_path generated
remove_path dev
remove_path cloudflare/email_oracle/.dev.vars

log 'preserving secrets/README.md and secrets/.gitignore, removing other secret material'
if [ -d secrets ]; then
  find secrets -mindepth 1 -maxdepth 1     ! -name '.gitignore'     ! -name 'README.md'     -exec rm -rf {} +
fi

log 'recreating clean runtime directories expected by quickstart'
mkdir -p data generated data/ipfs

cat <<'MSG'

Local cleanup complete.

Recommended verification before pushing:
  git status --short
  git check-ignore -v data generated .env .venv-release-check cloudflare/email_oracle/.dev.vars
  docker compose build
  ./scripts/quickstart_tester.sh

Note:
- data/ and generated/ are recreated empty for local quickstart convenience.
- external testers should get those directories from the repo empty, not with founder runtime contents.
MSG
