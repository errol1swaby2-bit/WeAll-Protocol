#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${OUT_DIR:-$HOME}}"
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
ARCHIVE_NAME="WeAll-Core-Audit-${STAMP}.zip"
ARCHIVE_PATH="${OUT_DIR%/}/${ARCHIVE_NAME}"

mkdir -p "$OUT_DIR"

cd "$ROOT/.."

zip -r "$ARCHIVE_PATH" "$(basename "$ROOT")" \
  -x "*/.venv/*" \
     "*/.venv-release-check/*" \
     "*/node_modules/*" \
     "*/__pycache__/*" \
     "*/.pytest_cache/*" \
     "*/.mypy_cache/*" \
     "*/.ruff_cache/*" \
     "*.egg-info/*" \
     "*/.git/*" \
     "*/.idea/*" \
     "*/.vscode/*" \
     "*/dist/*" \
     "*/build/*" \
     "*/coverage/*" \
     "*/htmlcov/*" \
     "*/.weall-dev/*" \
     "*/.weall-devnet/*" \
     "*/.weall/*" \
     "*/ipfs_partition/*" \
     "*/.DS_Store" \
     "*/.env.local" \
     "*/.env.*.local" \
     "*/frontend.pid" \
     "*/tools/kubo/*" \
     "*/tsconfig.tsbuildinfo" \
     "*.tsbuildinfo" \
     "*.pyc" \
     "*.pyo" \
     "*.pyd" \
     "*.log" \
     "*.tmp" \
     "*.swp" \
     "*.swo" \
     "*.sqlite*" \
     "*.db" \
     "*.tar.gz" \
     "*.zip"

cat <<MSG
[audit-archive] wrote: $ARCHIVE_PATH
[audit-archive] includes release lockfiles such as requirements.lock and web/package-lock.json
MSG
