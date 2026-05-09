#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
OUT_DIR="${OUT_DIR:-$HOME}"
ARCHIVE_NAME="WeAll-Protocol-release-${STAMP}.zip"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"

echo "[release] repo: $ROOT"

bash "$ROOT/scripts/clean_release_artifacts.sh"
"$ROOT/scripts/verify_release_tree.sh"

zip -r "$ARCHIVE_PATH" . \
  -x '.git/*' \
     '.venv/*' \
     '__pycache__/*' \
     '*.pyc' \
     '*.pyo' \
     '.pytest_cache/*' \
     '.mypy_cache/*' \
     '.ruff_cache/*' \
     '*.egg-info/*' \
     'node_modules/*' \
     'web/node_modules/*' \
     'web/dist/*' \
     'dist/*' \
     '*.tsbuildinfo' \
     '.env' \
     '.env.local' \
     'web/.env' \
     'web/.env.local' \
     'secrets/*' \
     '.weall-devnet/*' \
     '.weall/*' \
     'data/*' \
     'generated/demo_bootstrap_secret.json' \
     'generated/demo_bootstrap_result.json' \
     'generated/*secret*.json' \
     '*.db' \
     '*.db-wal' \
     '*.db-shm' \
     '*.sqlite' \
     '*.aux.sqlite' \
     '*.db.bft_journal.jsonl' \
     '*.aux_helper_lanes/*'

echo "[release] wrote $ARCHIVE_PATH"

