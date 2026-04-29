#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

TARGET="src/weall/api/routes_public.py"

if [[ ! -f "$TARGET" ]]; then
  echo "ERROR: target file not found: $TARGET" >&2
  exit 1
fi

# Find most recent backup
LATEST_BACKUP="$(ls -1 "${TARGET}.bak."* 2>/dev/null | sort | tail -n 1 || true)"
if [[ -z "${LATEST_BACKUP}" ]]; then
  echo "ERROR: no backups found (expected ${TARGET}.bak.<timestamp>)" >&2
  exit 1
fi

cp -f "$LATEST_BACKUP" "$TARGET"
echo "Restored: $TARGET"
echo "From backup: $LATEST_BACKUP"

echo "Running syntax check..."
python3 -m compileall -q src || { echo "ERROR: compileall failed"; exit 1; }

echo "Rollback complete."
