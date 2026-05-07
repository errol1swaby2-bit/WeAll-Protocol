#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTER_ROOT="$(cd "$ROOT/.." && pwd)"
WEB_ROOT="$OUTER_ROOT/web"

cd "$ROOT"

bash scripts/verify_lockfiles.sh

if [[ ! -f "$WEB_ROOT/package-lock.json" ]]; then
  echo "[deps] ERROR: web/package-lock.json missing" >&2
  echo "[deps] Generate it from $WEB_ROOT with: npm install --package-lock-only" >&2
  exit 1
fi

if ! grep -q '"lockfileVersion"' "$WEB_ROOT/package-lock.json"; then
  echo "[deps] ERROR: web/package-lock.json does not look like an npm lockfile" >&2
  exit 1
fi

if grep -Eq '"(react|react-dom|react-router-dom|tweetnacl|typescript|vite)"[[:space:]]*:[[:space:]]*"[~^]' "$WEB_ROOT/package.json"; then
  echo "[deps] ERROR: web/package.json still contains broad semver ranges for production-critical deps" >&2
  exit 1
fi

echo "[deps] OK: backend and frontend release dependency locks are present"
