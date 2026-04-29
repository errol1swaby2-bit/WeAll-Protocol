#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[secret-guard] scanning tracked files…"

# This guard is meant to protect what gets committed.
# If we're not in a git checkout (e.g., zip export), skip cleanly.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[secret-guard] WARN: not a git work tree; skipping tracked-files scan."
  exit 0
fi

TRACKED="$(mktemp)"
git ls-files > "$TRACKED"

fail() {
  echo "[secret-guard:FAIL] $*" >&2
  exit 1
}

# 1) Hard fail if any .env or .env.* file is tracked (except .env.example)
BAD_ENV_FILES="$(grep -E '(^|/)\.env(\..+)?$' "$TRACKED" | grep -vE '\.env\.example$' || true)"
if [[ -n "${BAD_ENV_FILES}" ]]; then
  echo "[secret-guard] tracked env files found:"
  echo "${BAD_ENV_FILES}"
  fail "Do not commit .env files. Use .env.example templates only."
fi

echo "[secret-guard] OK"
