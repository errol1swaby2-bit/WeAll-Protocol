#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

bad=$(find src -type f \( -name "*.js" -o -name "*.jsx" \) || true)

if [[ -n "${bad}" ]]; then
  echo "ERROR: JS source files found in web/src (TS-only policy)."
  echo "${bad}"
  exit 1
fi

echo "OK: no .js/.jsx files under web/src"
