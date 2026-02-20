#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

if [[ -f "src/weall.ts" ]]; then
  echo "ERROR: src/weall.ts exists. Remove it; canonical client is src/api/weall.ts"
  fail=1
fi

if [[ -f "src/lib/api.ts" ]]; then
  echo "ERROR: src/lib/api.ts exists. Remove it; canonical client is src/api/weall.ts"
  fail=1
fi

# Hard rule: no direct fetch() outside src/api (route all HTTP through src/api/weall.ts)
bad_fetch=$(grep -RIn -F --exclude-dir=api --exclude="*.test.*" --exclude="*.spec.*" "fetch(" src || true)
if [[ -n "${bad_fetch}" ]]; then
  echo "ERROR: fetch() used outside src/api. Route HTTP calls through src/api/weall.ts"
  echo "${bad_fetch}"
  fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi

echo "OK: single API client surface enforced (src/api/weall.ts)"
