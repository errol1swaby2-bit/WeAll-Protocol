#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

if [[ -f "src/lib/weallNodeSelect.ts" ]]; then
  echo "ERROR: src/lib/weallNodeSelect.ts exists. Single node selector is src/lib/nodeSelect.ts"
  fail=1
fi

if [[ ! -f "src/lib/nodeSelect.ts" ]]; then
  echo "ERROR: src/lib/nodeSelect.ts missing. Single node selector must exist."
  fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
  exit 1
fi

echo "OK: single node selection surface enforced (src/lib/nodeSelect.ts)"
