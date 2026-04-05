#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[verify] repo: $ROOT"

fail=0

check_path_absent() {
  local pattern="$1"
  local label="$2"
  if find . -path './.git' -prune -o -path './.venv' -prune -o -name "$pattern" -print | grep -q .; then
    echo "[verify] FAIL: found $label"
    find . -path './.git' -prune -o -path './.venv' -prune -name "$pattern" -print
    fail=1
  else
    echo "[verify] OK: no $label"
  fi
}

check_dir_absent() {
  local pattern="$1"
  local label="$2"
  if find . -path './.git' -prune -o -path './.venv' -prune -o -type d -name "$pattern" -print | grep -q .; then
    echo "[verify] FAIL: found $label"
    find . -path './.git' -prune -o -path './.venv' -prune -type d -name "$pattern" -print
    fail=1
  else
    echo "[verify] OK: no $label"
  fi
}

check_path_absent '*.pyc' 'Python bytecode files'
check_dir_absent '__pycache__' '__pycache__ directories'
check_dir_absent '.pytest_cache' '.pytest_cache directories'
check_path_absent '*.tsbuildinfo' 'TypeScript build info files'
check_dir_absent 'node_modules' 'node_modules directories'
check_dir_absent 'dist' 'frontend dist directories'
check_dir_absent '.wrangler' 'Wrangler local state directories'
check_path_absent '.env' '.env files'
check_path_absent '.env.local' '.env.local files'
check_path_absent '*.aux.sqlite' 'aux sqlite files'
check_path_absent '*.db.bft_journal.jsonl' 'BFT journal jsonl files'
check_dir_absent '*.aux_helper_lanes' 'helper lane temp directories'

required=(
  "generated/tx_index.json"
  "generated/helper_contract_map.json"
  "generated/tx_contract_map.json"
)
for f in "${required[@]}"; do
  if [[ -f "$f" ]]; then
    echo "[verify] OK: found $f"
  else
    echo "[verify] FAIL: missing required generated artifact $f"
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "[verify] release tree check FAILED"
  exit 1
fi

echo "[verify] release tree check passed"
