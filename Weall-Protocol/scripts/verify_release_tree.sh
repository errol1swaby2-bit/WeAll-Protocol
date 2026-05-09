#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTER_ROOT="$(cd "$ROOT/.." && pwd)"
WEB_ROOT="$OUTER_ROOT/web"
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

check_web_path_absent() {
  local pattern="$1"
  local label="$2"
  if [[ ! -d "$WEB_ROOT" ]]; then
    echo "[verify] OK: no outer web tree present for $label scan"
    return
  fi
  if find "$WEB_ROOT" -path "$WEB_ROOT/node_modules" -prune -o -path "$WEB_ROOT/dist" -prune -o -name "$pattern" -print | grep -q .; then
    echo "[verify] FAIL: found $label"
    find "$WEB_ROOT" -path "$WEB_ROOT/node_modules" -prune -o -path "$WEB_ROOT/dist" -prune -o -name "$pattern" -print
    fail=1
  else
    echo "[verify] OK: no $label"
  fi
}

check_web_dir_absent() {
  local pattern="$1"
  local label="$2"
  if [[ ! -d "$WEB_ROOT" ]]; then
    echo "[verify] OK: no outer web tree present for $label scan"
    return
  fi
  if find "$WEB_ROOT" -type d -name "$pattern" -print | grep -q .; then
    echo "[verify] FAIL: found $label"
    find "$WEB_ROOT" -type d -name "$pattern" -print
    fail=1
  else
    echo "[verify] OK: no $label"
  fi
}


check_secret_tree_safe() {
  if [[ ! -d "secrets" ]]; then
    echo "[verify] OK: no secrets directory present"
    return
  fi

  local bad
  bad="$(find secrets -mindepth 1 \
    ! -path 'secrets/.gitignore' \
    ! -path 'secrets/README.md' \
    ! -path 'secrets/README' \
    -print || true)"
  if [[ -n "$bad" ]]; then
    echo "[verify] FAIL: found raw secrets directory material"
    echo "$bad"
    echo "[verify] hint: move local node keys outside the repo or remove secrets/* before release checks"
    fail=1
  else
    echo "[verify] OK: no raw secrets directory material"
  fi
}

check_path_absent '*.pyc' 'Python bytecode files'
check_dir_absent '__pycache__' '__pycache__ directories'
check_dir_absent '.pytest_cache' '.pytest_cache directories'
check_dir_absent '*.egg-info' 'Python egg-info directories'
check_path_absent '*.tsbuildinfo' 'TypeScript build info files'
check_dir_absent 'node_modules' 'node_modules directories'
check_dir_absent 'dist' 'frontend dist directories'
check_web_path_absent '*.tsbuildinfo' 'outer web TypeScript build info files'
check_web_dir_absent 'node_modules' 'outer web node_modules directories'
check_web_dir_absent 'dist' 'outer web dist directories'
check_dir_absent '.provider-cli' 'provider local state directories'
check_path_absent '.env' '.env files'
check_path_absent '.env.local' '.env.local files'
check_secret_tree_safe
check_dir_absent '.weall-devnet' 'local devnet runtime directories'
check_dir_absent '.weall' 'local WeAll runtime directories'
check_dir_absent 'data' 'runtime data directories'
check_path_absent '*.db' 'SQLite database files'
check_path_absent '*.db-wal' 'SQLite WAL files'
check_path_absent '*.db-shm' 'SQLite shared-memory files'
check_path_absent '*.sqlite' 'SQLite files'
check_path_absent '*secret*.json' 'JSON secret artifacts'
check_path_absent 'demo_bootstrap_result.json' 'demo bootstrap result artifacts'
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

if python3 -S scripts/check_tx_canon_artifacts.py; then
  echo "[verify] OK: tx canon generated artifacts are synchronized"
else
  echo "[verify] FAIL: tx canon generated artifacts are stale or inconsistent"
  fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo "[verify] release tree check FAILED"
  exit 1
fi

echo "[verify] release tree check passed"
