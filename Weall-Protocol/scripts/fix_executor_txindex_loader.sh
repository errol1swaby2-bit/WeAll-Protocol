#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

TARGET="src/weall/runtime/executor.py"
if [[ ! -f "$TARGET" ]]; then
  echo "ERROR: target file not found: $TARGET" >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP="${TARGET}.bak.${TS}"
cp -f "$TARGET" "$BACKUP"
echo "Backup created: $BACKUP"

python3 - <<'PY'
from pathlib import Path

path = Path("src/weall/runtime/executor.py")
s = path.read_text(encoding="utf-8")

before = s

# Fix: TxIndex.load(...) -> TxIndex.load_from_file(...)
s = s.replace("TxIndex.load(self.tx_index_path)", "TxIndex.load_from_file(self.tx_index_path)")

if s == before:
    raise SystemExit("ERROR: no change applied. Did you already fix it or is the line different?")

path.write_text(s, encoding="utf-8")
print("Patched executor.py: TxIndex.load -> TxIndex.load_from_file")
PY

echo "Running syntax check..."
python3 -m compileall -q src || { echo "ERROR: compileall failed"; exit 1; }

echo "Running tests..."
pytest -q

echo "OK: patch applied cleanly."
