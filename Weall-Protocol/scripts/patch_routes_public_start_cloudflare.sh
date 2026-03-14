#!/usr/bin/env bash
set -euo pipefail

FILE="src/weall/api/routes_public.py"

if [[ ! -f "$FILE" ]]; then
  echo "ERROR: $FILE not found (run from repo root)." >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
BAK="${FILE}.bak.${TS}"
cp -f "$FILE" "$BAK"
echo "Backup created: $BAK"

python3 - <<'PY'
from __future__ import annotations
from pathlib import Path
import re
import sys

path = Path("src/weall/api/routes_public.py")
s = path.read_text(encoding="utf-8")

# Locate the start route function block
m = re.search(r'(?ms)@router\.post\(\s*"/v1/poh/email/start"\s*\)\s*\nasync\s+def\s+v1_poh_email_start\([^)]*\):\s*\n(.*?)(?=^\s*@router\.|\Z)', s)
if not m:
    print("ERROR: could not locate v1_poh_email_start route block", file=sys.stderr)
    sys.exit(1)

block = m.group(0)

# Try to find a call like: svc.start(...)
# It may be `verdict = svc.start(...)` or `out = svc.start(...)` etc.
cm = re.search(r'(?ms)\b(\w+)\s*=\s*svc\.start\(\s*(.*?)\s*\)\s*', block)
if not cm:
    # Fall back to any svc.start(...) call
    cm = re.search(r'(?ms)\bsvc\.start\(\s*(.*?)\s*\)\s*', block)
    if not cm:
        print("ERROR: could not locate any `svc.start(...)` call within v1_poh_email_start", file=sys.stderr)
        sys.exit(1)

    args = cm.group(1)
    already = ("email=" in args)
    if already:
        print("Already patched: svc.start already includes email=")
        sys.exit(0)

    args_stripped = args.strip()
    if args_stripped and not args_stripped.endswith(","):
        args_stripped = args_stripped + ","

    patched_args = (
        args_stripped
        + "\n        email=req.email,"
        + "\n    "
    )

    new_call = f"svc.start(\n        {patched_args}\n    )"
    block2 = block[:cm.start()] + new_call + block[cm.end():]
else:
    lhs = cm.group(1)
    args = cm.group(2)

    if "email=" in args:
        print("Already patched: svc.start already includes email=")
        sys.exit(0)

    args_stripped = args.strip()
    if args_stripped and not args_stripped.endswith(","):
        args_stripped = args_stripped + ","

    patched_args = (
        args_stripped
        + "\n        email=req.email,"
        + "\n    "
    )

    new_call = f"{lhs} = svc.start(\n        {patched_args}\n    )"
    block2 = block[:cm.start()] + new_call + block[cm.end():]

# Replace block back into file
s2 = s[:m.start()] + block2 + s[m.end():]
path.write_text(s2, encoding="utf-8")
print("Patched routes_public.py: added email=req.email to svc.start call in /v1/poh/email/start.")
PY

echo "Running syntax check..."
python3 -m py_compile "$FILE"

echo "OK: patch applied cleanly."
echo
echo "Next: restart API (docker compose up -d --build --force-recreate) and re-check /openapi.json."
