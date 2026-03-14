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

# Locate the confirm route function block
m = re.search(r'(?ms)@router\.post\(\s*"/v1/poh/email/confirm"\s*\)\s*\nasync\s+def\s+v1_poh_email_confirm\([^)]*\):\s*\n(.*?)(?=^\s*@router\.|\Z)', s)
if not m:
    print("ERROR: could not locate v1_poh_email_confirm route block", file=sys.stderr)
    sys.exit(1)

block = m.group(0)

# Find the svc.confirm(...) call within this block
cm = re.search(r'(?ms)\bverdict\s*=\s*svc\.confirm\(\s*(.*?)\s*\)\s*', block)
if not cm:
    print("ERROR: could not locate `verdict = svc.confirm(...)` within v1_poh_email_confirm", file=sys.stderr)
    sys.exit(1)

args = cm.group(1)

# If already patched (has remote_ip or turnstile_token), do nothing
if "remote_ip=" in args or "turnstile_token=" in args:
    print("Already patched: svc.confirm already includes oracle fields")
    sys.exit(0)

# We want to preserve existing arguments but append these kwargs:
#   email=getattr(req, "email", None),
#   turnstile_token=getattr(req, "turnstile_token", None),
#   remote_ip=(request.client.host if request.client else None),
#
# We will append safely with commas.
args_stripped = args.strip()

# Ensure trailing comma in existing args if needed
if args_stripped and not args_stripped.endswith(","):
    args_stripped = args_stripped + ","

patched_args = (
    args_stripped
    + "\n        email=getattr(req, \"email\", None),"
    + "\n        turnstile_token=getattr(req, \"turnstile_token\", None),"
    + "\n        remote_ip=(request.client.host if request.client else None),"
    + "\n    "
)

new_call = f"verdict = svc.confirm(\n        {patched_args}\n    )"

block2 = block[:cm.start()] + new_call + block[cm.end():]

# Replace block back into file
s2 = s[:m.start()] + block2 + s[m.end():]

path.write_text(s2, encoding="utf-8")
print("Patched routes_public.py: added email/turnstile_token/remote_ip to svc.confirm call.")
PY

echo "Running syntax check..."
python3 -m py_compile "$FILE"

echo "OK: patch applied cleanly."
echo
echo "Next: restart API (docker compose up -d --build --force-recreate) or rerun pytest if desired."
