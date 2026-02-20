#!/usr/bin/env bash
set -euo pipefail

FILE="docker-compose.yml"
KEY="WEALL_EMAIL_VERIFY_BASE_URL"
VALUE="${1:-https://cert.weallprotocol.xyz}"

if [[ ! -f "$FILE" ]]; then
  echo "ERROR: $FILE not found (run from repo root)." >&2
  exit 1
fi

TS="$(date +%Y%m%d_%H%M%S)"
BAK="${FILE}.bak.${TS}"
cp -f "$FILE" "$BAK"
echo "Backup created: $BAK"
echo "Setting $KEY=$VALUE in $FILE (services: weall-api, weall-producer)"

export WEALL_PATCH_KEY="$KEY"
export WEALL_PATCH_VALUE="$VALUE"

python3 - <<'PY'
from __future__ import annotations
from pathlib import Path
import os
import re
import sys

file_path = Path("docker-compose.yml")
s = file_path.read_text(encoding="utf-8")

KEY = os.environ.get("WEALL_PATCH_KEY", "").strip()
VALUE = os.environ.get("WEALL_PATCH_VALUE", "").strip()
TARGETS = ["weall-api", "weall-producer"]

if not KEY:
    print("ERROR: missing WEALL_PATCH_KEY", file=sys.stderr)
    sys.exit(1)
if not VALUE:
    print("ERROR: missing WEALL_PATCH_VALUE", file=sys.stderr)
    sys.exit(1)

def patch_service(text: str, service: str) -> str:
    # Capture the service block starting at "service:" until next top-level key.
    m = re.search(
        rf'(?ms)^\s*{re.escape(service)}:\s*\n(.*?)(?=^\s*[A-Za-z0-9_.-]+:\s*\n|\Z)',
        text
    )
    if not m:
        raise SystemExit(f"ERROR: service not found: {service}")

    block = m.group(0)

    # Replace existing KEY if present inside this service block.
    if re.search(rf'(?m)^\s*{re.escape(KEY)}\s*:\s*.*$', block):
        block2 = re.sub(
            rf'(?m)^(\s*{re.escape(KEY)}\s*:\s*).*$',
            rf'\1{VALUE}',
            block,
        )
        return text[:m.start()] + block2 + text[m.end():]

    # If environment: exists, insert the KEY under it.
    em = re.search(r'(?m)^(\s*)environment:\s*$\n', block)
    if em:
        env_indent = em.group(1)
        entry_indent = env_indent + "  "   # one level deeper
        insert_pos = em.end()
        block2 = block[:insert_pos] + f"{entry_indent}{KEY}: {VALUE}\n" + block[insert_pos:]
        return text[:m.start()] + block2 + text[m.end():]

    # No environment: block exists. Create one.
    # Determine base indent from service header.
    sh = re.search(rf'(?m)^(\s*){re.escape(service)}:\s*$', block)
    if not sh:
        raise SystemExit(f"ERROR: could not parse service header indent for {service}")

    base_indent = sh.group(1)
    child_indent = base_indent + "  "
    entry_indent = child_indent + "  "

    # Choose insertion point: after container_name if present; else after command/build; else after header.
    cn = re.search(r'(?m)^\s*container_name:\s*.*$\n', block)
    if cn:
        pos = cn.end()
    else:
        cmd = re.search(r'(?ms)^\s*command:\s*\n(?:^\s*-\s*.*\n)+', block)
        if cmd:
            pos = cmd.end()
        else:
            bld = re.search(r'(?ms)^\s*build:\s*\n(?:^\s+.*\n)+', block)
            pos = bld.end() if bld else sh.end()

    env_block = f"{child_indent}environment:\n{entry_indent}{KEY}: {VALUE}\n"
    block2 = block[:pos] + env_block + block[pos:]
    return text[:m.start()] + block2 + text[m.end():]

for svc in TARGETS:
    s = patch_service(s, svc)

file_path.write_text(s, encoding="utf-8")
print("Patched docker-compose.yml successfully.")
PY

echo "Validating compose YAML..."
docker compose config >/dev/null

echo "OK: $KEY set. Now rebuild/recreate:"
echo "  docker compose up -d --build --force-recreate"
