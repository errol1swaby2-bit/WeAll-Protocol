#!/usr/bin/env bash
set -euo pipefail

FILE="docker-compose.yml"
if [[ ! -f "$FILE" ]]; then
  echo "ERROR: $FILE not found" >&2
  exit 1
fi

cp -f "$FILE" "${FILE}.bak_testnet_$(date +%Y%m%d_%H%M%S)"

# If already present, no-op
if grep -qE '^\s*WEALL_MODE:\s*"?testnet"?' "$FILE"; then
  echo "WEALL_MODE already present in $FILE"
  docker compose config >/dev/null && echo "compose: ok"
  exit 0
fi

# Patch YAML with a simple state machine:
# - For each service (weall-api and weall-producer), if an environment: block exists, insert WEALL_MODE under it.
# - If it doesn't exist, create environment: block under the service root (at same indentation level as other keys).
python3 - <<'PY'
from pathlib import Path
import re
import sys

file = Path("docker-compose.yml")
s = file.read_text(encoding="utf-8").splitlines(True)

services = ["weall-api", "weall-producer"]
done = {k: False for k in services}

def find_service_block(lines, name):
    # Find line index of "  name:" or "name:" (any indent, but must be a YAML key)
    for i, ln in enumerate(lines):
        if re.match(rf'^\s*{re.escape(name)}:\s*$', ln):
            indent = re.match(r'^(\s*)', ln).group(1)
            return i, indent
    return None, None

def block_end(lines, start_i, service_indent):
    # Ends when we hit a line that is a YAML key with indent <= service_indent and not blank/comment
    for j in range(start_i+1, len(lines)):
        ln = lines[j]
        if ln.strip() == "" or ln.lstrip().startswith("#"):
            continue
        ind = re.match(r'^(\s*)', ln).group(1)
        if len(ind) <= len(service_indent) and re.match(r'^\s*[A-Za-z0-9_.-]+:\s*', ln):
            return j
    return len(lines)

def has_env_key(lines, start, end, env_indent):
    pat = rf'^{re.escape(env_indent)}environment:\s*$'
    for i in range(start, end):
        if re.match(pat, lines[i]):
            return i
    return None

def insert_under_env(lines, env_line_i, env_indent):
    # env values are typically env_indent + "  "
    entry_indent = env_indent + "  "
    insert_i = env_line_i + 1
    # avoid inserting inside a blank/comment header by placing right after env line
    lines.insert(insert_i, f'{entry_indent}WEALL_MODE: "testnet"\n')

def ensure_env_block(lines, start, end, service_indent):
    # Insert an environment block right after the service header line.
    # Use indent = service_indent + "  " for keys under service.
    key_indent = service_indent + "  "
    env_indent = key_indent
    insert_i = start + 1
    lines.insert(insert_i, f'{env_indent}environment:\n')
    lines.insert(insert_i + 1, f'{env_indent}  WEALL_MODE: "testnet"\n')

for name in services:
    si, sind = find_service_block(s, name)
    if si is None:
        print(f"ERROR: could not find service '{name}' in docker-compose.yml", file=sys.stderr)
        sys.exit(2)

    end = block_end(s, si, sind)
    # Look for an environment: key at indent of keys under service
    key_indent = sind + "  "
    env_i = has_env_key(s, si, end, key_indent)

    if env_i is not None:
        insert_under_env(s, env_i, key_indent)
        done[name] = True
    else:
        ensure_env_block(s, si, end, sind)
        done[name] = True

file.write_text("".join(s), encoding="utf-8")
print("Patched docker-compose.yml: set WEALL_MODE=testnet for weall-api and weall-producer")
PY

docker compose config >/dev/null && echo "compose: ok"
