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
BAK="${FILE}.bak.fixbuild.${TS}"
cp -f "$FILE" "$BAK"
echo "Backup created: $BAK"
echo "Fixing environment nested under build:, and setting $KEY=$VALUE"

export WEALL_PATCH_KEY="$KEY"
export WEALL_PATCH_VALUE="$VALUE"

python3 - <<'PY'
from __future__ import annotations
from pathlib import Path
import os
import re
import sys
from typing import List, Tuple, Dict

KEY = os.environ.get("WEALL_PATCH_KEY", "").strip()
VALUE = os.environ.get("WEALL_PATCH_VALUE", "").strip()
if not KEY or not VALUE:
    print("ERROR: missing WEALL_PATCH_KEY/WEALL_PATCH_VALUE", file=sys.stderr)
    sys.exit(1)

path = Path("docker-compose.yml")
lines = path.read_text(encoding="utf-8").splitlines(True)

svc_header_re = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):\s*$")
kv_re = re.compile(r"^(\s*)([A-Za-z0-9_.-]+)\s*:\s*(.*)?$")

def block_range_for_service(service: str) -> Tuple[int,int,int]:
    for i, ln in enumerate(lines):
        m = svc_header_re.match(ln)
        if m and m.group(2) == service:
            indent = len(m.group(1))
            j = i + 1
            while j < len(lines):
                m2 = svc_header_re.match(lines[j])
                if m2:
                    ind2 = len(m2.group(1))
                    if ind2 == indent and m2.group(2) != service:
                        break
                    if ind2 < indent:
                        break
                j += 1
            return i, j, indent
    raise SystemExit(f"ERROR: service not found: {service}")

def extract_env_block(block: List[str], env_indent: int, env_start_idx: int) -> Tuple[int,int,List[str]]:
    start = env_start_idx
    i = env_start_idx + 1
    entries: List[str] = []
    while i < len(block):
        ln = block[i]
        m = kv_re.match(ln)
        if m and len(m.group(1)) <= env_indent:
            break
        entries.append(ln)
        i += 1
    end = i
    return start, end, entries

def parse_env_entries_to_map(entries: List[str]) -> Dict[str,str]:
    out: Dict[str,str] = {}
    for ln in entries:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("- "):
            rest = s[2:].strip()
            if "=" in rest:
                k, v = rest.split("=", 1)
                out[k.strip()] = v.strip()
            continue
        if ":" in s:
            k, v = s.split(":", 1)
            out[k.strip()] = v.strip()
    return out

def env_map_to_lines(env_indent: int, env_map: Dict[str,str]) -> List[str]:
    entry_indent = " " * (env_indent + 2)
    out: List[str] = []
    for k in sorted(env_map.keys()):
        out.append(f"{entry_indent}{k}: {env_map[k]}\n")
    return out

def ensure_service_env(block: List[str], svc_indent: int) -> Tuple[List[str], int]:
    env_indent = svc_indent + 2
    for idx, ln in enumerate(block):
        if re.match(rf"^\s{{{env_indent}}}environment:\s*$", ln):
            return block, idx

    # insert after container_name if present, else right after header
    insert_at = 1
    for idx, ln in enumerate(block):
        if re.match(rf"^\s{{{env_indent}}}container_name:\s*.*$", ln):
            insert_at = idx + 1
            break

    env_header = " " * env_indent + "environment:\n"
    block = block[:insert_at] + [env_header] + block[insert_at:]
    return block, insert_at

def move_env_out_of_build(block: List[str], svc_indent: int) -> List[str]:
    env_indent = svc_indent + 2
    build_indent = env_indent
    build_child_indent = build_indent + 2

    # find build:
    build_idx = None
    for i, ln in enumerate(block):
        if re.match(rf"^\s{{{build_indent}}}build:\s*$", ln):
            build_idx = i
            break
    if build_idx is None:
        return block

    # compute end of build block
    j = build_idx + 1
    build_end = j
    while build_end < len(block):
        m = kv_re.match(block[build_end])
        if m and len(m.group(1)) <= build_indent:
            break
        build_end += 1

    # find environment: inside build at child indent
    bad_env_idx = None
    for k in range(build_idx + 1, build_end):
        if re.match(rf"^\s{{{build_child_indent}}}environment:\s*$", block[k]):
            bad_env_idx = k
            break
    if bad_env_idx is None:
        return block

    st, en, entries = extract_env_block(block, build_child_indent, bad_env_idx)
    bad_map = parse_env_entries_to_map(entries)

    # delete the bad env block
    del block[st:en]

    # ensure service env exists
    block, _ = ensure_service_env(block, svc_indent)

    # find service env header
    env_hdr_idx = None
    for idx, ln in enumerate(block):
        if re.match(rf"^\s{{{env_indent}}}environment:\s*$", ln):
            env_hdr_idx = idx
            break
    if env_hdr_idx is None:
        raise SystemExit("ERROR: failed to ensure service env")

    st2, en2, entries2 = extract_env_block(block, env_indent, env_hdr_idx)
    good_map = parse_env_entries_to_map(entries2)

    # merge bad_map into good_map only for keys that aren't already present
    for k, v in bad_map.items():
        if k not in good_map:
            good_map[k] = v

    new_entries = env_map_to_lines(env_indent, good_map)
    block[st2:en2] = [block[env_hdr_idx]] + new_entries
    return block

def set_service_key(block: List[str], svc_indent: int, key: str, value: str) -> List[str]:
    env_indent = svc_indent + 2
    block, _ = ensure_service_env(block, svc_indent)

    env_hdr_idx = None
    for idx, ln in enumerate(block):
        if re.match(rf"^\s{{{env_indent}}}environment:\s*$", ln):
            env_hdr_idx = idx
            break
    if env_hdr_idx is None:
        raise SystemExit("ERROR: could not find service env header")

    st, en, entries = extract_env_block(block, env_indent, env_hdr_idx)
    env_map = parse_env_entries_to_map(entries)
    env_map[key] = value

    new_entries = env_map_to_lines(env_indent, env_map)
    block[st:en] = [block[env_hdr_idx]] + new_entries
    return block

def patch_service(service: str):
    start, end, indent = block_range_for_service(service)
    block = lines[start:end]
    block = move_env_out_of_build(block, indent)
    block = set_service_key(block, indent, KEY, VALUE)
    lines[start:end] = block

for svc in ("weall-api", "weall-producer"):
    patch_service(svc)

path.write_text("".join(lines), encoding="utf-8")
print("compose: fixed env placement and set WEALL_EMAIL_VERIFY_BASE_URL.")
PY

echo "Validating compose YAML..."
docker compose config >/dev/null

echo "OK: compose fixed. Now recreate:"
echo "  docker compose up -d --build --force-recreate"
