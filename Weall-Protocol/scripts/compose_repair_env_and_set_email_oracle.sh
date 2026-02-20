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
BAK="${FILE}.bak.repair.${TS}"
cp -f "$FILE" "$BAK"
echo "Backup created: $BAK"
echo "Repairing duplicate environment: blocks and setting $KEY=$VALUE"

export WEALL_PATCH_KEY="$KEY"
export WEALL_PATCH_VALUE="$VALUE"

python3 - <<'PY'
from __future__ import annotations
from pathlib import Path
import os
import re
import sys

KEY = os.environ.get("WEALL_PATCH_KEY", "").strip()
VALUE = os.environ.get("WEALL_PATCH_VALUE", "").strip()
if not KEY or not VALUE:
    print("ERROR: missing WEALL_PATCH_KEY/WEALL_PATCH_VALUE", file=sys.stderr)
    sys.exit(1)

path = Path("docker-compose.yml")
lines = path.read_text(encoding="utf-8").splitlines(True)

svc_name_re = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):\s*$")
key_line_re = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):\s*(.*)?$")

def find_service_block(name: str):
    # Find "  name:" line (any indent) and return [start, end, indent]
    for i, ln in enumerate(lines):
        m = svc_name_re.match(ln)
        if m and m.group(2) == name:
            indent = len(m.group(1))
            # end at next service header with same indent, or next top-level key with less indent
            j = i + 1
            while j < len(lines):
                m2 = svc_name_re.match(lines[j])
                if m2:
                    ind2 = len(m2.group(1))
                    # next sibling at same indent (another service) OR back to a parent section
                    if ind2 == indent and m2.group(2) != name:
                        break
                    if ind2 < indent:
                        break
                j += 1
            return i, j, indent
    return None

def parse_env_entries(block: list[str], env_header_idx: int, env_indent: int):
    """
    env_header_idx is index into block where 'environment:' line is.
    Collect following lines that belong to environment until next key at indent <= env_indent.
    Return (start_idx, end_idx, entries_lines)
    """
    start = env_header_idx
    i = env_header_idx + 1
    entries = []
    while i < len(block):
        ln = block[i]
        # Stop when we hit a YAML key at indent <= env_indent
        m = key_line_re.match(ln)
        if m and len(m.group(1)) <= env_indent and m.group(2) != "":
            break
        entries.append(ln)
        i += 1
    end = i
    return start, end, entries

def extract_env_key(line: str):
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    # list style: - KEY=VAL
    if s.startswith("- "):
        rest = s[2:].strip()
        if "=" in rest:
            return rest.split("=", 1)[0].strip()
        return None
    # map style: KEY: VAL
    if ":" in s and not s.startswith("-"):
        return s.split(":", 1)[0].strip()
    return None

def ensure_env_map_line(indent: str, key: str, value: str) -> str:
    return f"{indent}{key}: {value}\n"

def merge_env_blocks(block: list[str], service_indent: int) -> list[str]:
    """
    For a service block, merge duplicate 'environment:' keys at the service key indent.
    service_indent is indent of the service header (e.g., 2 for '  weall-api:').
    environment key indent is usually service_indent+2.
    """
    env_key_indent = service_indent + 2

    # Find all environment: headers at that indent
    env_headers = []
    for idx, ln in enumerate(block):
        if re.match(rf"^\s{{{env_key_indent}}}environment:\s*$", ln):
            env_headers.append(idx)

    if not env_headers:
        # No environment: block exists -> create one near top (after container_name if present, else after header)
        insert_at = 1
        for idx, ln in enumerate(block):
            if re.match(rf"^\s{{{env_key_indent}}}container_name:\s*.*$", ln):
                insert_at = idx + 1
                break
        env_entry_indent = " " * (env_key_indent + 2)
        new_env = [
            " " * env_key_indent + "environment:\n",
            ensure_env_map_line(env_entry_indent, KEY, VALUE),
        ]
        return block[:insert_at] + new_env + block[insert_at:]

    # Collect entries from all env blocks, preserving order: first block wins, later add missing keys
    env_entry_indent = " " * (env_key_indent + 2)

    # Parse all env blocks (start,end,entries)
    parsed = []
    for h in env_headers:
        st, en, entries = parse_env_entries(block, h, env_key_indent)
        parsed.append((st, en, entries))

    # Build ordered dict of key -> line, while preserving comments/blank lines too.
    ordered_lines = []
    seen_keys = set()

    def add_entries(entries: list[str]):
        nonlocal ordered_lines, seen_keys
        for ln in entries:
            k = extract_env_key(ln)
            if k is None:
                # keep comments/blank lines from the FIRST env block only (avoid duplicating)
                ordered_lines.append(ln)
                continue
            if k in seen_keys:
                continue
            seen_keys.add(k)
            # Normalize to map-style if list-style was used
            s = ln.strip()
            if s.startswith("- "):
                rest = s[2:].strip()
                if "=" in rest:
                    kk, vv = rest.split("=", 1)
                    ordered_lines.append(ensure_env_map_line(env_entry_indent, kk.strip(), vv.strip()))
                else:
                    # ignore malformed
                    continue
            else:
                # map style line: keep as-is but ensure it has correct indentation
                # if indentation differs, rewrite
                if not ln.startswith(env_entry_indent):
                    # rewrite with same key/value split
                    parts = s.split(":", 1)
                    kk = parts[0].strip()
                    vv = parts[1].strip()
                    ordered_lines.append(ensure_env_map_line(env_entry_indent, kk, vv))
                else:
                    ordered_lines.append(ln)

    # First env block: keep comments/blanks
    add_entries(parsed[0][2])

    # Subsequent blocks: add only keys (skip comments/blanks)
    for _, _, entries in parsed[1:]:
        for ln in entries:
            k = extract_env_key(ln)
            if k is None:
                continue
            if k in seen_keys:
                continue
            seen_keys.add(k)
            s = ln.strip()
            if s.startswith("- "):
                rest = s[2:].strip()
                if "=" in rest:
                    kk, vv = rest.split("=", 1)
                    ordered_lines.append(ensure_env_map_line(env_entry_indent, kk.strip(), vv.strip()))
            else:
                parts = s.split(":", 1)
                kk = parts[0].strip()
                vv = parts[1].strip()
                ordered_lines.append(ensure_env_map_line(env_entry_indent, kk, vv))

    # Ensure KEY is set/updated (remove existing line for KEY, then append correct one)
    new_ordered = []
    for ln in ordered_lines:
        k = extract_env_key(ln)
        if k == KEY:
            continue
        new_ordered.append(ln)
    new_ordered.append(ensure_env_map_line(env_entry_indent, KEY, VALUE))

    # Rebuild: keep everything except remove ALL env blocks, then insert ONE merged env block at first env location.
    first_start, first_end, _ = parsed[0]
    # Remove all env blocks ranges from bottom up
    remove_ranges = [(st, en) for st, en, _ in parsed]
    remove_ranges.sort(reverse=True)

    b = block[:]
    for st, en in remove_ranges:
        del b[st:en]

    # Insert merged env block at location of first_start (which is still correct after deletions above? not necessarily)
    # We want to insert at the position where the first env block used to start.
    insert_at = first_start
    if insert_at > len(b):
        insert_at = len(b)

    merged = [" " * env_key_indent + "environment:\n"] + new_ordered
    b = b[:insert_at] + merged + b[insert_at:]
    return b

# Apply to both services (and also any other services, just in case, to prevent future parse errors)
# We’ll attempt to merge duplicates for every service under services: by scanning indent level 2.
# But only ensure KEY is set for weall-api and weall-producer.

# First: repair duplicates for all services that have them
service_starts = []
for i, ln in enumerate(lines):
    m = svc_name_re.match(ln)
    if m:
        # heuristic: services entries typically indent >=2 and are not top-level sections like "services", "networks"
        name = m.group(2)
        if name not in ("services", "networks", "volumes"):
            service_starts.append((i, len(m.group(1)), name))

# Build unique list of names at indent >=2
names = []
seen = set()
for _, ind, nm in service_starts:
    if ind >= 2 and nm not in seen:
        seen.add(nm)
        names.append(nm)

def update_service(name: str, set_key: bool):
    found = find_service_block(name)
    if not found:
        return
    start, end, indent = found
    block = lines[start:end]
    # merge env blocks; this also creates env if missing
    merged_block = merge_env_blocks(block, indent)
    # If we don't want to set KEY for this service, remove KEY line we may have injected by env creation.
    if not set_key:
        env_entry_indent = " " * (indent + 4)
        merged_block2 = []
        in_env = False
        env_key_indent = indent + 2
        for ln in merged_block:
            if re.match(rf"^\s{{{env_key_indent}}}environment:\s*$", ln):
                in_env = True
                merged_block2.append(ln)
                continue
            if in_env:
                m = key_line_re.match(ln)
                if m and len(m.group(1)) <= env_key_indent:
                    in_env = False
                if in_env:
                    k = extract_env_key(ln)
                    if k == KEY:
                        continue
                    merged_block2.append(ln)
                    continue
            merged_block2.append(ln)
        merged_block = merged_block2

    lines[start:end] = merged_block

# Repair everything, but only set KEY for the two target services
for nm in names:
    update_service(nm, set_key=(nm in ("weall-api", "weall-producer")))

path.write_text("".join(lines), encoding="utf-8")
print("Repaired docker-compose.yml and set WEALL_EMAIL_VERIFY_BASE_URL for weall-api and weall-producer.")
PY

echo "Validating compose YAML..."
docker compose config >/dev/null

echo "OK: compose file repaired and $KEY set."
echo "Now run:"
echo "  docker compose up -d --build --force-recreate"
