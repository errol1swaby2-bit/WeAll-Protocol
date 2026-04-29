#!/usr/bin/env bash
set -euo pipefail

# Verify a live peer against a locally pinned join-anchor file.
# Stable fields are always checked. Exact current state-sync anchor matching is
# optional because a healthy node may advance height after the anchor was
# exported; use WEALL_DEVNET_STRICT_JOIN_ANCHOR=1 for strict current-anchor mode.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_API="${1:-${NODE_API:-http://127.0.0.1:8001}}"
ANCHOR="${2:-${WEALL_JOIN_ANCHOR_PATH:-./.weall-devnet/join-anchor.json}}"
STRICT="${WEALL_DEVNET_STRICT_JOIN_ANCHOR:-0}"

cd "${REPO_ROOT}"
args=(verify --api "${NODE_API}" --anchor "${ANCHOR}")
case "${STRICT}" in
  1|true|TRUE|yes|YES|on|ON) args+=(--strict-current-anchor) ;;
esac
python3 scripts/devnet_join_anchor.py "${args[@]}"
echo "==> OK: peer matches pinned join anchor: ${NODE_API}"
