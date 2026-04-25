#!/usr/bin/env bash
set -euo pipefail

NODE_API="${1:-${NODE_API:-http://127.0.0.1:8001}}"
OUT="${2:-${WEALL_JOIN_ANCHOR_PATH:-./.weall-devnet/join-anchor.json}}"
mkdir -p "$(dirname "${OUT}")"

curl -fsS "${NODE_API}/v1/chain/genesis" > "${OUT}"
echo "wrote ${OUT}"
cat "${OUT}"
echo
