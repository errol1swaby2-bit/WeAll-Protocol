#!/usr/bin/env bash
set -euo pipefail

NODE_API="${1:-${NODE_API:-http://127.0.0.1:8001}}"
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
need curl
need python3

curl -fsS "${NODE_API}/v1/chain/identity" | python3 -m json.tool
curl -fsS "${NODE_API}/v1/chain/state-root" | python3 -m json.tool
curl -fsS "${NODE_API}/v1/chain/genesis" | python3 -m json.tool
