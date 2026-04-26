#!/usr/bin/env bash
set -euo pipefail

# Controlled-devnet bidirectional convergence probe.
# This wrapper intentionally uses normal public tx submission, verified state
# sync, and state-root comparison. It never calls seeded-demo endpoints.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

NODE1_API="${NODE1_API:-http://127.0.0.1:8001}"
NODE2_API="${NODE2_API:-http://127.0.0.1:8002}"
WORKSPACE="${WEALL_DEVNET_CROSS_NODE_DIR:-${REPO_ROOT}/.weall-devnet/cross-node}"
JOIN_ANCHOR_PATH="${WEALL_JOIN_ANCHOR_PATH:-}"

args=(
  --node1-api "${NODE1_API}"
  --node2-api "${NODE2_API}"
  --workspace "${WORKSPACE}"
)

if [[ -n "${JOIN_ANCHOR_PATH}" ]]; then
  args+=(--join-anchor-path "${JOIN_ANCHOR_PATH}")
fi

exec python3 scripts/devnet_cross_node_convergence.py "${args[@]}" "$@"
