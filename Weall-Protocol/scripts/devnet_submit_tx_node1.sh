#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
exec python3 scripts/devnet_tx.py --api "${NODE1_API:-http://127.0.0.1:8001}" submit-tx "$@"
