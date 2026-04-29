#!/usr/bin/env bash
set -euo pipefail

# Adversarial harness: prove the join-anchor verifier rejects a peer whose
# expected chain_id has been tampered. This does not mutate node state.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_API="${1:-${NODE_API:-http://127.0.0.1:8001}}"
TMP_DIR="${TMPDIR:-/tmp}/weall-wrong-chain.$$"
mkdir -p "${TMP_DIR}"
trap 'rm -rf "${TMP_DIR}"' EXIT

cd "${REPO_ROOT}"
python3 scripts/devnet_join_anchor.py export --api "${NODE_API}" --out "${TMP_DIR}/anchor.json" >/dev/null
python3 scripts/devnet_join_anchor.py tamper \
  --in "${TMP_DIR}/anchor.json" \
  --out "${TMP_DIR}/wrong-chain.json" \
  --field chain_id \
  --value "weall-intentionally-wrong-chain" >/dev/null

if python3 scripts/devnet_join_anchor.py verify --api "${NODE_API}" --anchor "${TMP_DIR}/wrong-chain.json" >/tmp/weall-wrong-chain.out 2>/tmp/weall-wrong-chain.err; then
  echo "ERROR: wrong-chain anchor was accepted" >&2
  cat /tmp/weall-wrong-chain.out >&2 || true
  exit 1
fi

echo "==> OK: wrong-chain join anchor was rejected"
