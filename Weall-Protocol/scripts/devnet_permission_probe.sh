#!/usr/bin/env bash
set -euo pipefail

# Probe protocol permission gates through normal public transaction submission.
# This script creates a fresh Tier-0 account by default, then attempts direct API
# submissions for actions gated by Tier1/Tier2/Tier3/Juror. Forbidden probes must
# fail before canonical state mutation. No seeded demo routes are used.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

API="${WEALL_API:-http://127.0.0.1:8001}"
ACCOUNT="${WEALL_PERMISSION_PROBE_ACCOUNT:-}"
KEYFILE="${WEALL_PERMISSION_PROBE_KEYFILE:-}"

args=("--api" "$API")
if [[ -n "$ACCOUNT" ]]; then
  args+=("--account" "$ACCOUNT")
fi
if [[ -n "$KEYFILE" ]]; then
  args+=("--keyfile" "$KEYFILE")
fi

exec python3 -S ./scripts/devnet_permission_probe.py "${args[@]}" "$@"
