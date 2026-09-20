#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "NOTICE: devnet_review_tier2.sh is a compatibility alias; canonical Tier-2 verification is Live PoH." >&2

export WEALL_LIVE_CASE_ID="${WEALL_LIVE_CASE_ID:-${WEALL_TIER2_CASE_ID:-}}"
export WEALL_LIVE_JUROR_ACCOUNT="${WEALL_LIVE_JUROR_ACCOUNT:-${WEALL_TIER2_JUROR_ACCOUNT:-${WEALL_ACCOUNT:-}}}"
export WEALL_LIVE_JUROR_KEYFILE="${WEALL_LIVE_JUROR_KEYFILE:-${WEALL_TIER2_JUROR_KEYFILE:-${WEALL_KEYFILE:-}}}"
export WEALL_LIVE_VERDICT="${WEALL_LIVE_VERDICT:-${WEALL_TIER2_VERDICT:-pass}}"

exec bash "$ROOT/scripts/devnet_review_live.sh" "$@"
