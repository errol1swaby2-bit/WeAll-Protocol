#!/usr/bin/env bash
set -euo pipefail

# Controlled-devnet full onboarding path through protocol-native Tier 3:
# account -> Tier 1 email (when WEALL_EMAIL is set) -> Tier 2 async review
# -> Tier 3 live-review attestations -> cross-node sync/root comparison.
# This is a convenience wrapper around devnet_full_onboarding_e2e.sh and never
# calls demo seed routes.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export WEALL_DEVNET_RUN_TIER2="${WEALL_DEVNET_RUN_TIER2:-1}"
export WEALL_DEVNET_RUN_TIER3="${WEALL_DEVNET_RUN_TIER3:-1}"
export WEALL_TIER3_JUROR_COUNT="${WEALL_TIER3_JUROR_COUNT:-10}"

exec bash "$ROOT/scripts/devnet_full_onboarding_e2e.sh" "$@"
