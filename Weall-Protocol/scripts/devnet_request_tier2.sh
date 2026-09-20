#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "NOTICE: devnet_request_tier2.sh is a compatibility alias; canonical Tier-2 verification is Live PoH." >&2
exec bash "$ROOT/scripts/devnet_request_live.sh" "$@"
