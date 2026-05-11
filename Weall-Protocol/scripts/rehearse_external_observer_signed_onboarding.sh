#!/usr/bin/env bash
set -euo pipefail

# Human-friendly alias for the production-style external observer live gate.
# This path performs signed onboarding-safe tx submission against a remote
# genesis API and verifies committed account/PoH state visibility.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec bash "${ROOT_DIR}/scripts/external_observer_live_gate.sh" "$@"
