#!/usr/bin/env bash
set -euo pipefail

# Demo/conference preflight. This keeps demo oracle access explicit and pinned to
# the deterministic demo chain. It does not mutate state or require production
# secrets.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-demo.json}"

fail() {
  echo "ERROR: $*" >&2
  exit 2
}

[ -f "${MANIFEST}" ] || fail "demo chain manifest not found: ${MANIFEST}"

export WEALL_MODE="demo"
export WEALL_RUNTIME_PROFILE="seeded_demo"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST}"
export WEALL_REQUIRE_CHAIN_MANIFEST="1"
export WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-1}"
export WEALL_ORACLE_PROFILE="demo"

bash "${ROOT_DIR}/scripts/demo_oracle_env_check.sh"

if [ -n "${WEALL_DEMO_ORACLE_URL:-${WEALL_EMAIL_ORACLE_URL:-}}" ]; then
  bash "${ROOT_DIR}/scripts/demo_oracle_smoke.sh"
else
  echo "WARN: no demo oracle URL set; skipped remote /healthz smoke" >&2
fi

cat <<MSG
OK: demo full oracle preflight passed
- demo manifest is pinned
- demo chain id/genesis/tx-index anchors are explicit
- demo oracle profile is isolated from production
MSG
