#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${ROOT_DIR}/web"
PROTO_DIR="${ROOT_DIR}/Weall-Protocol"

echo "==> Golden Path Regression"
echo "ROOT: ${ROOT_DIR}"
echo

echo "==> [1/4] Frontend: locked install"
cd "${WEB_DIR}"
npm ci
echo

echo "==> [2/4] Frontend: dependency audit + typecheck + build"
# Dependency vulnerabilities are a release gate. Never mutate dependencies inside
# a verification script; update package.json/package-lock.json intentionally.
npm run dependency-audit
npm run typecheck
npm run build
echo

echo "==> [3/4] Backend: pytest (contract + core PoH + content flow coverage)"
cd "${PROTO_DIR}"

# Fast, high-signal subset that covers the web<->backend surface congruity
pytest -q \
  tests/test_api_contract_shapes_minimal.py \
  tests/test_no_email_poh_code_remaining.py

# Core PoH flows + auth hardening
pytest -q \
  tests/test_apply_poh_flows_mvp.py \
  tests/test_apply_poh_tier2_flows_mvp.py \
  tests/test_apply_poh_live_auth_mvp.py \
  tests/test_apply_poh_live_hardening_mvp.py

# Content + governance high-signal invariants (keep these if they stay fast)
pytest -q \
  tests/test_gates_scoped_and_reputation.py \
  tests/test_poh_async_native_tier1.py \
  tests/test_no_required_external_identity_provider_artifacts.py \
  tests/test_prod_preflight_external_identity_free.py

echo

echo "==> [4/4] Full backend suite (optional, set FULL=1)"
if [[ "${FULL:-0}" == "1" ]]; then
  pytest
else
  echo "Skipping full suite. Run with FULL=1 to execute the full backend suite."
fi

echo
echo "✅ Golden Path Regression complete."
