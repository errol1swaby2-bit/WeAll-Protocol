#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="${ROOT_DIR}/web"
PROTO_DIR="${ROOT_DIR}/Weall-Protocol"

echo "==> Golden Path Regression"
echo "ROOT: ${ROOT_DIR}"
echo

echo "==> [1/4] Frontend: npm ci + typecheck + build"
cd "${WEB_DIR}"
npm ci
npm run typecheck
npm run build
echo

echo "==> [2/4] Frontend: npm audit (safe auto-fix only)"
# Do NOT use --force in CI-like scripts; it can introduce breaking changes.
# This step is informational + safe auto-fix only.
npm audit || true
npm audit fix || true
npm run typecheck
npm run build
echo

echo "==> [3/4] Backend: pytest (contract + core PoH + content flow coverage)"
cd "${PROTO_DIR}"

# Fast, high-signal subset that covers the web<->backend surface congruity
pytest -q \
  tests/test_api_contract_shapes_minimal.py \
  tests/test_api_contracts_web_and_email_oracle.py

# Core PoH flows + auth hardening
pytest -q \
  tests/test_apply_poh_flows_mvp.py \
  tests/test_apply_poh_tier2_flows_mvp.py \
  tests/test_apply_poh_tier3_auth_mvp.py \
  tests/test_apply_poh_tier3_hardening_mvp.py

# Content + governance high-signal invariants (keep these if they stay fast)
pytest -q \
  tests/test_gates_scoped_and_reputation.py \
  tests/test_no_plaintext_email_on_chain.py

echo

echo "==> [4/4] Full backend suite (optional, set FULL=1)"
if [[ "${FULL:-0}" == "1" ]]; then
  pytest
else
  echo "Skipping full suite. Run with FULL=1 to execute all 705 tests."
fi

echo
echo "✅ Golden Path Regression complete."
