#!/usr/bin/env bash
set -euo pipefail

# Fail-closed preflight for controlled multi-node devnet readiness.
# This script validates mode/profile knobs before an external tester path is run.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${WEALL_API:-${API:-http://127.0.0.1:8001}}"

export WEALL_MODE="${WEALL_MODE:-devnet}"
export WEALL_RUNTIME_PROFILE="${WEALL_RUNTIME_PROFILE:-controlled_devnet}"
export WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-0}"
export WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE="${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-0}"
export WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"
export WEALL_ENABLE_OPERATOR_POH="${WEALL_ENABLE_OPERATOR_POH:-0}"
export WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE="${WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE:-0}"
export WEALL_ALLOW_DIRECT_SESSION_MUTATION="${WEALL_ALLOW_DIRECT_SESSION_MUTATION:-0}"

cd "${REPO_ROOT}"

/usr/bin/env python3 - <<'PY'
from __future__ import annotations

import os
import sys

sys.path.insert(0, "src")
from weall.api.mode_isolation import demo_mode_isolation_issue

issue = demo_mode_isolation_issue()
if issue:
    raise SystemExit(f"controlled-devnet preflight failed: {issue}")

print("controlled-devnet env preflight: ok")
print(f"mode={os.environ.get('WEALL_MODE', '')}")
print(f"runtime_profile={os.environ.get('WEALL_RUNTIME_PROFILE', '')}")
print(f"demo_seed_route={os.environ.get('WEALL_ENABLE_DEMO_SEED_ROUTE', '')}")
print(f"dev_bootstrap_secret_route={os.environ.get('WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE', '')}")
print(f"poh_bootstrap_open={os.environ.get('WEALL_POH_BOOTSTRAP_OPEN', '')}")
print(f"sigverify={os.environ.get('WEALL_SIGVERIFY', '')}")
print(f"strict_tx_sig_domain={os.environ.get('WEALL_STRICT_TX_SIG_DOMAIN', '')}")
print(f"operator_poh={os.environ.get('WEALL_ENABLE_OPERATOR_POH', '')}")
print(f"dev_session_create_route={os.environ.get('WEALL_ENABLE_DEV_SESSION_CREATE_ROUTE', '')}")
print(f"direct_session_mutation={os.environ.get('WEALL_ALLOW_DIRECT_SESSION_MUTATION', '')}")
PY

bash scripts/devnet_assert_no_operator_poh.sh
bash scripts/devnet_assert_no_direct_session_mutation.sh
python3 -S scripts/check_tx_canon_artifacts.py
echo "artifact hygiene: run scripts/devnet_assert_no_demo_artifacts.sh before publishing a tester bundle"

if command -v curl >/dev/null 2>&1; then
  echo "==> Optional live-node check: ${API}/v1/chain/identity"
  if curl -fsS "${API}/v1/chain/identity" >/tmp/weall-controlled-devnet-identity.json 2>/dev/null; then
    cat /tmp/weall-controlled-devnet-identity.json
    echo
  else
    echo "live-node check skipped: no node reachable at ${API}"
  fi
fi
