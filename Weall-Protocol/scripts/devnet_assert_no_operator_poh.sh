#!/usr/bin/env bash
set -euo pipefail

# Fail if operator-driven PoH controls are enabled in controlled devnet.
# Tier-2/Live readiness must be proven through protocol-assigned jurors and
# canonical transactions, not operator shortcut endpoints.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

export WEALL_MODE="${WEALL_MODE:-devnet}"
export WEALL_RUNTIME_PROFILE="${WEALL_RUNTIME_PROFILE:-controlled_devnet}"
export WEALL_ENABLE_DEMO_SEED_ROUTE="${WEALL_ENABLE_DEMO_SEED_ROUTE:-0}"
export WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE="${WEALL_ENABLE_DEV_BOOTSTRAP_SECRET_ROUTE:-0}"
export WEALL_POH_BOOTSTRAP_OPEN="${WEALL_POH_BOOTSTRAP_OPEN:-0}"
export WEALL_SIGVERIFY="${WEALL_SIGVERIFY:-1}"
export WEALL_STRICT_TX_SIG_DOMAIN="${WEALL_STRICT_TX_SIG_DOMAIN:-1}"

python3 -S - <<'PY'
from __future__ import annotations

import os
import sys

sys.path.insert(0, "src")
from weall.api.mode_isolation import operator_poh_env_issue

issue = operator_poh_env_issue(os.environ)
if issue:
    raise SystemExit(f"operator PoH disabled for controlled devnet: {issue}")
print("controlled-devnet operator PoH guard: ok")
PY
