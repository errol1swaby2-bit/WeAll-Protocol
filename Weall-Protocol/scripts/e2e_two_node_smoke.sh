#!/usr/bin/env bash
set -euo pipefail

# scripts/e2e_two_node_smoke.sh
#
# Multi-node smoke (in-process, deterministic):
# Runs the existing convergence test(s) as the smoke signal.
#
# Rationale:
# - Your test suite already contains hardened multi-node convergence coverage.
# - Running an explicit subset is a production runbook-friendly smoke check.

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
need pytest

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Two-node convergence smoke (pytest subset)"
echo "==> Running:"
echo "    - tests/test_e2e_two_node_convergence.py"
echo

pytest -q tests/test_e2e_two_node_convergence.py
