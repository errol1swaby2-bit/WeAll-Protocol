#!/usr/bin/env bash
set -euo pipefail

# Convenience wrapper for the full-stack golden path python script.
#
# Usage:
#   ./scripts/golden_path_full_stack.sh
#
# Optional:
#   WEALL_API=http://127.0.0.1:8000 WEALL_CHAIN_ID=dev ./scripts/golden_path_full_stack.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

export PYTHONPATH="${REPO_ROOT}/src:${PYTHONPATH:-}"

python3 "${REPO_ROOT}/scripts/golden_path_full_stack.py"
