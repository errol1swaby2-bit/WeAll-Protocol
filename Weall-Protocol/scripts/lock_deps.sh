#!/usr/bin/env bash
set -euo pipefail

# Generate fully pinned lockfiles for reproducible installs.
#
# Usage:
#   ./scripts/lock_deps.sh
#
# Output:
#   requirements.lock
#   requirements-dev.lock
#
# Notes:
# - Uses pip-tools (pip-compile).
# - Pins ALL transitive dependencies.
# - Keeps separate dev lockfile for tests/tooling.
#
# If pip-compile isn't installed:
#   pip install pip-tools

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v pip-compile >/dev/null 2>&1; then
  echo "ERROR: pip-compile not found."
  echo "Install it with: pip install pip-tools"
  exit 1
fi

PYTHON_BIN="${PYTHON_BIN:-python}"

echo "Using python: $($PYTHON_BIN --version)"
echo "Generating requirements.lock from requirements.in ..."
pip-compile \
  --resolver=backtracking \
  --strip-extras \
  --no-emit-index-url \
  --no-emit-trusted-host \
  --output-file requirements.lock \
  requirements.in

echo "Generating requirements-dev.lock from requirements-dev.in ..."
pip-compile \
  --resolver=backtracking \
  --strip-extras \
  --no-emit-index-url \
  --no-emit-trusted-host \
  --output-file requirements-dev.lock \
  requirements-dev.in

echo "Done."
echo "Created:"
echo "  - requirements.lock"
echo "  - requirements-dev.lock"
