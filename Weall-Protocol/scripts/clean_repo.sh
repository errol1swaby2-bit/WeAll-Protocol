#!/usr/bin/env bash
set -euo pipefail

# Clean repo artifacts that should never be committed or shipped in release zips.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

echo "[clean] repo: $root_dir"

# Python caches / build artifacts
rm -rf .pytest_cache
find . -type d -name "__pycache__" -prune -exec rm -rf {} +
find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
rm -rf build dist .mypy_cache .ruff_cache .pyright .tox .nox

# Editor/OS noise
rm -rf .DS_Store Thumbs.db || true

# Compose backup files that accumulate during experiments
rm -f docker-compose.yml.bak* *.bak *.bak2 || true

echo "[clean] done"
