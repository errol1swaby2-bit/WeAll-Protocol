#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${PYTHONPATH:-src}"
pytest -q tests/test_behavior.py
python3 scripts/gen_b499_b503_mechanics_proof_v1_5.py >/dev/null
printf '[mechanics] OK: Batches 499-503 executable mechanics gate passed\n'
