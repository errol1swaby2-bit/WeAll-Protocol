#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${PYTHONPATH:-src}"
python3 scripts/gen_b517_b521_completion_proof_v1_5.py
python3 scripts/gen_b517_b521_completion_proof_v1_5.py --check
pytest -q tests/test_batch517_521_completion_mechanics.py
echo "[mechanics] OK: Batches 517-521 completion mechanics gate passed"
