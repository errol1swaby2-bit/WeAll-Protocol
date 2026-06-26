#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 scripts/gen_b510_b515_completion_proof_v1_5.py --write
PYTHONPATH=src pytest -q tests/test_coverage_behavior.py
printf '[mechanics] OK: Batches 510-515 completion mechanics gate passed\n'
