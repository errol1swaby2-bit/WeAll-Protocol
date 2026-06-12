#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b556_b561_final_missing_mechanics_proof_v1_5.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" pytest -q tests/test_batch556_561_completion_mechanics.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b556_b561_final_missing_mechanics_proof_v1_5.py --check
echo "[mechanics] OK: Batches 556-561 final missing mechanics gate passed"
