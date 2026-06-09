#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b534_b538_completion_proof_v1_5.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" pytest -q tests/test_batch534_538_completion_mechanics.py
echo "[mechanics] OK: Batches 534-538 full node/lifecycle completion gate passed"
