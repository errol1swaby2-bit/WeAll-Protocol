#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=src:scripts python3 scripts/gen_b523_b527_completion_proof_v1_5.py
PYTHONPATH=src pytest -q tests/test_batch523_527_completion_mechanics.py
PYTHONPATH=src python3 scripts/gen_b523_b527_completion_proof_v1_5.py --check
PYTHONPATH=src python3 scripts/gen_api_contract_map.py --check
printf '[mechanics] OK: Batches 523-527 completion mechanics gate passed\n'
