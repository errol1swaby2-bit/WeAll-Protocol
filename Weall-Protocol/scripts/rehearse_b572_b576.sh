#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-src:scripts}"
python3 scripts/gen_b572_b576_multimachine_soak_proof_v1_5.py
python3 scripts/gen_b572_b576_multimachine_soak_proof_v1_5.py --check
pytest -q tests/test_process_validator_soak_ipfs_panel_locked_economics.py
printf '[mechanics] OK: Batches 572-576 multi-machine/soak mechanics gate passed\n'
