#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python scripts/gen_b567_b571_autonomous_mechanics_proof_v1_5.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" pytest -q tests/test_autonomous_validator_ipfs_anti_sybil_economics_read_models.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python scripts/gen_b567_b571_autonomous_mechanics_proof_v1_5.py --check
echo "[mechanics] OK: Batches 567-571 autonomous mechanics gate passed"
