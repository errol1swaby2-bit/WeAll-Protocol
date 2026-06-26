#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b556_b561_final_missing_mechanics_proof_v1_5.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" pytest -q tests/test_public_validator_state_sync_storage_anti_sybil_economics_boundaries.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b556_b561_final_missing_mechanics_proof_v1_5.py --check
echo "[mechanics] OK: Batches 556-561 final missing mechanics gate passed"
