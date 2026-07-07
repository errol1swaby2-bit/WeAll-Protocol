#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH=src:scripts python3 scripts/gen_b556_b561_final_missing_mechanics_proof_v1_5.py
PYTHONPATH=src:scripts python3 scripts/gen_b562_b566_mechanics_hardening_proof_v1_5.py
PYTHONPATH=src:scripts pytest -q tests/test_validator_follower_catchup_storage_anti_sybil_locked_economics.py
PYTHONPATH=src:scripts python3 scripts/gen_b556_b561_final_missing_mechanics_proof_v1_5.py --check
PYTHONPATH=src:scripts python3 scripts/gen_b562_b566_mechanics_hardening_proof_v1_5.py --check
echo "[mechanics] OK: Batches 562-566 mechanics hardening gate passed"
