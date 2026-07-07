#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b549_b553_controlled_testnet_candidate_proof_v1_5.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" pytest -q tests/test_public_write_validator_storage_anti_sybil_testnet_boundaries.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b549_b553_controlled_testnet_candidate_proof_v1_5.py --check
echo "[mechanics] OK: Batches 549-553 controlled testnet candidate hardening gate passed"
