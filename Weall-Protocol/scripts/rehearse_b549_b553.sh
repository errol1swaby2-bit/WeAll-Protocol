#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b549_b553_private_testnet_candidate_proof_v1_5.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" pytest -q tests/test_batch549_553_completion_mechanics.py
PYTHONPATH="src:scripts${PYTHONPATH:+:$PYTHONPATH}" python3 scripts/gen_b549_b553_private_testnet_candidate_proof_v1_5.py --check
echo "[mechanics] OK: Batches 549-553 private testnet candidate hardening gate passed"
