#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH=src python3 scripts/gen_b505_b509_mechanics_proof_v1_5.py
PYTHONPATH=src python3 scripts/gen_b505_b509_mechanics_proof_v1_5.py --check
PYTHONPATH=src pytest -q tests/test_adversarial_bft_state_sync_poh_appeal_governance_vectors.py
printf '[mechanics] OK: Batches 505-509 adversarial mechanics gate passed\n'
