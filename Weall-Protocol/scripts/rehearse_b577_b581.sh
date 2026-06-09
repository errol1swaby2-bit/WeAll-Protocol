#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHONPATH="src:scripts:${PYTHONPATH:-}" python3 scripts/gen_b577_b581_containerized_adversarial_proof_v1_5.py
PYTHONPATH="src:scripts:${PYTHONPATH:-}" pytest -q tests/test_batch577_581_completion_mechanics.py
PYTHONPATH="src:scripts:${PYTHONPATH:-}" python3 scripts/gen_b577_b581_containerized_adversarial_proof_v1_5.py --check
printf '[mechanics] OK: Batches 577-581 containerized/adversarial mechanics gate passed\n'
