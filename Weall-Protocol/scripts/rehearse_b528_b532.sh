#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:-src:scripts}:src:scripts"
python3 scripts/gen_b528_b532_completion_proof_v1_5.py
python3 -m pytest -q tests/test_validator_db_lifecycle_reviewer_accountability_storage_coverage.py
printf '[mechanics] OK: Batches 528-532 live completion mechanics gate passed\n'
