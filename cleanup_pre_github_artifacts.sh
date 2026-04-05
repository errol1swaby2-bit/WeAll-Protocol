#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-$HOME/WeAll-Protocol/Weall-Protocol}"

cd "$REPO_ROOT"

echo "Cleaning known stray files in: $REPO_ROOT"

rm -f "teststest_helper_lane_journal_batch28.py"
rm -f "teststest_helper_merge_admission_batch28.py"
rm -f "teststest_helper_restart_replay_batch28.py"
rm -f "teststest_sqlite_family_tables_batch28.py"

rm -rf .pytest-b*
find . -type f \( -name "*.aux.sqlite" -o -name "*.bft_journal.jsonl" \) -delete
find . -type d -name "*.aux_helper_lanes" -prune -exec rm -rf {} +

echo "Done. Review the repo root manually for any additional stray files before commit."
