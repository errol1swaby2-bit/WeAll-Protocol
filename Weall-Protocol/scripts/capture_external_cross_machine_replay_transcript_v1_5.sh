#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/capture_external_cross_machine_replay_transcript_v1_5.sh \
    --machine-id <external-machine-id> \
    --operator-id <external-operator-id> \
    --out-dir <evidence-dir> \
    [--chain-id-prefix <prefix>]

Captures one machine's replay evidence packet for AUD-618-P1-003 / A04-F002.
This is evidence capture only. It does not close AUD-618-P1-003 by itself,
claim public_beta_ready, claim mainnet readiness, or replace external review.

The strict capture verifies the same commit and same generated vector artifacts,
runs scripts/replay_consistency_audit.py,
scripts/rehearse_fresh_node_replay_sync_v1_5.py,
DB-backed fresh-node replay, the 236-type lifecycle corpus, scheduler/order
permutation checks, helper serial equivalence, failed-receipt replay, and
PYTHONHASHSEED values 1, 7, and 31337.

It writes LOCAL_MACHINE_REPLAY_EVIDENCE.json with
external_review_required_before_closure=true.

Run this separately on two external/physical machines, then aggregate with:

  python scripts/build_external_cross_machine_replay_transcript_v1_5.py \
    --packet <machine-a>/LOCAL_MACHINE_REPLAY_EVIDENCE.json \
    --packet <machine-b>/LOCAL_MACHINE_REPLAY_EVIDENCE.json \
    --machine-isolation two_physical_machines \
    --operator-attestation external_replay_operator_signed \
    --operator-signature '<controlled signature/reference>' \
    --out <aggregate>/TRANSCRIPT.json

Then validate the aggregate with:

  PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py \
    --kind external_cross_machine_replay_transcript \
    --strict-release \
    --path <aggregate>/TRANSCRIPT.json
USAGE
}

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      usage
      exit 0
      ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="\${PYTHON:-python}"
exec "$PYTHON_BIN" scripts/capture_a04_external_determinism_packet_v1_5.py "$@"
