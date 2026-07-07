#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Captures one machine's independent controlled validator/operator rehearsal evidence packet for AUD-618-P0-001.

This script is evidence-capture tooling only. It does not close AUD-618-P0-001 by itself, does not enable public validator admission, does not claim public multi-validator BFT readiness, and does not grant signing authority through local flags.

Usage:
  bash scripts/capture_independent_controlled_validator_operator_transcript_v1_5.sh \
    --operator-id <operator-id> \
    --machine-id <machine-id> \
    --node-id <node-id> \
    --out-dir <output-dir> [--chain-id <chain-id>] [--run-local-rehearsal]

Outputs:
  LOCAL_VALIDATOR_OPERATOR_EVIDENCE.json
  commands.txt
  CLAIM_BOUNDARIES.md
  manifest.json

Required external aggregate evidence before closure:
  - invited/independent operator identity and attestation;
  - fresh clone and exact commit/branch;
  - node registration transcript;
  - node-operator readiness transcript;
  - validator-candidate readiness path and readiness receipt;
  - controlled activation rehearsal proof;
  - observer bypass/vote rejection proof;
  - restart fail-closed proof unless chain state permits signing;
  - matching state roots across the controlled validator rehearsal;
  - strict-release validation of the aggregate transcript.
USAGE
}

operator_id=""
machine_id=""
node_id=""
out_dir=""
chain_id="weall-testnet-v1"
run_local_rehearsal=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --operator-id)
      operator_id="${2:-}"
      shift 2
      ;;
    --machine-id)
      machine_id="${2:-}"
      shift 2
      ;;
    --node-id)
      node_id="${2:-}"
      shift 2
      ;;
    --chain-id)
      chain_id="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --run-local-rehearsal)
      run_local_rehearsal=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$operator_id" || -z "$machine_id" || -z "$node_id" || -z "$out_dir" ]]; then
  echo "missing required --operator-id, --machine-id, --node-id, or --out-dir" >&2
  usage >&2
  exit 2
fi

mkdir -p "$out_dir"
commands_file="$out_dir/commands.txt"
{
  echo "# AUD-618-P0-001 independent controlled validator/operator rehearsal commands"
  echo "git rev-parse HEAD"
  echo "git status --short --untracked-files=all"
  echo "PYTHONPATH=src python scripts/validator_readiness_check.py --help"
  echo "PYTHONPATH=src python -m pytest -q tests/test_observer_to_validator_authority_path.py tests/test_validator_gate_and_observer_safety.py tests/test_validator_observer_restart_posture.py"
  echo "# Optional local rehearsal, still not external closure:"
  echo "bash scripts/external_observer_to_validator_live_gate.sh"
} > "$commands_file"

commit="unknown"
branch="unknown"
status="git_unavailable"
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  status="$(git status --short --untracked-files=all 2>/dev/null | sed ':a;N;$!ba;s/\n/\\n/g')"
  [[ -z "$status" ]] && status="clean"
fi

local_rehearsal_summary="not_run"
if [[ "$run_local_rehearsal" -eq 1 ]]; then
  if bash scripts/external_observer_to_validator_live_gate.sh > "$out_dir/local-rehearsal.log" 2>&1; then
    local_rehearsal_summary="passed_local_rehearsal_not_external_closure"
  else
    local_rehearsal_summary="failed_local_rehearsal_see_log"
  fi
fi

python3 - "$out_dir/LOCAL_VALIDATOR_OPERATOR_EVIDENCE.json" <<'PY' \
  "$operator_id" "$machine_id" "$node_id" "$chain_id" "$commit" "$branch" "$status" "$local_rehearsal_summary"
import hashlib, json, sys
from pathlib import Path
out = Path(sys.argv[1])
operator_id, machine_id, node_id, chain_id, commit, branch, status, rehearsal = sys.argv[2:]
payload = {
    "schema": "weall.v1_5.local_validator_operator_evidence_packet",
    "blocker": "AUD-618-P0-001",
    "operator_id": operator_id,
    "machine_id": machine_id,
    "node_id": node_id,
    "chain_id": chain_id,
    "commit": commit,
    "branch": branch,
    "git_status": status,
    "fresh_clone_required_for_closure": True,
    "node_registration_required": True,
    "node_operator_readiness_required": True,
    "validator_candidate_path_required": True,
    "readiness_receipt_required": True,
    "activation_rehearsal_required": True,
    "observer_bypass_rejection_required": True,
    "restart_fail_closed_required_unless_chain_state_permits_signing": True,
    "local_rehearsal_summary": rehearsal,
    "aggregate_transcript_template": "docs/proofs/independent-controlled-validator-operator/2026-07-05/TRANSCRIPT_TEMPLATE.json",
    "strict_release_validator": "PYTHONPATH=src:scripts python scripts/validate_external_operator_transcript_v1_5.py --kind public_validator_operator_transcript --strict-release --path <TRANSCRIPT.json>",
    "claim_boundaries": {
        "public_beta_ready": False,
        "mainnet_ready": False,
        "public_validator_enabled": False,
        "public_multi_validator_bft": False,
        "live_economics": False,
        "automatic_protocol_upgrades": False,
        "production_helper_execution": False,
        "legal_compliance_ready": False,
    },
    "external_review_required_before_closure": True,
}
payload["packet_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cat > "$out_dir/CLAIM_BOUNDARIES.md" <<'EOF_BOUNDARIES'
# Claim boundaries for AUD-618-P0-001 packet

This packet is local machine evidence for an independent controlled validator/operator rehearsal.
It does not close AUD-618-P0-001 by itself.

Do not claim:

- public beta readiness;
- public mainnet readiness;
- public validator safety;
- public multi-validator BFT readiness;
- live economics;
- automatic protocol upgrades;
- production helper execution;
- legal/compliance approval.
EOF_BOUNDARIES

python3 - "$out_dir/manifest.json" "$out_dir" <<'PY'
import hashlib, json, sys
from pathlib import Path
manifest = Path(sys.argv[1])
root = Path(sys.argv[2])
files = {}
for path in sorted(root.iterdir()):
    if path.is_file() and path.name != "manifest.json":
        files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
manifest.write_text(json.dumps({
    "schema": "weall.v1_5.validator_operator_packet_manifest",
    "blocker": "AUD-618-P0-001",
    "files": files,
    "does_not_close_blocker": True,
    "external_review_required_before_closure": True,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "Wrote AUD-618-P0-001 local validator/operator evidence packet to $out_dir"
echo "This packet does not close AUD-618-P0-001; attach external aggregate transcript and run strict-release validation."
