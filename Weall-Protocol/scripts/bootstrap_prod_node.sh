#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CONFIG_PATH="${WEALL_CHAIN_CONFIG_PATH:-./configs/prod.chain.json}"
BUNDLE_OUT="${WEALL_BOOTSTRAP_BUNDLE_OUT:-generated/validator_bootstrap_bundle.json}"
VERIFY_OUT="${WEALL_BOOTSTRAP_VERIFY_OUT:-generated/validator_bootstrap_verify.json}"
INCIDENT_LANE_OUT="${WEALL_BOOTSTRAP_INCIDENT_LANE_OUT:-generated/operator_incident_lane.json}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

need_cmd python3
need_cmd docker
need_cmd curl

if [ ! -f "$CONFIG_PATH" ]; then
  echo "ERROR: production chain config not found: $CONFIG_PATH" >&2
  exit 1
fi

mkdir -p data generated data/ipfs secrets
chmod -R a+rwX data generated

if [ ! -f generated/tx_index.json ]; then
  echo "[bootstrap-prod] generating tx index"
  python3 scripts/gen_tx_index.py
fi

echo "[bootstrap-prod] building canonical bootstrap bundle"
PYTHONPATH=src WEALL_CHAIN_CONFIG_PATH="$CONFIG_PATH" python3 scripts/build_validator_bootstrap_bundle.py --out "$BUNDLE_OUT"

echo "[bootstrap-prod] running single public-validator preflight"
PYTHONPATH=src WEALL_CHAIN_CONFIG_PATH="$CONFIG_PATH" python3 scripts/public_validator_preflight.py --bundle "$BUNDLE_OUT" --incident-lane-out "$INCIDENT_LANE_OUT" --json > "$VERIFY_OUT"

cat <<MSG
[bootstrap-prod] production bootstrap prerequisites look sane.

Generated artifacts:
- Bootstrap bundle: ${ROOT_DIR}/${BUNDLE_OUT}
- Verification report: ${ROOT_DIR}/${VERIFY_OUT}
- Operator incident lane: ${ROOT_DIR}/${INCIDENT_LANE_OUT}

Next steps:
1. Ensure Docker secrets or *_FILE vars are set for node keys.
2. Review docs/production_node_bootstrap.md and docs/validator_bootstrap_verification.md.
3. Review the operator incident lane bundle before changing safe-mode posture.
4. Start the node in observer mode first.
5. Verify:
   - GET /v1/status
   - GET /v1/status/consensus
   - GET /v1/status/operator
6. Only after local bootstrap verification stays clean and the operator incident lane remains normal should validator signing / voting be enabled.
7. Re-run:
   - python3 scripts/public_validator_preflight.py --bundle "$BUNDLE_OUT" --incident-lane-out "$INCIDENT_LANE_OUT"
   - python3 scripts/build_operator_incident_report.py --include-lane-summary --lane-out "$INCIDENT_LANE_OUT"
MSG
