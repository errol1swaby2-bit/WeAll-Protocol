#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

GENESIS_API_BASE="${WEALL_GENESIS_API_BASE:-}"
BUNDLE_PATH="${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-configs/chains/weall-genesis.json}"
ALLOW_PRIVATE="${WEALL_ALLOW_PRIVATE_GENESIS_API:-0}"
RUN_SIGNED="${WEALL_REVIEWER_RUN_SIGNED_ONBOARDING:-1}"
EVIDENCE_DIR="${WEALL_REVIEWER_EVIDENCE_DIR:-}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/reviewer_observer_rehearsal.sh --genesis-api-base <url> --bundle <path> [options]

Options:
  --genesis-api-base <url>       Genesis API base URL.
  --bundle <path>                Public observer bundle JSON.
  --manifest <path>              Chain manifest path.
  --allow-private-genesis-api    Allow private/LAN Genesis API for controlled rehearsal.
  --preflight-only               Run remote preflight but skip signed onboarding.
  --evidence-dir <path>          Directory for captured command output.
  -h, --help                     Show this help.

Purpose:
  Verify remote Genesis compatibility, then optionally run the signed observer
  onboarding proof from the observer machine.
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

truthy() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --genesis-api-base) GENESIS_API_BASE="${2:-}"; shift 2 ;;
    --bundle) BUNDLE_PATH="${2:-}"; shift 2 ;;
    --manifest) MANIFEST_PATH="${2:-}"; shift 2 ;;
    --allow-private-genesis-api) ALLOW_PRIVATE="1"; shift ;;
    --preflight-only) RUN_SIGNED="0"; shift ;;
    --evidence-dir) EVIDENCE_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "${GENESIS_API_BASE}" ]] || fail "--genesis-api-base is required"
[[ -n "${BUNDLE_PATH}" ]] || fail "--bundle is required"
[[ -f "${BUNDLE_PATH}" ]] || fail "bundle not found: ${BUNDLE_PATH}"
[[ -f "${MANIFEST_PATH}" ]] || fail "manifest not found: ${MANIFEST_PATH}"

if [[ -z "${EVIDENCE_DIR}" ]]; then
  EVIDENCE_DIR="${ROOT_DIR}/audit-metadata/reviewer-lan-rehearsal-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "${EVIDENCE_DIR}"

# shellcheck disable=SC1091
if [[ -x ".venv/bin/activate" ]]; then
  . .venv/bin/activate
fi

export WEALL_GENESIS_API_BASE="${GENESIS_API_BASE%/}"
export WEALL_API_BASE="${GENESIS_API_BASE%/}"
export WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE="${BUNDLE_PATH}"
export WEALL_CHAIN_MANIFEST_PATH="${MANIFEST_PATH}"
export WEALL_ALLOW_PRIVATE_GENESIS_API="${ALLOW_PRIVATE}"

echo "[reviewer-observer] verifying remote Genesis endpoints"

for path in /v1/health /v1/status /v1/chain/identity /v1/genesis/observer/readiness; do
  out="${EVIDENCE_DIR}/$(echo "${path}" | tr '/' '_' | sed 's/^_//').json"
  curl -fsS "${WEALL_GENESIS_API_BASE}${path}" | tee "${out}" >/dev/null
  echo "OK: ${path}"
done

echo "[reviewer-observer] verifying public observer bundle"

WEALL_ALLOW_PRIVATE_GENESIS_API="${ALLOW_PRIVATE}" \
python3 scripts/verify_node_operator_onboarding_bundle.py \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --json | tee "${EVIDENCE_DIR}/bundle_verify.json"

echo "[reviewer-observer] running remote preflight gate"

WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
bash scripts/first_external_observer_reproducibility_gate.sh "${BUNDLE_PATH}" \
  2>&1 | tee "${EVIDENCE_DIR}/remote_preflight.log"

if truthy "${RUN_SIGNED}"; then
  echo "[reviewer-observer] running signed observer onboarding gate"

  WEALL_RUN_TWO_MACHINE_OBSERVER_PREFLIGHT=1 \
  WEALL_RUN_SIGNED_OBSERVER_ONBOARDING=1 \
  bash scripts/first_external_observer_reproducibility_gate.sh "${BUNDLE_PATH}" \
    2>&1 | tee "${EVIDENCE_DIR}/signed_onboarding.log"

  cat <<MSG
OK: reviewer observer rehearsal passed
- remote Genesis compatibility passed
- signed observer onboarding gate passed
- evidence: ${EVIDENCE_DIR}
MSG
else
  cat <<MSG
OK: reviewer observer remote preflight passed
- signed observer onboarding skipped by request
- evidence: ${EVIDENCE_DIR}
MSG
fi
