#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_PATH="${1:-${WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE:-}}"
OUT_PATH="${2:-${WEALL_NODE_OPERATOR_ENV_FILE:-${ROOT_DIR}/.weall-node-operator.env}}"
MANIFEST_PATH="${WEALL_CHAIN_MANIFEST_PATH:-${ROOT_DIR}/configs/chains/weall-genesis.json}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[ -n "${BUNDLE_PATH}" ] || fail "usage: $0 <node-operator-onboarding-bundle.json> [out-env-file]"
[ -f "${BUNDLE_PATH}" ] || fail "bundle not found: ${BUNDLE_PATH}"
[ -f "${MANIFEST_PATH}" ] || fail "chain manifest not found: ${MANIFEST_PATH}"

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
python3 "${ROOT_DIR}/scripts/install_node_operator_onboarding_bundle.py" \
  --bundle "${BUNDLE_PATH}" \
  --manifest "${MANIFEST_PATH}" \
  --out "${OUT_PATH}" \
  --force \
  --print-source-command

cat <<MSG
OK: public node-operator bundle anchors installed
- env file: ${OUT_PATH}
- source it before running operator preflight scripts
- this file contains public anchors only; configure local node signing keys separately
MSG
