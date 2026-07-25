#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/m3_common.sh"
m3_activate_venv
python "${ROOT}/scripts/check_m3_artifact_privacy.py" \
  --artifact-root "${M3_ARTIFACT_ROOT}" \
  --out "${M3_ARTIFACT_ROOT}/privacy/private-material-scan.json"
