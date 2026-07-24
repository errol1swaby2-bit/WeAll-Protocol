#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
FREEZE="${M2_IMPLEMENTATION_FREEZE_COMMIT:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M2_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
FREEZE="$(git rev-parse "${FREEZE}^{commit}")"
MODE="${1:-}"
if [[ "${MODE}" == "--cached" ]]; then
  python3 scripts/check_m2_evidence_manifest.py \
    --mode staged \
    --freeze-commit "${FREEZE}"
elif [[ -z "${MODE}" ]]; then
  python3 scripts/check_m2_evidence_manifest.py \
    --mode commit \
    --freeze-commit "${FREEZE}" \
    --commit HEAD
else
  echo "ERROR: unsupported argument: ${MODE}" >&2
  echo "Usage: $0 [--cached]" >&2
  exit 2
fi
echo "OK: M2 evidence-only commit integrity passed"
