#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
FREEZE="${M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M3_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
FREEZE="$(git rev-parse "${FREEZE}^{commit}")"
MODE="${1:-}"
if [[ "${MODE}" == "--cached" ]]; then
  python3 scripts/check_m3_evidence_only_commit.py --mode staged --freeze-commit "${FREEZE}"
elif [[ -z "${MODE}" ]]; then
  python3 scripts/check_m3_evidence_only_commit.py --mode commit --freeze-commit "${FREEZE}" --commit HEAD
else
  echo "ERROR: unsupported argument: ${MODE}" >&2
  echo "Usage: $0 [--cached]" >&2
  exit 2
fi
echo "OK: M3 evidence-only commit integrity passed"
