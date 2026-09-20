#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
FREEZE="${M1_M3_IMPLEMENTATION_FREEZE_COMMIT:-}"
[[ -n "${FREEZE}" ]] || { echo "ERROR: M1_M3_IMPLEMENTATION_FREEZE_COMMIT is required" >&2; exit 2; }
FREEZE="$(git rev-parse "${FREEZE}^{commit}")"
if [[ "${1:-}" == "--cached" ]]; then
  python3 scripts/check_m1_m3_integrated_evidence.py --mode staged --freeze-commit "${FREEZE}"
elif [[ $# -eq 0 ]]; then
  python3 scripts/check_m1_m3_integrated_evidence.py --mode commit --freeze-commit "${FREEZE}" --commit HEAD
else
  echo "Usage: $0 [--cached]" >&2
  exit 2
fi
