#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=source; FREEZE=""; COMMIT=HEAD
usage(){ cat <<'USAGE'
Usage: scripts/check_m1_m3_closure.sh [--source-only] [--formal --implementation-freeze COMMIT [--evidence-commit COMMIT]]

Source-only validates implementation readiness without claiming evidence closure.
Formal validates a committed direct-child integrated evidence commit.
USAGE
}
while [[ $# -gt 0 ]]; do case "$1" in
  --source-only) MODE=source; shift;;
  --formal) MODE=formal; shift;;
  --implementation-freeze) FREEZE="${2:?missing commit}"; shift 2;;
  --evidence-commit) COMMIT="${2:?missing commit}"; shift 2;;
  -h|--help) usage; exit 0;;
  *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2;;
esac; done
if [[ "$MODE" == source ]]; then
  bash "$ROOT/scripts/test_m1_m3_source.sh"
  bash "$ROOT/scripts/test_upgrade_safety.sh"
  echo 'OK: source readiness passed. Formal closure remains a separate freeze-bound evidence claim.'
  exit 0
fi
[[ -n "$FREEZE" ]] || { echo 'ERROR: formal mode requires --implementation-freeze.' >&2; exit 2; }
python3 "$ROOT/scripts/check_m1_m3_integrated_evidence.py" --mode commit --freeze-commit "$FREEZE" --commit "$COMMIT"
