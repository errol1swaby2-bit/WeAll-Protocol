#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FREEZE=""; ACTORS=""; CHECK_ONLY=0
usage(){ cat <<'USAGE'
Usage: scripts/close_m1_m3.sh --implementation-freeze COMMIT --actor-manifest PATH [--check-only]

Golden-path orchestrator. It validates source and upgrade safety, then validates
or builds fresh freeze-bound evidence. It intentionally never creates a Git
commit; evidence commits remain an explicit reviewed operator action.
USAGE
}
while [[ $# -gt 0 ]]; do case "$1" in
  --implementation-freeze) FREEZE="${2:?missing commit}"; shift 2;;
  --actor-manifest) ACTORS="${2:?missing path}"; shift 2;;
  --check-only) CHECK_ONLY=1; shift;;
  -h|--help) usage; exit 0;;
  *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2;;
esac; done
[[ -n "$FREEZE" && -n "$ACTORS" ]] || { echo 'ERROR: implementation freeze and actor manifest are required.' >&2; exit 2; }
bash "$ROOT/scripts/test_m1_m3_source.sh"
bash "$ROOT/scripts/test_upgrade_safety.sh"
if [[ $CHECK_ONLY -eq 1 ]]; then
  bash "$ROOT/scripts/build_m1_m3_evidence.sh" --implementation-freeze "$FREEZE" --actor-manifest "$ACTORS" --check-only
  echo 'OK: closure prerequisites passed; no evidence or commit created.'
else
  bash "$ROOT/scripts/build_m1_m3_evidence.sh" --implementation-freeze "$FREEZE" --actor-manifest "$ACTORS"
  echo 'Next action: review evidence paths, stage them, run cached validators, and create one direct-child evidence-only commit.'
fi
