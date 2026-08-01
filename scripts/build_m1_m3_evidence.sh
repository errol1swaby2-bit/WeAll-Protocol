#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/m1_m3_common.sh"
FREEZE=""; ACTORS=""; CHECK_ONLY=0
usage(){ cat <<'USAGE'
Usage: scripts/build_m1_m3_evidence.sh --implementation-freeze COMMIT --actor-manifest PATH [--check-only]

Builds fresh M2 and M3 evidence only at an exact clean implementation freeze.
Historical M3 evidence is never copied or rebound. --check-only validates all
preconditions without starting nodes or creating artifacts.
USAGE
}
while [[ $# -gt 0 ]]; do case "$1" in
  --implementation-freeze) FREEZE="${2:?missing commit}"; shift 2;;
  --actor-manifest) ACTORS="${2:?missing path}"; shift 2;;
  --check-only) CHECK_ONLY=1; shift;;
  -h|--help) usage; exit 0;;
  *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2;;
esac; done
[[ -n "$FREEZE" && -n "$ACTORS" && -f "$ACTORS" ]] || { echo 'ERROR: freeze and existing actor manifest are required.' >&2; exit 2; }
read -r RESOLVED TREE < <(m13_require_git_freeze "$ROOT" "$FREEZE")
python3 "$ROOT/scripts/validate_m3_actor_manifest.py" --manifest "$ACTORS" --implementation-freeze "$RESOLVED" >/dev/null
[[ $CHECK_ONLY -eq 1 ]] && { printf 'OK: evidence prerequisites passed for %s tree %s; no evidence created.\n' "$RESOLVED" "$TREE"; exit 0; }
M2_IMPLEMENTATION_FREEZE_COMMIT="$RESOLVED" bash "$ROOT/scripts/run_m2_complete_closure.sh"
M3_IMPLEMENTATION_FREEZE_COMMIT="$RESOLVED" WEALL_M3_ACTOR_MANIFEST="$ACTORS" bash "$ROOT/scripts/run_m3_complete_closure.sh"
echo 'Evidence generated. Next action: stage only approved evidence paths and run cached evidence-only validation.'
