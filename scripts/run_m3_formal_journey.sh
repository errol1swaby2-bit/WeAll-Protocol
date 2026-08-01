#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/m1_m3_common.sh"
FREEZE=""; ACTORS=""; CHECK_ONLY=0
usage(){ cat <<'USAGE'
Usage: scripts/run_m3_formal_journey.sh --implementation-freeze COMMIT --actor-manifest PATH [--check-only]

Validates the freeze, clean worktree, actor-manifest presence, and evidence-path
preconditions. Without --check-only it delegates to the canonical signed M3
real-stack journey. Keys and custody material must remain outside the repository.
USAGE
}
while [[ $# -gt 0 ]]; do case "$1" in
  --implementation-freeze) FREEZE="${2:?missing commit}"; shift 2;;
  --actor-manifest) ACTORS="${2:?missing path}"; shift 2;;
  --check-only) CHECK_ONLY=1; shift;;
  -h|--help) usage; exit 0;;
  *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2;;
esac; done
[[ -n "$FREEZE" ]] || { echo 'ERROR: --implementation-freeze is required.' >&2; exit 2; }
[[ -n "$ACTORS" && -f "$ACTORS" ]] || { echo 'ERROR: --actor-manifest must name an existing private manifest.' >&2; exit 2; }
read -r RESOLVED TREE < <(m13_require_git_freeze "$ROOT" "$FREEZE")
printf 'implementation_commit=%s\nimplementation_tree=%s\nactor_manifest=%s\n' "$RESOLVED" "$TREE" "$ACTORS"
python3 "$ROOT/scripts/validate_m3_actor_manifest.py" --manifest "$ACTORS" --implementation-freeze "$RESOLVED" >/dev/null
[[ $CHECK_ONLY -eq 1 ]] && { echo 'OK: M3 formal journey prerequisites passed; no transaction submitted.'; exit 0; }
M3_IMPLEMENTATION_FREEZE_COMMIT="$RESOLVED" WEALL_M3_ACTOR_MANIFEST="$ACTORS" bash "$ROOT/scripts/run_m3_civic_real_stack_e2e.sh"
