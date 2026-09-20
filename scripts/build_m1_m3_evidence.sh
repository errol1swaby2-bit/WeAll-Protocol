#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/m1_m3_common.sh"

FREEZE=""
ACTORS=""
CHECK_ONLY=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/build_m1_m3_evidence.sh \
    --implementation-freeze COMMIT \
    --actor-manifest PATH \
    [--check-only]

Builds fresh M2 and M3 evidence only at an exact clean implementation freeze.

Historical M3 evidence is never copied or rebound. The private actor manifest
is validated through public manifest and transaction-transcript projections
before any node or evidence operation begins.

--check-only validates all preconditions without starting nodes or creating
repository evidence.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --implementation-freeze)
      FREEZE="${2:?missing commit}"
      shift 2
      ;;
    --actor-manifest)
      ACTORS="${2:?missing path}"
      shift 2
      ;;
    --check-only)
      CHECK_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$FREEZE" ]] || {
  echo 'ERROR: --implementation-freeze is required.' >&2
  exit 2
}

[[ -n "$ACTORS" && -f "$ACTORS" ]] || {
  echo 'ERROR: --actor-manifest must name an existing private manifest.' >&2
  exit 2
}

read -r RESOLVED TREE < <(
  m13_require_git_freeze "$ROOT" "$FREEZE"
)

VALIDATION_DIR="$(
  m13_make_tmp weall-m1-m3-evidence-preflight
)"

cleanup_validation() {
  rm -rf "$VALIDATION_DIR"
}

trap cleanup_validation EXIT INT TERM

PUBLIC_MANIFEST="$VALIDATION_DIR/M3_ACTOR_MANIFEST.public.json"
PUBLIC_TRANSCRIPT="$VALIDATION_DIR/M3_TRANSACTION_TRANSCRIPT.public.json"

python3 "$ROOT/scripts/validate_m3_actor_manifest.py" \
  --manifest "$ACTORS" \
  --implementation-freeze "$RESOLVED" \
  --out-public-manifest "$PUBLIC_MANIFEST" \
  --out-transcript "$PUBLIC_TRANSCRIPT" \
  >/dev/null

test -s "$PUBLIC_MANIFEST"
test -s "$PUBLIC_TRANSCRIPT"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  printf \
    'OK: evidence prerequisites passed for %s tree %s; no evidence created.\n' \
    "$RESOLVED" \
    "$TREE"
  exit 0
fi

cleanup_validation
trap - EXIT INT TERM

M2_IMPLEMENTATION_FREEZE_COMMIT="$RESOLVED" \
  bash "$ROOT/scripts/run_m2_complete_closure.sh"

M3_IMPLEMENTATION_FREEZE_COMMIT="$RESOLVED" \
WEALL_M3_ACTOR_MANIFEST="$ACTORS" \
  bash "$ROOT/scripts/run_m3_complete_closure.sh"

echo 'Evidence generated.'
echo 'Next action: review and stage only approved evidence paths.'
echo 'Then run cached evidence-only validation before committing.'
