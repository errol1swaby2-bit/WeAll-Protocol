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
  scripts/run_m3_formal_journey.sh \
    --implementation-freeze COMMIT \
    --actor-manifest PATH \
    [--check-only]

Validates the exact clean implementation freeze, private actor-manifest
contract, and public-output projection preconditions.

Without --check-only, delegates to the canonical signed M3 real-stack journey.
Private keys, signer state, browser state, and custody material must remain
outside the repository.
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
  m13_make_tmp weall-m3-formal-preflight
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

printf 'implementation_commit=%s\n' "$RESOLVED"
printf 'implementation_tree=%s\n' "$TREE"
printf 'actor_manifest=%s\n' "$ACTORS"
printf 'public_projection_validation=passed\n'

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  echo 'OK: M3 formal journey prerequisites passed; no transaction submitted.'
  exit 0
fi

cleanup_validation
trap - EXIT INT TERM

M3_IMPLEMENTATION_FREEZE_COMMIT="$RESOLVED" \
WEALL_M3_ACTOR_MANIFEST="$ACTORS" \
  bash "$ROOT/scripts/run_m3_civic_real_stack_e2e.sh"
