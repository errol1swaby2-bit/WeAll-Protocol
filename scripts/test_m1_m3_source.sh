#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/m1_m3_common.sh"

BACKEND="$ROOT/Weall-Protocol"
JSON_OUT=""
REQUIRE_RUFF=0
FULL_RUFF=0
RUFF_BASE_REF=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/test_m1_m3_source.sh [OPTIONS]

Runs source-bound M1-M3 checks without using historical or live evidence.
No repository files are generated or modified.

Options:
  --json-out PATH
      Preserve the machine-readable source-gate summary.

  --require-ruff
      Reject Ruff diagnostics added beyond an explicit Git baseline in changed
      backend Python files.

  --ruff-base-ref REF
      Baseline commit used by --require-ruff.

      Default:
        dirty worktree: HEAD
        clean committed worktree: HEAD^

      Formal replacement-freeze validation should pass the retired
      implementation freeze explicitly.

  --full-ruff
      Run Ruff over the complete backend src, tests, and scripts trees.
      This exposes all repository-wide lint debt and is independent of the
      changed-source regression gate.

  -h, --help
      Show this help text.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json-out)
      JSON_OUT="${2:?missing path after --json-out}"
      shift 2
      ;;
    --require-ruff)
      REQUIRE_RUFF=1
      shift
      ;;
    --ruff-base-ref)
      RUFF_BASE_REF="${2:?missing ref after --ruff-base-ref}"
      shift 2
      ;;
    --full-ruff)
      FULL_RUFF=1
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

for command_name in python3 git; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: missing required command: %s\n' "$command_name" >&2
    exit 2
  }
done

git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  printf 'ERROR: %s is not a Git worktree.\n' "$ROOT" >&2
  exit 2
}

if [[ -n "$JSON_OUT" ]]; then
  TMP="${JSON_OUT%.json}.d"
  rm -rf "$TMP"
  mkdir -p "$TMP"
else
  TMP="$(m13_make_tmp weall-m1-m3-source)"
  trap 'rm -rf "$TMP"' EXIT INT TERM
fi

RESULTS="$TMP/results.tsv"
LOGS="$TMP/logs"
IDENTITY="$TMP/identity.env"

mkdir -p "$LOGS"
: > "$RESULTS"

m13_identity "$ROOT" |
  tee "$IDENTITY"

fail=0

run() {
  m13_run_gate \
    "$RESULTS" \
    "$LOGS" \
    "$@" || fail=$((fail + 1))
}

run \
  'v2 compiler check' \
  bash -lc \
  "cd '$BACKEND' && \
   PYTHONPATH=src:scripts \
   python3 scripts/compile_v2_spec.py --check"

run \
  'v1.5 artifact check' \
  bash -lc \
  "cd '$BACKEND' && \
   PYTHONPATH=src:scripts \
   python3 scripts/check_v15_public_readiness_artifacts.py"

run \
  'M2 requirement traceability' \
  bash -lc \
  "cd '$BACKEND' && \
   PYTHONPATH=src:scripts \
   python3 scripts/check_m2_requirement_traceability.py"

run \
  'M3 source traceability' \
  python3 \
  "$ROOT/scripts/check_m3_requirement_traceability.py" \
  --source-only

run \
  'membership admission and workflow tests' \
  bash -lc \
  "cd '$BACKEND' && \
   PYTHONPATH=src:scripts \
   WEALL_API_BOOT_RUNTIME=0 \
   python3 -m pytest -q \
     tests/test_group_membership_approval_contract.py \
     tests/test_group_membership_public_autojoin.py \
     tests/test_group_join_route_and_membership_status.py \
     tests/test_m3_scope_contract.py"

run \
  'group transaction schema tests' \
  bash -lc \
  "cd '$BACKEND' && \
   PYTHONPATH=src:scripts \
   WEALL_API_BOOT_RUNTIME=0 \
   python3 -m pytest -q \
     tests/test_tx_schema_treasury_groups.py"

if [[ "$FULL_RUFF" -eq 1 ]]; then
  run \
    'ruff full repository' \
    bash -lc \
    "cd '$BACKEND' && \
     python3 -m ruff check src tests scripts"

elif [[ "$REQUIRE_RUFF" -eq 1 ]]; then
  if [[ -z "$RUFF_BASE_REF" ]]; then
    if [[ -n "$(
      git -C "$ROOT" status --porcelain=v1 --untracked-files=all
    )" ]]; then
      RUFF_BASE_REF="HEAD"
    elif git -C "$ROOT" rev-parse \
      --verify 'HEAD^' >/dev/null 2>&1; then
      RUFF_BASE_REF="HEAD^"
    else
      printf '%s\n' \
        'ERROR: Ruff baseline could not be inferred.' \
        'Pass --ruff-base-ref REF explicitly.' >&2
      exit 2
    fi
  fi

  run \
    'ruff changed-source regression gate' \
    python3 \
    "$BACKEND/scripts/check_ruff_regressions.py" \
    --repo-root "$ROOT" \
    --base-ref "$RUFF_BASE_REF" \
    --json-out "$TMP/ruff-regression-report.json"
fi

if [[ -z "$JSON_OUT" ]]; then
  JSON_OUT="$TMP/source-summary.json"
fi

m13_write_json_summary \
  "$RESULTS" \
  "$IDENTITY" \
  "$JSON_OUT" \
  source >/dev/null

cat "$JSON_OUT"

if [[ "$fail" -ne 0 ]]; then
  printf 'M1-M3 source tests FAILED: %s gate(s).\n' \
    "$fail" >&2
  exit 1
fi

printf 'OK: M1-M3 source tests passed.\n'
