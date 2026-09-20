#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/m1_m3_common.sh"
BACKEND="$ROOT/Weall-Protocol"
JSON_OUT=""
usage(){ cat <<'USAGE'
Usage: scripts/audit_m1_m3.sh [--check-only] [--json-out PATH]

Runs the read-only M1-M3 baseline audit. It never regenerates artifacts or
creates evidence. In a source export, Git identity fields are reported as
UNAVAILABLE rather than guessed.
USAGE
}
while [[ $# -gt 0 ]]; do case "$1" in
  --check-only) shift;;
  --json-out) JSON_OUT="${2:?missing path}"; shift 2;;
  -h|--help) usage; exit 0;;
  *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2;;
esac; done
for c in python3 git; do command -v "$c" >/dev/null || { echo "ERROR: missing command: $c" >&2; exit 2; }; done
if [[ -n "$JSON_OUT" ]]; then
  TMP="${JSON_OUT%.json}.d"
  rm -rf "$TMP"
  mkdir -p "$TMP"
else
  TMP="$(m13_make_tmp weall-m1-m3-audit)"
  trap 'rm -rf "$TMP"' EXIT INT TERM
fi
RESULTS="$TMP/results.tsv"; LOGS="$TMP/logs"; ID="$TMP/identity.env"; mkdir -p "$LOGS"; : >"$RESULTS"
m13_identity "$ROOT" | tee "$ID"
fail=0
m13_run_gate "$RESULTS" "$LOGS" 'v2 generated contracts current' bash -lc "cd '$BACKEND' && PYTHONPATH=src:scripts python3 scripts/compile_v2_spec.py --check" || fail=$((fail+1))
m13_run_gate "$RESULTS" "$LOGS" 'v1.5 public-readiness artifacts current' bash -lc "cd '$BACKEND' && PYTHONPATH=src:scripts python3 scripts/check_v15_public_readiness_artifacts.py" || fail=$((fail+1))
m13_run_gate "$RESULTS" "$LOGS" 'M2 source traceability' bash -lc "cd '$BACKEND' && PYTHONPATH=src:scripts python3 scripts/check_m2_requirement_traceability.py" || fail=$((fail+1))
m13_run_gate "$RESULTS" "$LOGS" 'M3 source traceability' python3 "$ROOT/scripts/check_m3_requirement_traceability.py" --source-only || fail=$((fail+1))
if [[ -z "$JSON_OUT" ]]; then JSON_OUT="$TMP/audit-summary.json"; fi
m13_write_json_summary "$RESULTS" "$ID" "$JSON_OUT" audit >/dev/null
cat "$JSON_OUT"
[[ $fail -eq 0 ]] || { echo "M1-M3 read-only audit FAILED: $fail gate(s)." >&2; exit 1; }
echo 'OK: M1-M3 read-only audit passed.'
