#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/lib/m1_m3_common.sh"
BACKEND="$ROOT/Weall-Protocol"; JSON_OUT=""
usage(){ cat <<'USAGE'
Usage: scripts/test_upgrade_safety.sh [--json-out PATH]

Runs deterministic migration, record-only activation, rollback-boundary, and
upgrade replay tests. This does not enable automatic software or state upgrades.
USAGE
}
while [[ $# -gt 0 ]]; do case "$1" in
  --json-out) JSON_OUT="${2:?missing path}"; shift 2;;
  -h|--help) usage; exit 0;;
  *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2;;
esac; done
if [[ -n "$JSON_OUT" ]]; then
  TMP="${JSON_OUT%.json}.d"
  rm -rf "$TMP"
  mkdir -p "$TMP"
else
  TMP="$(m13_make_tmp weall-upgrade-safety)"
  trap 'rm -rf "$TMP"' EXIT INT TERM
fi
RESULTS="$TMP/results.tsv"; LOGS="$TMP/logs"; ID="$TMP/identity.env"; mkdir -p "$LOGS"; : >"$RESULTS"; m13_identity "$ROOT" | tee "$ID"
fail=0
m13_run_gate "$RESULTS" "$LOGS" 'upgrade and migration test suite' bash -lc "cd '$BACKEND' && PYTHONPATH=src:scripts WEALL_API_BOOT_RUNTIME=0 python3 -m pytest -q tests/test_ledger_migrations.py tests/test_ledger_migrations_registry.py tests/test_poh_v2_two_tier_migration.py tests/test_protocol_upgrade_height_scheduled_lifecycle.py tests/test_protocol_upgrade_record_only_boundary.py tests/test_constitution_upgrade_height_scheduled_lifecycle.py tests/test_bounded_rollback_equivalence.py tests/prod/test_protocol_upgrade_execution_hardening_plan.py" || fail=$((fail+1))
m13_run_gate "$RESULTS" "$LOGS" 'upgrade generated plan current' bash -lc "cd '$BACKEND' && PYTHONPATH=src:scripts python3 scripts/gen_protocol_upgrade_execution_hardening_plan_v1_5.py --check" || fail=$((fail+1))
if [[ -z "$JSON_OUT" ]]; then JSON_OUT="$TMP/upgrade-summary.json"; fi
m13_write_json_summary "$RESULTS" "$ID" "$JSON_OUT" upgrade >/dev/null
cat "$JSON_OUT"
[[ $fail -eq 0 ]] || { echo "Upgrade safety tests FAILED: $fail gate(s)." >&2; exit 1; }
echo 'OK: upgrade safety tests passed within the documented record-only boundary.'
