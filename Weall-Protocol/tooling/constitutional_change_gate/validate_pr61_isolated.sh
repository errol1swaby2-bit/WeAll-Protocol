#!/usr/bin/env bash
# Read-only toward the supplied WeAll repository and all live node data.
set -Eeuo pipefail
umask 077
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 /absolute/path/to/WeAll-Protocol-git-root [output-dir-outside-repo]" >&2
  exit 2
fi
SRC="$(realpath -- "$1")"
PKG="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -d "$SRC/.git" || -f "$SRC/.git" ]] || { echo "Source is not a git root: $SRC" >&2; exit 2; }
[[ -f "$SRC/Weall-Protocol/generated/tx_index.json" ]] || { echo "Not a WeAll checkout: $SRC" >&2; exit 2; }
BASE='48cbc1cbf36fa3c573d0f5903c2afb80d6d93344'
HEAD='d10674253b5fb3cc765ec66442f3eaf5558cb81b'
OUT="$(realpath -m -- "${2:-/tmp/weall-v2-pr61-isolated-review}")"
case "$OUT/" in "$SRC/"*|"$PKG/"*) echo 'Output must be outside source checkout and candidate package' >&2; exit 2;; esac
mkdir -p -- "$OUT"
TMP="$(mktemp -d -t weall-pr61-reconciliation-XXXXXXXX)"
trap 'rm -rf -- "$TMP"' EXIT
# Shared-object local clone keeps source Git index, branches and working tree unchanged.
# The temporary clone is isolated and deliberately excludes ignored .weall-devnet state.
git clone --quiet --shared --no-checkout -- "$SRC" "$TMP/repo"
# If stacked PR commits are not present locally, try network fetch in the CLONE ONLY.
if ! git -C "$TMP/repo" cat-file -e "$HEAD^{commit}" 2>/dev/null; then
  git -C "$TMP/repo" fetch --quiet --no-tags https://github.com/errol1swaby2-bit/WeAll-Protocol.git refs/pull/61/head
fi
if ! git -C "$TMP/repo" cat-file -e "$BASE^{commit}" 2>/dev/null; then
  git -C "$TMP/repo" fetch --quiet --no-tags https://github.com/errol1swaby2-bit/WeAll-Protocol.git "$BASE"
fi
git -C "$TMP/repo" -c advice.detachedHead=false checkout --quiet --detach "$HEAD"
python3 -m unittest discover -s "$PKG/tests" -v > "$OUT/isolated_gate_tests.log" 2>&1
python3 "$PKG/weall_change_gate.py" impact --repo "$TMP/repo" --out "$OUT/impact" \
  --base "$BASE" --head "$HEAD" > "$OUT/impact_command.log" 2>&1
set +e
python3 "$PKG/reconcile_v2.py" --repo "$TMP/repo" --out "$OUT/reconciliation" \
  --expected-head "$HEAD" > "$OUT/reconciliation_command.log" 2>&1
RC=$?
set -e
if [[ $RC -ne 2 || ! -f "$OUT/reconciliation/v2_reconciliation.json" ]]; then
  cat "$OUT/reconciliation_command.log" >&2
  echo 'Reconciliation did not reach its expected fail-closed verdict.' >&2
  exit 2
fi
python3 - "$OUT/reconciliation/v2_reconciliation.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1],encoding='utf-8'))
assert r['target_checkout_commit']=='d10674253b5fb3cc765ec66442f3eaf5558cb81b'
assert r['gate']=='BLOCKED_PENDING_AUTHORIZED_TRACEABILITY_AND_EXACT_COMMIT_EVIDENCE'
print('EXPECTED RESULT: structurally reconciled for review, release gate BLOCKED.')
PY
printf '\nRead-only reports in: %s\n' "$OUT"
printf '%s\n' 'No GitHub writes; no source repo branch/worktree/ledger modifications.'
