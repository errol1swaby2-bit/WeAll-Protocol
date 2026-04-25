#!/usr/bin/env bash
set -euo pipefail

# Pull a bounded state-sync response from node 1 and apply it to node 2 through
# the same executor/state-sync verification path used by transport sync. This is
# an early controlled-devnet harness, not a demo seed path.
#
# Default behavior: replay persisted blocks from height 0 using trusted delta sync.
# This preserves the local block database invariants on the joining node.
# Set WEALL_DEVNET_SYNC_BOOTSTRAP_MODE=snapshot only for explicit snapshot-bootstrap experiments.

NODE1_API="${1:-${NODE1_API:-http://127.0.0.1:8001}}"
NODE2_API="${2:-${NODE2_API:-http://127.0.0.1:8002}}"
MAX_ROUNDS="${WEALL_DEVNET_SYNC_MAX_ROUNDS:-8}"
SLEEP_S="${WEALL_DEVNET_SYNC_SLEEP:-0.5}"
BOOTSTRAP_MODE="${WEALL_DEVNET_SYNC_BOOTSTRAP_MODE:-delta}"
TMP_DIR="${TMPDIR:-/tmp}/weall-devnet-sync.$$"
mkdir -p "${TMP_DIR}"
trap 'rm -rf "${TMP_DIR}"' EXIT

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
need curl
need python3

_fetch_identity() {
  local api="$1"
  local out="$2"
  curl -fsS "${api%/}/v1/chain/identity" > "${out}"
}

_post_json() {
  local url="$1"
  local in_file="$2"
  local out_file="$3"
  local code_file="$4"
  local code
  code="$(curl -sS -H 'content-type: application/json' --data-binary "@${in_file}" \
    -o "${out_file}" -w '%{http_code}' "${url}" || true)"
  printf '%s' "${code}" > "${code_file}"
  if [[ "${code}" -lt 200 || "${code}" -ge 300 ]]; then
    echo "HTTP ${code} from ${url}" >&2
    cat "${out_file}" >&2 || true
    echo >&2
    return 1
  fi
}

for round in $(seq 1 "${MAX_ROUNDS}"); do
  _fetch_identity "${NODE1_API}" "${TMP_DIR}/node1.json"
  _fetch_identity "${NODE2_API}" "${TMP_DIR}/node2.json"

  read -r NODE1_HEIGHT NODE2_HEIGHT NODE1_ROOT NODE2_ROOT < <(python3 - "${TMP_DIR}/node1.json" "${TMP_DIR}/node2.json" <<'PY'
import json, sys
n1 = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
n2 = json.load(open(sys.argv[2], 'r', encoding='utf-8'))
print(int(n1.get('height') or 0), int(n2.get('height') or 0), str(n1.get('state_root') or ''), str(n2.get('state_root') or ''))
PY
)

  if [[ "${NODE1_HEIGHT}" == "${NODE2_HEIGHT}" && "${NODE1_ROOT}" == "${NODE2_ROOT}" ]]; then
    echo "==> OK: node 2 synced to node 1 height=${NODE1_HEIGHT} state_root=${NODE1_ROOT}"
    exit 0
  fi

  echo "==> Sync round ${round}: node1_height=${NODE1_HEIGHT} node2_height=${NODE2_HEIGHT}"
  python3 - "${TMP_DIR}/node1.json" "${TMP_DIR}/node2.json" "${BOOTSTRAP_MODE}" > "${TMP_DIR}/request.json" <<'PY'
import json, sys
node1 = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
node2 = json.load(open(sys.argv[2], 'r', encoding='utf-8'))
bootstrap_mode = str(sys.argv[3] or 'delta').strip().lower()
anchor = node1.get('snapshot_anchor') or {}
from_height = int(node2.get('height') or 0)
node1_height = int(node1.get('height') or 0)
mode = 'snapshot' if from_height == 0 and node1_height > 0 and bootstrap_mode == 'snapshot' else 'delta'
print(json.dumps({
    'mode': mode,
    'from_height': from_height,
    'selector': {'trusted_anchor': anchor},
}, sort_keys=True))
PY

  _post_json "${NODE1_API%/}/v1/sync/request" "${TMP_DIR}/request.json" \
    "${TMP_DIR}/response_outer.json" "${TMP_DIR}/request.status"

  python3 - "${TMP_DIR}/response_outer.json" "${TMP_DIR}/node1.json" "${TMP_DIR}/request.json" > "${TMP_DIR}/apply.json" <<'PY'
import json, sys
outer = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
identity = json.load(open(sys.argv[2], 'r', encoding='utf-8'))
request = json.load(open(sys.argv[3], 'r', encoding='utf-8'))
if not outer.get('ok'):
    raise SystemExit('sync request failed: ' + json.dumps(outer, sort_keys=True))
mode = str(request.get('mode') or '').lower()
print(json.dumps({
    'response': outer.get('response'),
    'trusted_anchor': identity.get('snapshot_anchor') or {},
    'allow_snapshot_bootstrap': mode == 'snapshot',
}, sort_keys=True))
PY

  _post_json "${NODE2_API%/}/v1/sync/apply" "${TMP_DIR}/apply.json" \
    "${TMP_DIR}/apply_out.json" "${TMP_DIR}/apply.status"
  cat "${TMP_DIR}/apply_out.json"
  echo
  sleep "${SLEEP_S}"
done

echo "ERROR: node 2 did not sync to node 1 within ${MAX_ROUNDS} rounds" >&2
bash "$(dirname "$0")/devnet_compare_state_roots.sh" "${NODE1_API}" "${NODE2_API}" || true
exit 1
