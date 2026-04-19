#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="${ROOT_DIR}/web/public/dev-bootstrap.json"
API_BASE="${WEALL_API_BASE:-http://127.0.0.1:8000}"
FRONTEND_BASE="${WEALL_FRONTEND_BASE:-http://127.0.0.1:5173}"

log() {
  printf '[demo-rehearsal] %s\n' "$*"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

json_get() {
  local expr="$1"
  python3 - "$MANIFEST_PATH" "$expr" <<'PY'
import json, sys
path, expr = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as fh:
    obj = json.load(fh)
cur = obj
for part in expr.split('.'):
    if not part:
        continue
    if isinstance(cur, dict):
        cur = cur.get(part)
    else:
        cur = None
        break
if cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(str(cur))
PY
}

check_url() {
  local url="$1"
  local label="$2"
  if curl -fsS "$url" >/dev/null; then
    log "ok: ${label}"
  else
    log "fail: ${label}"
    exit 1
  fi
}

need_cmd curl
need_cmd python3

[ -f "$MANIFEST_PATH" ] || { log "missing manifest: ${MANIFEST_PATH}"; exit 1; }

check_url "${API_BASE}/v1/readyz" "backend readyz"
check_url "${FRONTEND_BASE}" "frontend root"

ACCOUNT="$(json_get 'account')"
GROUP_ID="$(json_get 'seededGroup.group_id')"
DISPUTE_ID="$(json_get 'seededDispute.dispute_id')"
PROPOSAL_ID="$(json_get 'seededProposal.proposal_id')"

[ -n "$ACCOUNT" ] || { log "manifest missing account"; exit 1; }
[ -n "$GROUP_ID" ] || { log "manifest missing seededGroup.group_id"; exit 1; }
[ -n "$DISPUTE_ID" ] || { log "manifest missing seededDispute.dispute_id"; exit 1; }
[ -n "$PROPOSAL_ID" ] || { log "manifest missing seededProposal.proposal_id"; exit 1; }

log "seeded account: ${ACCOUNT}"
log "seeded group: ${GROUP_ID}"
log "seeded dispute: ${DISPUTE_ID}"
log "seeded proposal: ${PROPOSAL_ID}"

check_url "${API_BASE}/v1/groups/${GROUP_ID}" "seeded group route"
check_url "${API_BASE}/v1/disputes/${DISPUTE_ID}" "seeded dispute route"
check_url "${API_BASE}/v1/gov/proposals/${PROPOSAL_ID}" "seeded proposal route"

log "conference demo rehearsal check passed"
