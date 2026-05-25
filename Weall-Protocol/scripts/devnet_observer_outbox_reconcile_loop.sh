#!/usr/bin/env bash
set -euo pipefail

# Local controlled-devnet observer helper.
# Watches the observer durable tx outbox, drains pending txs upstream, then
# reconciles upstream-confirmed txs back into the local observer state. This is
# intentionally an operator-side rehearsal helper, not consensus authority.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBSERVER_API="${OBSERVER_API:-${NODE2_API:-http://127.0.0.1:8002}}"
OBSERVER_OPERATOR_TOKEN="${WEALL_OBSERVER_EDGE_OPERATOR_TOKEN:-${WEALL_OPERATOR_TOKEN:-local-observer-operator-token}}"
STATE_SYNC_TOKEN="${WEALL_STATE_SYNC_OPERATOR_TOKEN:-local-rehearsal-sync-token}"
OUTBOX_PATH="${WEALL_TX_OUTBOX_PATH:-${WEALL_RUNTIME_DIR:-${REPO_ROOT}/data}/observer_tx_outbox.json}"
POLL_S="${WEALL_RECONCILE_POLL_S:-1.0}"
MAX_IDLE="${WEALL_RECONCILE_MAX_IDLE:-0}"
ONCE="${WEALL_RECONCILE_ONCE:-0}"

cd "${REPO_ROOT}"

python3 - <<'PY' "${OBSERVER_API}" "${OBSERVER_OPERATOR_TOKEN}" "${STATE_SYNC_TOKEN}" "${OUTBOX_PATH}" "${POLL_S}" "${MAX_IDLE}" "${ONCE}"
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

api, observer_token, sync_token, outbox_path, poll_s, max_idle, once = sys.argv[1:]
api = api.rstrip('/')
outbox = Path(outbox_path)
poll = max(0.2, float(poll_s or '1.0'))
max_idle_n = max(0, int(float(max_idle or '0')))
run_once = str(once).strip().lower() in {'1', 'true', 'yes', 'on'}

def request(method: str, path: str, *, body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode('utf-8')
    headers = {
        'accept': 'application/json',
        'x-weall-observer-operator-token': observer_token,
        'x-weall-state-sync-operator-token': sync_token,
    }
    if body is not None:
        headers['content-type'] = 'application/json'
    req = urllib.request.Request(api + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - local operator-configured URL
            raw = resp.read().decode('utf-8', errors='replace')
            return int(resp.status), json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode('utf-8', errors='replace')
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except Exception:
            parsed = {'raw': raw}
        return int(exc.code), parsed
    except Exception as exc:
        return 0, {'ok': False, 'error': type(exc).__name__, 'detail': str(exc)}

def read_rows() -> list[dict]:
    try:
        data = json.loads(outbox.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return []
    except Exception as exc:
        print(f'WARN: cannot read observer outbox {outbox}: {exc}', flush=True)
        return []
    rows = data.get('records') if isinstance(data, dict) else data
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

idle = 0
next_reconcile_at: dict[str, float] = {}
reconcile_attempts: dict[str, int] = {}
print(f'==> observer reconcile loop api={api} outbox={outbox}', flush=True)
while True:
    changed = False
    rows = read_rows()
    pending = [r for r in rows if str(r.get('upstream_status') or 'pending') not in {'confirmed'}]
    if pending:
        status, body = request('POST', '/v1/observer/edge/outbox/drain')
        changed = changed or bool(body.get('ok'))
        print(f'==> drain status={status} counts={body.get("outbox", {}).get("counts")}', flush=True)

    for rec in read_rows():
        tx_id = str(rec.get('tx_id') or '').strip()
        if not tx_id:
            continue
        local_synced = rec.get('local_state_synced') is True
        upstream_status = str(rec.get('upstream_status') or '').strip()
        if local_synced:
            continue
        # The reconcile route also probes upstream status, so call it for accepted
        # and confirmed rows. Pending rows will return a bounded diagnostic.
        if upstream_status in {'accepted', 'confirmed'}:
            now = time.time()
            due_at = float(next_reconcile_at.get(tx_id, 0.0))
            if now < due_at:
                continue
            enc = urllib.parse.quote(tx_id, safe=':')
            status, body = request('POST', f'/v1/observer/edge/reconcile/{enc}')
            ok = bool(body.get('ok') and body.get('local_state_synced'))
            changed = changed or ok
            err = body.get("error", "")
            print(f'==> reconcile tx={tx_id} status={status} ok={ok} err={err}', flush=True)
            if ok:
                next_reconcile_at.pop(tx_id, None)
                reconcile_attempts.pop(tx_id, None)
            else:
                # Avoid hammering accepted-but-not-yet-confirmed rows into the
                # API rate limiter.  The outbox still remains durable; this only
                # spaces local operator probes while genesis catches up.
                attempts = int(reconcile_attempts.get(tx_id, 0)) + 1
                reconcile_attempts[tx_id] = attempts
                if status == 429 or str(err).find('upstream_not_confirmed') >= 0 or str(err).find('rate_limited') >= 0:
                    backoff = min(30.0, max(poll, 1.0) * (2 ** min(attempts, 5)))
                    next_reconcile_at[tx_id] = time.time() + backoff

    if run_once:
        break
    idle = 0 if changed else idle + 1
    if max_idle_n and idle >= max_idle_n:
        print(f'==> reconcile loop exiting after idle={idle}', flush=True)
        break
    time.sleep(poll)
PY
