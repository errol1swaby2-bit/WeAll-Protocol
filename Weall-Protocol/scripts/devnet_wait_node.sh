#!/usr/bin/env bash
set -euo pipefail

# Wait until a devnet node exposes the canonical chain identity endpoint.
# This is intentionally a read-only health gate; it does not submit txs, does
# not call demo seed routes, and does not mutate local state.

NODE_API="${1:-${NODE_API:-${WEALL_API:-http://127.0.0.1:8001}}}"
TIMEOUT_S="${2:-${WEALL_NODE_WAIT_TIMEOUT:-30}}"
POLL_S="${3:-${WEALL_NODE_WAIT_POLL:-0.5}}"
LOG_HINT="${WEALL_NODE_WAIT_LOG:-}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 2
  }
}
need curl
need python3

python3 - "$NODE_API" "$TIMEOUT_S" "$POLL_S" "$LOG_HINT" <<'PY'
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

api, timeout_s, poll_s, log_hint = sys.argv[1:5]
api = api.rstrip("/")
deadline = time.time() + float(timeout_s)
last_error = "not checked"

while time.time() <= deadline:
    try:
        with urllib.request.urlopen(api + "/v1/chain/identity", timeout=3) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        chain_id = str(data.get("chain_id") or "").strip()
        if chain_id:
            print(json.dumps({"ok": True, "api": api, "chain_id": chain_id, "height": data.get("height"), "tip_hash": data.get("tip_hash"), "state_root": data.get("state_root")}, indent=2, sort_keys=True))
            raise SystemExit(0)
        last_error = "identity response missing chain_id"
    except Exception as exc:  # noqa: BLE001 - CLI diagnostic path
        last_error = f"{type(exc).__name__}: {exc}"
    time.sleep(float(poll_s))

print(f"ERROR: node did not become ready at {api}/v1/chain/identity within {timeout_s}s", file=sys.stderr)
print(f"last_error={last_error}", file=sys.stderr)
if log_hint:
    path = Path(log_hint)
    print(f"log={path}", file=sys.stderr)
    if path.exists():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-80:]
        print("--- node log tail ---", file=sys.stderr)
        for line in lines:
            print(line, file=sys.stderr)
raise SystemExit(1)
PY
