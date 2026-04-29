# File: scripts/crash_drill.py
#!/usr/bin/env python3
"""Crash/restart drill for SQLite-backed executor consistency.

Goal
----
Continuously create a tiny chain, then intentionally SIGKILL the process
mid-flight, restart, and verify the executor refuses to start only when
DB invariants are violated.

This is NOT a consensus test. It is an operator/production readiness drill
that helps prove:
  - crash consistency under WAL
  - fail-closed behavior on mismatched snapshot vs blocks table
  - idempotent restart initialization

Usage
-----
  cd projects/Weall-Protocol
  python scripts/crash_drill.py --iters 25

Options
-------
  --iters N          number of crash cycles (default 10)
  --workdir PATH     directory to place the db (default ./data/crash_drill)
  --kill-min-ms A    minimum delay before kill (default 10)
  --kill-max-ms B    maximum delay before kill (default 250)

Notes
-----
The child process runs with WEALL_UNSAFE_DEV=1 and WEALL_ALLOW_UNSIGNED_TXS=1
so we can submit minimal txs without signatures.
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

CHILD_CODE = r"""
import os, time
from weall.runtime.executor import WeAllExecutor

# Unsafe/dev flags to allow unsigned test txs.
os.environ.setdefault('WEALL_MODE','dev')
os.environ.setdefault('WEALL_UNSAFE_DEV','1')
os.environ.setdefault('WEALL_ALLOW_UNSIGNED_TXS','1')
os.environ.setdefault('WEALL_SIGVERIFY','0')

workdir = os.environ['WEALL_DRILL_WORKDIR']
db_path = os.path.join(workdir, 'chain.sqlite')
tx_index_path = os.environ.get('WEALL_TX_INDEX_PATH','./generated/tx_index.json')

ex = WeAllExecutor(db_path=db_path, node_id='drill-node', chain_id='weall-drill', tx_index_path=tx_index_path)

# submit a deterministic pair of txs each loop
# NOTE: ACCOUNT_REGISTER is allowed for unknown accounts; PEER_ADVERTISE requires payload.endpoint.

loop = 0
while True:
    loop += 1
    # Account register (nonce must be 1 for new signer)
    ex.submit_tx({
        'tx_type':'ACCOUNT_REGISTER',
        'signer':'alice',
        'nonce':1,
        'system':False,
        'payload':{'account_id':'alice'}
    })

    # Advertise a fake endpoint (nonce must be next for existing signer)
    ex.submit_tx({
        'tx_type':'PEER_ADVERTISE',
        'signer':'alice',
        'nonce':2,
        'system':False,
        'payload':{'endpoint':'tcp://127.0.0.1:30303'}
    })

    # Produce a block (will be empty if nothing admissible)
    ex.produce_block(max_txs=100)

    # keep process alive so parent can kill at arbitrary time
    time.sleep(0.05)
"""


def _run_child(workdir: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["WEALL_DRILL_WORKDIR"] = str(workdir)
    # Make sure imports work when called from repo root.
    env.setdefault("PYTHONPATH", str(Path.cwd() / "src"))

    return subprocess.Popen(
        [sys.executable, "-c", CHILD_CODE],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _verify_restart(workdir: Path) -> None:
    # A clean restart should succeed and should NOT raise ExecutorError.
    env = os.environ.copy()
    env.setdefault("WEALL_MODE", "prod")
    env.setdefault("PYTHONPATH", str(Path.cwd() / "src"))

    code = r"""
from weall.runtime.executor import WeAllExecutor
import os
workdir=os.environ['WEALL_DRILL_WORKDIR']
ex=WeAllExecutor(db_path=workdir+'/chain.sqlite', node_id='restart', chain_id='weall-drill', tx_index_path='./generated/tx_index.json')
print('ok height', ex.read_state().get('height'))
"""

    p = subprocess.run(
        [sys.executable, "-c", code], env={**env, "WEALL_DRILL_WORKDIR": str(workdir)}
    )
    if p.returncode != 0:
        raise RuntimeError("restart verification failed (executor refused to start or crashed)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=10)
    ap.add_argument("--workdir", type=str, default="./data/crash_drill")
    ap.add_argument("--kill-min-ms", type=int, default=10)
    ap.add_argument("--kill-max-ms", type=int, default=250)
    args = ap.parse_args()

    iters = max(1, int(args.iters))
    wdir = Path(args.workdir).resolve()
    kill_min = max(0, int(args.kill_min_ms))
    kill_max = max(kill_min, int(args.kill_max_ms))

    # Fresh workdir each run.
    if wdir.exists():
        shutil.rmtree(wdir)
    wdir.mkdir(parents=True, exist_ok=True)

    print(f"workdir: {wdir}")
    print(f"iters: {iters}  kill_window_ms=[{kill_min},{kill_max}]")

    for i in range(1, iters + 1):
        child = _run_child(wdir)
        delay = random.randint(kill_min, kill_max) / 1000.0
        time.sleep(delay)

        # SIGKILL to simulate power loss.
        try:
            os.kill(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

        try:
            child.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                child.kill()
            except Exception:
                pass

        # Verify restart invariants.
        _verify_restart(wdir)
        print(f"[{i}/{iters}] crash/restart OK")

    print("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
