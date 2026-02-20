#!/usr/bin/env python3

"""Production-ish smoke test for WeAll.

This is intentionally simple and dependency-light.

It verifies:
  - executor boots on a fresh SQLite db
  - FastAPI app boots and serves /health + /readyz
  - block loop can produce at least one empty block when enabled

Usage:
  python3 scripts/prod_smoke.py

Optional env overrides:
  WEALL_TX_INDEX_PATH=./generated/tx_index.json
  WEALL_BLOCK_INTERVAL_MS=500
  WEALL_PRODUCE_EMPTY_BLOCKS=1
  WEALL_BLOCK_LOOP_FAIL_FAST_AFTER=10
"""

from __future__ import annotations

import os
import tempfile
import time

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.block_loop import BlockLoopConfig, BlockProducerLoop


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)


def main() -> int:
    tx_index_path = os.environ.get("WEALL_TX_INDEX_PATH", "./generated/tx_index.json")

    # Fresh isolated db
    with tempfile.TemporaryDirectory(prefix="weall-smoke-") as td:
        db_path = os.path.join(td, "weall.db")
        lock_path = os.path.join(td, "block_loop.lock")

        os.environ["WEALL_DB_PATH"] = db_path
        os.environ.setdefault("WEALL_NODE_ID", "smoke-node")
        os.environ.setdefault("WEALL_CHAIN_ID", "smoke-chain")
        os.environ["WEALL_TX_INDEX_PATH"] = tx_index_path

        # Make it easy for the loop to produce a block.
        os.environ.setdefault("WEALL_BLOCK_LOOP_ENABLED", "1")
        os.environ.setdefault("WEALL_PRODUCE_EMPTY_BLOCKS", "1")
        os.environ.setdefault("WEALL_BLOCK_INTERVAL_MS", str(_env_int("WEALL_BLOCK_INTERVAL_MS", 500)))

        app = create_app(boot_runtime=True)
        ex = app.state.executor

        # Start an explicit block loop for the smoke run (API runtime may not start it).
        cfg = BlockLoopConfig(
            interval_ms=_env_int("WEALL_BLOCK_INTERVAL_MS", 500),
            produce_empty_blocks=True,
            enabled=True,
            lock_path=lock_path,
            max_block_txs=_env_int("WEALL_BLOCK_MAX_TXS", 1000),
            fail_fast_after=_env_int("WEALL_BLOCK_LOOP_FAIL_FAST_AFTER", 10),
            error_backoff_min_ms=_env_int("WEALL_BLOCK_LOOP_ERROR_BACKOFF_MIN_MS", 250),
            error_backoff_max_ms=_env_int("WEALL_BLOCK_LOOP_ERROR_BACKOFF_MAX_MS", 10_000),
            bft_enabled=False,
            bft_timeout_ms=_env_int("WEALL_BFT_TIMEOUT_MS", 10_000),
            bft_unsafe_autocommit=False,
            validator_account=(os.environ.get("WEALL_VALIDATOR_ACCOUNT") or "").strip(),
        )

        loop = BlockProducerLoop(executor=ex, mempool=ex.mempool, attestation_pool=ex.attestation_pool, cfg=cfg)
        if not loop.start():
            raise RuntimeError("failed to start block loop")

        # API checks
        c = TestClient(app)
        r = c.get("/health")
        assert r.status_code == 200, r.text
        j = r.json()
        assert bool(j.get("ok")) is True

        r2 = c.get("/readyz")
        assert r2.status_code == 200, r2.text
        j2 = r2.json()
        assert "chain_id" in j2
        assert "tx_index_hash" in j2

        # Wait for at least one produced block.
        deadline = time.time() + 8.0
        start_h = int(ex.read_state().get("height") or 0)
        while time.time() < deadline:
            h = int(ex.read_state().get("height") or 0)
            if h >= start_h + 1:
                break
            time.sleep(0.1)

        loop.stop()

        end_h = int(ex.read_state().get("height") or 0)
        if end_h < start_h + 1:
            raise RuntimeError(f"block height did not advance: start={start_h} end={end_h}")

        print("OK: health/ready + produced empty block", {"start_height": start_h, "end_height": end_h})
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
