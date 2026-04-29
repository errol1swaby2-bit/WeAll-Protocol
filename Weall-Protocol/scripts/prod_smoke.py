#!/usr/bin/env python3

"""Production-ish smoke test for WeAll.

This smoke test is intentionally lightweight and source-checkout friendly.

It verifies:
  - the app can boot from a fresh SQLite database
  - the canonical health/readiness/operator status routes respond
  - the block loop can produce at least one empty block when enabled

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
import shutil
import sys
import tempfile
import time
from pathlib import Path


def _bootstrap_repo_imports() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"
    src_dir_str = str(src_dir)
    if src_dir.exists() and src_dir_str not in sys.path:
        sys.path.insert(0, src_dir_str)


_bootstrap_repo_imports()

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.block_loop import BlockLoopConfig, BlockProducerLoop


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)


def _assert_ok_json(client: TestClient, path: str) -> dict:
    response = client.get(path)
    assert response.status_code == 200, f"{path} -> {response.status_code}: {response.text}"
    data = response.json()
    assert isinstance(data, dict), f"{path} did not return a JSON object"
    return data


def main() -> int:
    tx_index_path = os.environ.get("WEALL_TX_INDEX_PATH", "./generated/tx_index.json")
    temp_dir = tempfile.mkdtemp(prefix="weall-smoke-")

    try:
        db_path = os.path.join(temp_dir, "weall.db")
        lock_path = os.path.join(temp_dir, "block_loop.lock")

        os.environ["WEALL_DB_PATH"] = db_path
        os.environ.setdefault("WEALL_NODE_ID", "smoke-node")
        os.environ.setdefault("WEALL_CHAIN_ID", "smoke-chain")
        os.environ["WEALL_TX_INDEX_PATH"] = tx_index_path

        os.environ.setdefault("WEALL_BLOCK_LOOP_ENABLED", "1")
        os.environ.setdefault("WEALL_PRODUCE_EMPTY_BLOCKS", "1")
        os.environ.setdefault(
            "WEALL_BLOCK_INTERVAL_MS", str(_env_int("WEALL_BLOCK_INTERVAL_MS", 500))
        )

        app = create_app(boot_runtime=True)
        ex = app.state.executor

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

        loop = BlockProducerLoop(
            executor=ex,
            mempool=ex.mempool,
            attestation_pool=ex.attestation_pool,
            cfg=cfg,
        )
        if not loop.start():
            raise RuntimeError("failed to start block loop")

        try:
            client = TestClient(app)

            health = _assert_ok_json(client, "/v1/health")
            assert bool(health.get("ok")) is True, f"/v1/health returned unexpected payload: {health}"

            ready = _assert_ok_json(client, "/v1/readyz")
            assert "chain_id" in ready, f"/v1/readyz missing chain_id: {ready}"
            assert "tx_index_hash" in ready, f"/v1/readyz missing tx_index_hash: {ready}"

            status = _assert_ok_json(client, "/v1/status")
            consensus = _assert_ok_json(client, "/v1/status/consensus")
            operator = _assert_ok_json(client, "/v1/status/operator")

            start_h = int(ex.read_state().get("height") or 0)
            deadline = time.time() + 8.0
            while time.time() < deadline:
                h = int(ex.read_state().get("height") or 0)
                if h >= start_h + 1:
                    break
                time.sleep(0.1)

            end_h = int(ex.read_state().get("height") or 0)
            if end_h < start_h + 1:
                raise RuntimeError(
                    f"block height did not advance: start={start_h} end={end_h}"
                )

            print(
                "OK: health/ready/status + produced empty block",
                {
                    "start_height": start_h,
                    "end_height": end_h,
                    "health_ok": health.get("ok"),
                    "ready_chain_id": ready.get("chain_id"),
                    "status_keys": sorted(status.keys()),
                    "consensus_keys": sorted(consensus.keys()),
                    "operator_keys": sorted(operator.keys()),
                },
            )
            return 0
        finally:
            loop.stop()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
