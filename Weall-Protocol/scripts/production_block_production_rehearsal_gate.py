#!/usr/bin/env python3
"""Reproducible local block-production proof gate.

This gate boots a fresh isolated node, starts the existing block producer loop,
waits for one empty block, and verifies that /v1/consensus/block-production/proof
exposes a committed block with state_root, receipts_root, and block_hash.

It is intentionally local-only evidence. It does not claim public multi-validator
BFT readiness and it never uses an observer profile as a producer.
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
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))


_bootstrap_repo_imports()

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.block_loop import BlockLoopConfig, BlockProducerLoop


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return int(default)


def _assert_ok(client: TestClient, path: str) -> dict:
    res = client.get(path)
    if res.status_code != 200:
        raise RuntimeError(f"{path} -> {res.status_code}: {res.text}")
    payload = res.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path} did not return object JSON")
    return payload


def main() -> int:
    temp_dir = tempfile.mkdtemp(prefix="weall-block-proof-")
    old_env = dict(os.environ)
    try:
        os.environ.update(
            {
                "WEALL_DB_PATH": os.path.join(temp_dir, "weall.db"),
                "WEALL_NODE_ID": "block-proof-node",
                "WEALL_CHAIN_ID": "block-proof-chain",
                "WEALL_TX_INDEX_PATH": os.environ.get("WEALL_TX_INDEX_PATH", "./generated/tx_index.json"),
                "WEALL_MODE": os.environ.get("WEALL_MODE", "dev"),
                "WEALL_OBSERVER_MODE": "0",
                "WEALL_BFT_ENABLED": "0",
                "WEALL_VALIDATOR_SIGNING_ENABLED": "1",
                "WEALL_BLOCK_LOOP_ENABLED": "1",
                "WEALL_PRODUCE_EMPTY_BLOCKS": "1",
                "WEALL_BLOCK_INTERVAL_MS": os.environ.get("WEALL_BLOCK_INTERVAL_MS", "300"),
                "WEALL_SQLITE_ALLOW_NON_WAL": "1",
                "WEALL_BLOCK_LOOP_LOCK_PATH": os.path.join(temp_dir, "block_loop.lock"),
            }
        )
        app = create_app(boot_runtime=True)
        ex = app.state.executor
        cfg = BlockLoopConfig(
            interval_ms=_env_int("WEALL_BLOCK_INTERVAL_MS", 300),
            produce_empty_blocks=True,
            enabled=True,
            lock_path=os.environ["WEALL_BLOCK_LOOP_LOCK_PATH"],
            max_block_txs=_env_int("WEALL_BLOCK_MAX_TXS", 1000),
            fail_fast_after=_env_int("WEALL_BLOCK_LOOP_FAIL_FAST_AFTER", 10),
            error_backoff_min_ms=_env_int("WEALL_BLOCK_LOOP_ERROR_BACKOFF_MIN_MS", 100),
            error_backoff_max_ms=_env_int("WEALL_BLOCK_LOOP_ERROR_BACKOFF_MAX_MS", 1000),
            bft_enabled=False,
            bft_timeout_ms=_env_int("WEALL_BFT_TIMEOUT_MS", 10000),
            bft_unsafe_autocommit=False,
            validator_account="",
        )
        loop = BlockProducerLoop(executor=ex, mempool=ex.mempool, attestation_pool=ex.attestation_pool, cfg=cfg)
        if not loop.start():
            raise RuntimeError("block loop did not start")
        try:
            client = TestClient(app)
            start = int(ex.read_state().get("height") or 0)
            deadline = time.time() + 8.0
            while time.time() < deadline:
                if int(ex.read_state().get("height") or 0) >= start + 1:
                    break
                time.sleep(0.1)
            ready = _assert_ok(client, "/v1/consensus/block-production/readiness")
            proof = _assert_ok(client, "/v1/consensus/block-production/proof")
            if ready.get("observer_mode"):
                raise RuntimeError("observer_reported_as_producer")
            if int(proof.get("height") or 0) < start + 1:
                raise RuntimeError(f"height did not advance: start={start} proof={proof}")
            for key in ("block_id", "block_hash", "state_root", "receipts_root"):
                if not str(proof.get(key) or "").strip():
                    raise RuntimeError(f"missing {key} in proof: {proof}")
            if not proof.get("has_root_evidence"):
                raise RuntimeError(f"proof does not expose root evidence: {proof}")
            print("OK: local production-profile block proof", proof)
            return 0
        finally:
            loop.stop()
    finally:
        os.environ.clear()
        os.environ.update(old_env)
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
