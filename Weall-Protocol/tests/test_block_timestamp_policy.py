from __future__ import annotations

import time
from pathlib import Path

from weall.runtime.executor import MAX_BLOCK_FUTURE_DRIFT_MS, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _now_ms() -> int:
    return int(time.time() * 1000)


def test_executor_rejects_future_drift_block_timestamp(tmp_path: Path) -> None:
    """If the executor state claims a tip timestamp too far in the future,
    block production must fail-closed.

    This prevents time-gated mechanics (e.g. economics lock) from being bypassed
    by simply jumping state forward via local clock manipulation.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="alice", chain_id="ts-policy", tx_index_path=tx_index_path)

    sub = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "user0", "nonce": 1, "payload": {"pubkey": "k:0"}})
    assert sub["ok"] is True

    h0 = int(ex.read_state().get("height", 0))

    # Force the in-memory tip timestamp beyond allowed drift.
    ex.state["tip_ts_ms"] = _now_ms() + MAX_BLOCK_FUTURE_DRIFT_MS + 5_000

    meta = ex.produce_block(max_txs=1)
    assert meta.ok is False
    assert meta.error.startswith("invalid_block_ts")

    # Height must not advance when we fail closed.
    assert int(ex.read_state().get("height", 0)) == h0
