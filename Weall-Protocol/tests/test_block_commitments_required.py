from __future__ import annotations

from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _canon_path() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / "generated" / "tx_index.json")


def _new_executor(tmp_path: Path) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "db.sqlite"),
        node_id="n1",
        chain_id="test-chain",
        tx_index_path=_canon_path(),
    )


def test_apply_block_rejects_missing_receipts_root(tmp_path: Path) -> None:
    leader = _new_executor(tmp_path / "leader")
    follower = _new_executor(tmp_path / "follower")

    ok = leader.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:@alice"},
        }
    )
    assert ok["ok"] is True

    meta = leader.produce_block(max_txs=1)
    assert meta.ok is True
    block = leader.get_latest_block()
    assert isinstance(block, dict)

    block["header"] = dict(block.get("header") or {})
    block["header"].pop("receipts_root", None)

    res = follower.apply_block(block)
    assert res.ok is False
    assert res.error == "bad_block:missing_receipts_root"


def test_apply_block_rejects_missing_state_root(tmp_path: Path) -> None:
    leader = _new_executor(tmp_path / "leader")
    follower = _new_executor(tmp_path / "follower")

    ok = leader.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:@alice"},
        }
    )
    assert ok["ok"] is True

    meta = leader.produce_block(max_txs=1)
    assert meta.ok is True
    block = leader.get_latest_block()
    assert isinstance(block, dict)

    block["header"] = dict(block.get("header") or {})
    block["header"].pop("state_root", None)

    res = follower.apply_block(block)
    assert res.ok is False
    assert res.error == "bad_block:missing_state_root"
