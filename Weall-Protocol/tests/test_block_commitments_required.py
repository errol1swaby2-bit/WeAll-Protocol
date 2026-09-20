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


def _one_tx_block(tmp_path: Path) -> tuple[WeAllExecutor, dict]:
    leader = _new_executor(tmp_path / "leader-bind")
    ok = leader.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@binder",
            "nonce": 1,
            "payload": {"pubkey": "k:@binder"},
        }
    )
    assert ok["ok"] is True
    meta = leader.produce_block(max_txs=1)
    assert meta.ok is True
    block = leader.get_latest_block()
    assert isinstance(block, dict)
    return leader, block


def test_apply_block_rejects_supplied_block_id_alias(tmp_path: Path) -> None:
    import copy

    _leader, block = _one_tx_block(tmp_path)
    follower = _new_executor(tmp_path / "follower-block-id")
    forged = copy.deepcopy(block)
    forged["block_id"] = "ab" * 32

    res = follower.apply_block(forged)
    assert res.ok is False
    assert res.error == "bad_block:block_id_mismatch"


def test_apply_block_rejects_header_tx_id_alias(tmp_path: Path) -> None:
    import copy

    _leader, block = _one_tx_block(tmp_path)
    follower = _new_executor(tmp_path / "follower-header-id")
    forged = copy.deepcopy(block)
    forged["header"] = dict(forged["header"])
    forged["header"]["tx_ids"] = ["tx:" + ("ff" * 32)]

    res = follower.apply_block(forged)
    assert res.ok is False
    assert res.error == "bad_block:header_tx_ids_mismatch"


def test_apply_block_rejects_body_tx_id_alias(tmp_path: Path) -> None:
    import copy

    _leader, block = _one_tx_block(tmp_path)
    follower = _new_executor(tmp_path / "follower-body-id")
    forged = copy.deepcopy(block)
    assert isinstance(forged.get("txs"), list) and forged["txs"]
    forged["txs"][0] = dict(forged["txs"][0])
    forged["txs"][0]["tx_id"] = "tx:" + ("ee" * 32)

    res = follower.apply_block(forged)
    assert res.ok is False
    assert res.error == "bad_block:body_tx_id_mismatch:0"


def test_apply_block_rejects_supplied_block_hash_alias(tmp_path: Path) -> None:
    import copy

    _leader, block = _one_tx_block(tmp_path)
    follower = _new_executor(tmp_path / "follower-block-hash")
    forged = copy.deepcopy(block)
    forged["block_hash"] = "cd" * 32

    res = follower.apply_block(forged)
    assert res.ok is False
    assert res.error == "bad_block:block_hash_mismatch"
