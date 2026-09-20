from __future__ import annotations

import copy
from pathlib import Path

from weall.runtime.block_id import compute_block_id
from weall.runtime.executor import WeAllExecutor
from weall.runtime.mempool import compute_tx_id


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _new_executor(tmp_path: Path) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id="apply-block-system-binding",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _live_ready_state() -> dict:
    return {
        "chain_id": "apply-block-system-binding",
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "accounts": {
            "@target": {"poh_tier": 1, "nonce": 1, "reputation_milli": 0},
            **{
                f"@j{i}": {"poh_tier": 2, "nonce": 1, "reputation_milli": 5000}
                for i in range(1, 12)
            },
        },
        "roles": {"jurors": {"active_set": [f"@j{i}" for i in range(1, 12)]}},
        "params": {"poh": {"live_min_rep_milli": 0}},
        "poh": {
            "live_cases": {
                "case-live": {
                    "case_id": "case-live",
                    "account_id": "@target",
                    "status": "open",
                    "jurors": {},
                    "session_commitment": "session:cmt",
                    "room_commitment": "room:cmt",
                    "prompt_commitment": "prompt:cmt",
                }
            }
        },
    }


def _leader_block_and_follower(tmp_path: Path) -> tuple[dict, WeAllExecutor]:
    state = _live_ready_state()
    leader = _new_executor(tmp_path / "leader")
    follower = _new_executor(tmp_path / "follower")
    leader._ledger_store.write_state_snapshot(copy.deepcopy(state))  # type: ignore[attr-defined]
    follower._ledger_store.write_state_snapshot(copy.deepcopy(state))  # type: ignore[attr-defined]
    leader.state = leader._ledger_store.read()  # type: ignore[attr-defined]
    follower.state = follower._ledger_store.read()  # type: ignore[attr-defined]

    block, _new_state, applied_ids, invalid_ids, err = leader.build_block_candidate(
        max_txs=0,
        allow_empty=True,
    )
    assert err == ""
    assert applied_ids
    assert not invalid_ids
    assert isinstance(block, dict)
    assert len(block.get("txs") or []) == 1
    assert (block["txs"][0] or {}).get("tx_type") == "POH_LIVE_JUROR_ASSIGN"
    return block, follower


def _retx(block: dict) -> None:
    for tx in block.get("txs") or []:
        if isinstance(tx, dict):
            tx["tx_id"] = compute_tx_id(tx, chain_id="apply-block-system-binding")
    header = block.get("header")
    if isinstance(header, dict):
        header["tx_ids"] = [
            str(tx.get("tx_id") or "") for tx in block.get("txs") or [] if isinstance(tx, dict)
        ]
        block["block_id"] = compute_block_id(
            chain_id=str(header.get("chain_id") or "apply-block-system-binding"),
            height=int(header.get("height") or block.get("height") or 0),
            prev_block_id=str(block.get("prev_block_id") or ""),
            prev_block_hash=str(header.get("prev_block_hash") or ""),
            ts_ms=int(header.get("block_ts_ms") or block.get("block_ts_ms") or 0),
            tx_ids=list(header["tx_ids"]),
            receipts_root=str(header.get("receipts_root") or ""),
        )
    block.pop("block_hash", None)


def test_apply_block_accepts_exact_scheduler_emitted_system_tx(tmp_path: Path) -> None:
    block, follower = _leader_block_and_follower(tmp_path)

    res = follower.apply_block(block)

    assert res.ok is True


def test_apply_block_rejects_system_tx_missing_queue_id(tmp_path: Path) -> None:
    block, follower = _leader_block_and_follower(tmp_path)
    forged = copy.deepcopy(block)
    payload = forged["txs"][0]["payload"]
    payload.pop("_system_queue_id", None)
    _retx(forged)

    res = follower.apply_block(forged)

    assert res.ok is False
    assert res.error == "bad_block:system_queue_binding:missing_system_queue_id"


def test_apply_block_rejects_unknown_system_queue_id(tmp_path: Path) -> None:
    block, follower = _leader_block_and_follower(tmp_path)
    forged = copy.deepcopy(block)
    forged["txs"][0]["payload"]["_system_queue_id"] = "unknown-queue-id"
    _retx(forged)

    res = follower.apply_block(forged)

    assert res.ok is False
    assert res.error == "bad_block:system_queue_binding:unknown_system_queue_id"


def test_apply_block_rejects_proposer_chosen_live_jurors(tmp_path: Path) -> None:
    block, follower = _leader_block_and_follower(tmp_path)
    forged = copy.deepcopy(block)
    forged["txs"][0]["payload"]["jurors"] = ["@j1"]
    _retx(forged)

    res = follower.apply_block(forged)

    assert res.ok is False
    assert res.error == "bad_block:system_queue_binding:system_queue_payload_mismatch"
