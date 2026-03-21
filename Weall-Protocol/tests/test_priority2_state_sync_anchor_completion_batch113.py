from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, chain_id: str = "batch113-sync") -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=chain_id,
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _produce_register_block(ex: WeAllExecutor, signer: str, nonce: int) -> None:
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": nonce,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert sub["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


def _delta_response(
    source: WeAllExecutor, *, from_height: int, to_height: int | None = None
) -> StateSyncResponseMsg:
    top = int(source.state.get("height") or 0)
    end = top if to_height is None else min(int(to_height), top)
    blocks = []
    for h in range(int(from_height) + 1, end + 1):
        blk = source.get_block_by_height(h)
        assert isinstance(blk, dict)
        blk2 = dict(blk)
        blk2["parent_block_id"] = str(blk2.get("prev_block_id") or "")
        blk2["prev_block_hash"] = ""
        blocks.append(blk2)
    return StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=source.chain_id,
            schema_version="1",
            tx_index_hash=source._tx_index_hash,
            sent_ts_ms=0,
            corr_id="batch113",
        ),
        ok=True,
        reason=None,
        height=int(source.state.get("height") or 0),
        snapshot=None,
        blocks=tuple(blocks),
        snapshot_hash=None,
        snapshot_anchor=build_snapshot_anchor(source.state),
    )


def test_apply_state_sync_response_rejects_empty_delta_when_anchor_ahead(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    _produce_register_block(leader, "@u1", 1)
    _produce_register_block(leader, "@u2", 1)

    trusted_anchor = build_snapshot_anchor(leader.state)
    empty = StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=leader.chain_id,
            schema_version="1",
            tx_index_hash=leader._tx_index_hash,
            sent_ts_ms=0,
            corr_id="batch113-empty",
        ),
        ok=True,
        reason=None,
        height=int(leader.state.get("height") or 0),
        snapshot=None,
        blocks=(),
        snapshot_hash=None,
        snapshot_anchor=trusted_anchor,
    )

    with pytest.raises(ExecutorError, match="state_sync_delta_no_progress"):
        lagger.apply_state_sync_response(empty, trusted_anchor=trusted_anchor)

    assert int(lagger.state.get("height") or 0) == 0


def test_apply_state_sync_response_allows_empty_delta_when_already_at_anchor(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    _produce_register_block(leader, "@u1", 1)
    _produce_register_block(leader, "@u2", 1)

    lagger.apply_state_sync_response(_delta_response(leader, from_height=0), trusted_anchor=build_snapshot_anchor(leader.state))
    trusted_anchor = build_snapshot_anchor(leader.state)
    empty = StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=leader.chain_id,
            schema_version="1",
            tx_index_hash=leader._tx_index_hash,
            sent_ts_ms=0,
            corr_id="batch113-empty-ok",
        ),
        ok=True,
        reason=None,
        height=int(leader.state.get("height") or 0),
        snapshot=None,
        blocks=(),
        snapshot_hash=None,
        snapshot_anchor=trusted_anchor,
    )

    metas = lagger.apply_state_sync_response(empty, trusted_anchor=trusted_anchor)

    assert metas == []
    assert int(lagger.state.get("height") or 0) == 2


def test_apply_state_sync_response_accepts_completed_delta_with_matching_anchor(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    for i in range(1, 4):
        _produce_register_block(leader, f"@u{i}", 1)

    resp = _delta_response(leader, from_height=0)
    trusted_anchor = build_snapshot_anchor(leader.state)

    metas = lagger.apply_state_sync_response(resp, trusted_anchor=trusted_anchor)

    assert len(metas) == 3
    assert int(lagger.state.get("height") or 0) == 3
    assert build_snapshot_anchor(lagger.state)["state_root"] == trusted_anchor["state_root"]
