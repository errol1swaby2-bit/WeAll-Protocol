from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, chain_id: str = "batch6-sync") -> WeAllExecutor:
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


def _delta_response_from(source: WeAllExecutor, *, from_height: int, to_height: int | None = None) -> StateSyncResponseMsg:
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
    hdr = WireHeader(
        type=MsgType.STATE_SYNC_RESPONSE,
        chain_id=source.chain_id,
        schema_version="1",
        tx_index_hash=source._tx_index_hash,
        sent_ts_ms=0,
        corr_id="batch6",
    )
    return StateSyncResponseMsg(
        header=hdr,
        ok=True,
        reason=None,
        height=int(source.state.get("height") or 0),
        snapshot=None,
        blocks=tuple(blocks),
        snapshot_hash=None,
        snapshot_anchor=build_snapshot_anchor(source.state),
    )


def test_apply_state_sync_response_replays_contiguous_delta(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    _produce_register_block(leader, "@u1", 1)
    _produce_register_block(leader, "@u2", 1)
    _produce_register_block(leader, "@u3", 1)

    resp = _delta_response_from(leader, from_height=0)
    metas = lagger.apply_state_sync_response(resp, trusted_anchor=build_snapshot_anchor(leader.state))

    assert [m.ok for m in metas] == [True, True, True]
    assert int(lagger.state.get("height") or 0) == 3
    assert str(lagger.state.get("tip") or "") == str(leader.state.get("tip") or "")


def test_apply_state_sync_response_rejects_anchor_mismatch(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    _produce_register_block(leader, "@u1", 1)
    _produce_register_block(leader, "@u2", 1)

    resp = _delta_response_from(leader, from_height=0)
    bad_anchor = build_snapshot_anchor(leader.state)
    bad_anchor["tip_hash"] = "deadbeef"

    with pytest.raises(ExecutorError, match="state_sync_verify_failed"):
        lagger.apply_state_sync_response(resp, trusted_anchor=bad_anchor)

    assert int(lagger.state.get("height") or 0) == 0


def test_apply_state_sync_response_rejects_gapped_delta(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    _produce_register_block(leader, "@u1", 1)
    _produce_register_block(leader, "@u2", 1)
    _produce_register_block(leader, "@u3", 1)

    full = _delta_response_from(leader, from_height=0)
    gapped = StateSyncResponseMsg(
        header=full.header,
        ok=True,
        reason=None,
        height=full.height,
        snapshot=None,
        blocks=(full.blocks[0], full.blocks[2]),
        snapshot_hash=None,
        snapshot_anchor=full.snapshot_anchor,
    )

    with pytest.raises(ExecutorError, match="state_sync_verify_failed:block_height_not_contiguous"):
        lagger.apply_state_sync_response(gapped, trusted_anchor=build_snapshot_anchor(leader.state))

    assert int(lagger.state.get("height") or 0) == 0
