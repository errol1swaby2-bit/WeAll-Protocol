from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, chain_id: str = "batch12-sync") -> WeAllExecutor:
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


class _RoundLimitedTransport:
    def __init__(self, source: WeAllExecutor, *, blocks_per_round: int) -> None:
        self.source = source
        self.blocks_per_round = max(1, int(blocks_per_round))
        self.requests: list[tuple[int, int]] = []

    def request_state_sync(
        self, peer_id: str, req: StateSyncRequestMsg, **_: object
    ) -> StateSyncResponseMsg:
        self.requests.append((int(req.from_height or 0), int(req.to_height or 0)))
        start = int(req.from_height or 0)
        end = min(int(req.to_height or 0), start + self.blocks_per_round)
        blocks = []
        for h in range(start + 1, end + 1):
            blk = self.source.get_block_by_height(h)
            assert isinstance(blk, dict)
            blk2 = dict(blk)
            blk2["parent_block_id"] = str(blk2.get("prev_block_id") or "")
            blk2["prev_block_hash"] = ""
            blocks.append(blk2)
        hdr = WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=self.source.chain_id,
            schema_version="1",
            tx_index_hash=self.source._tx_index_hash,
            sent_ts_ms=0,
            corr_id=req.header.corr_id,
        )
        return StateSyncResponseMsg(
            header=hdr,
            ok=True,
            reason=None,
            height=int(self.source.state.get("height") or 0),
            snapshot=None,
            blocks=tuple(blocks),
            snapshot_hash=None,
            snapshot_anchor=build_snapshot_anchor(self.source.state),
        )


class _NoProgressTransport:
    def __init__(self, source: WeAllExecutor) -> None:
        self.source = source

    def request_state_sync(
        self, peer_id: str, req: StateSyncRequestMsg, **_: object
    ) -> StateSyncResponseMsg:
        hdr = WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=self.source.chain_id,
            schema_version="1",
            tx_index_hash=self.source._tx_index_hash,
            sent_ts_ms=0,
            corr_id=req.header.corr_id,
        )
        return StateSyncResponseMsg(
            header=hdr,
            ok=True,
            reason=None,
            height=int(self.source.state.get("height") or 0),
            snapshot=None,
            blocks=(),
            snapshot_hash=None,
            snapshot_anchor=build_snapshot_anchor(self.source.state),
        )


def test_request_and_apply_state_sync_advances_in_multiple_rounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WEALL_SYNC_MAX_DELTA_BLOCKS", "2")
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    for i in range(1, 6):
        _produce_register_block(leader, f"@u{i}", 1)

    transport = _RoundLimitedTransport(leader, blocks_per_round=2)
    anchor = build_snapshot_anchor(leader.state)
    metas = lagger.request_and_apply_state_sync(transport, "peer-1", trusted_anchor=anchor)

    assert len(metas) == 5
    assert int(lagger.state.get("height") or 0) == 5
    assert str(lagger.state.get("tip") or "") == str(leader.state.get("tip") or "")
    assert transport.requests == [(0, 2), (2, 4), (4, 5)]


def test_request_and_apply_state_sync_rejects_ok_response_without_progress(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    _produce_register_block(leader, "@u1", 1)
    _produce_register_block(leader, "@u2", 1)

    transport = _NoProgressTransport(leader)
    anchor = build_snapshot_anchor(leader.state)

    with pytest.raises(ExecutorError, match="state_sync_no_progress"):
        lagger.request_and_apply_state_sync(transport, "peer-1", trusted_anchor=anchor)

    assert int(lagger.state.get("height") or 0) == 0
