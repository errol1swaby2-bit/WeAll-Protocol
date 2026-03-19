from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import build_snapshot_anchor
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str, chain_id: str = "batch11-sync") -> WeAllExecutor:
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


class _LeaderBackedStateSyncPeer:
    def __init__(self, leader: WeAllExecutor) -> None:
        self.leader = leader
        self.calls: list[tuple[int, int | None]] = []

    def request_state_sync(
        self, peer_id: str, req: StateSyncRequestMsg, **_: object
    ) -> StateSyncResponseMsg:
        del peer_id
        self.calls.append(
            (int(req.from_height or 0), None if req.to_height is None else int(req.to_height))
        )
        svc = self.leader._state_sync_service()
        resp = svc.handle_request(req)
        blocks = []
        for blk in list(resp.blocks or ()):
            blk2 = dict(blk)
            blk2["parent_block_id"] = str(blk2.get("prev_block_id") or "")
            blk2["prev_block_hash"] = ""
            blocks.append(blk2)
        return StateSyncResponseMsg(
            header=resp.header,
            ok=resp.ok,
            reason=resp.reason,
            height=resp.height,
            snapshot=resp.snapshot,
            blocks=tuple(blocks),
            snapshot_hash=resp.snapshot_hash,
            snapshot_anchor=resp.snapshot_anchor,
        )


class _NoProgressStateSyncPeer:
    def __init__(self, chain_id: str, tx_index_hash: str, trusted_anchor: dict) -> None:
        self.chain_id = chain_id
        self.tx_index_hash = tx_index_hash
        self.trusted_anchor = dict(trusted_anchor)

    def request_state_sync(
        self, peer_id: str, req: StateSyncRequestMsg, **_: object
    ) -> StateSyncResponseMsg:
        del peer_id
        return StateSyncResponseMsg(
            header=WireHeader(
                type=MsgType.STATE_SYNC_RESPONSE,
                chain_id=self.chain_id,
                schema_version="1",
                tx_index_hash=self.tx_index_hash,
                sent_ts_ms=0,
                corr_id=req.header.corr_id,
            ),
            ok=True,
            reason=None,
            height=int(self.trusted_anchor.get("height") or 0),
            snapshot=None,
            blocks=(),
            snapshot_hash=None,
            snapshot_anchor=dict(self.trusted_anchor),
        )


def test_request_and_apply_state_sync_retries_in_chunks_until_anchor(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_SYNC_MAX_DELTA_BLOCKS", "2")
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")

    for i in range(1, 6):
        _produce_register_block(leader, f"@u{i}", 1)

    peer = _LeaderBackedStateSyncPeer(leader)
    anchor = build_snapshot_anchor(leader.state)
    metas = lagger.request_and_apply_state_sync(peer, "peer-1", trusted_anchor=anchor)

    assert len(metas) == 5
    assert int(lagger.state.get("height") or 0) == 5
    assert str(lagger.state.get("tip") or "") == str(leader.state.get("tip") or "")
    assert peer.calls == [(0, 2), (2, 4), (4, 5)]


def test_request_and_apply_state_sync_rejects_no_progress_from_peer(tmp_path: Path) -> None:
    lagger = _make_executor(tmp_path, "lagger")
    trusted_anchor = {
        "height": 3,
        "tip_hash": "tip-3",
        "state_root": "state-root-3",
        "finalized_height": 0,
        "finalized_block_id": "",
        "snapshot_hash": "snap-3",
    }
    peer = _NoProgressStateSyncPeer(lagger.chain_id, lagger._tx_index_hash, trusted_anchor)

    with pytest.raises(ExecutorError, match="state_sync_no_progress"):
        lagger.request_and_apply_state_sync(peer, "peer-1", trusted_anchor=trusted_anchor)
