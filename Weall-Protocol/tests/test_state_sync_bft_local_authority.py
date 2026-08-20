from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import StateSyncVerifyError, build_snapshot_anchor
from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id="state-sync-bft-local-authority",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )


def _produce_register_block(ex: WeAllExecutor, signer: str) -> None:
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": signer,
            "nonce": 1,
            "payload": {"pubkey": f"k:{signer}"},
        }
    )
    assert sub["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True


class _SyncPeer:
    def __init__(self, source: WeAllExecutor) -> None:
        self.source = source

    def request_state_sync(self, _peer_id, req, **_kwargs):
        return self.source._state_sync_service().handle_request(req)


def test_snapshot_anchor_excludes_node_local_bft_identity() -> None:
    left = {
        "height": 3,
        "tip": "b3",
        "tip_hash": "h3",
        "accounts": {},
        "bft": {"last_voted_view": 2, "last_voted_block_id": "a"},
    }
    right = copy.deepcopy(left)
    right["bft"] = {"last_voted_view": 9, "last_voted_block_id": "z"}

    assert build_snapshot_anchor(left) == build_snapshot_anchor(right)


def test_snapshot_response_never_transfers_node_local_bft(tmp_path: Path) -> None:
    source = _make_executor(tmp_path, "source")
    source._bft.record_local_vote(view=4, block_id="source-vote")
    source._persist_bft_state()
    anchor = build_snapshot_anchor(source.state)
    req = StateSyncRequestMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_REQUEST,
            chain_id=source.chain_id,
            schema_version=source._schema_version(),
            tx_index_hash=source._tx_index_hash,
            corr_id="bft-local",
        ),
        mode="snapshot",
        selector={"trusted_anchor": anchor},
    )

    resp = source._state_sync_service().handle_request(req)
    assert resp.ok is True
    assert isinstance(resp.snapshot, dict)
    assert "bft" not in resp.snapshot
    source._state_sync_service().verify_response(resp, trusted_anchor=anchor)

    poisoned_snapshot = dict(resp.snapshot)
    poisoned_snapshot["bft"] = {"last_voted_view": -1}
    poisoned = StateSyncResponseMsg(
        header=resp.header,
        ok=True,
        reason=resp.reason,
        height=resp.height,
        snapshot=poisoned_snapshot,
        blocks=resp.blocks,
        snapshot_hash=resp.snapshot_hash,
        snapshot_anchor=resp.snapshot_anchor,
    )
    with pytest.raises(StateSyncVerifyError, match="snapshot_contains_node_local_bft"):
        source._state_sync_service().verify_response(poisoned, trusted_anchor=anchor)


def test_checkpoint_snapshot_cannot_erase_local_signing_history(tmp_path: Path) -> None:
    leader = _make_executor(tmp_path, "leader")
    lagger = _make_executor(tmp_path, "lagger")
    for signer in ("@u1", "@u2", "@u3"):
        _produce_register_block(leader, signer)

    assert lagger._bft.record_local_vote(view=7, block_id="local-vote") is True
    assert lagger._bft.record_local_proposal(view=7, block_id="local-proposal") is True
    lagger._persist_bft_state()
    before_state = copy.deepcopy(lagger.state)

    leader._db.prune_history(
        retain_last_blocks=1,
        retain_blocks_ms=0,
        retain_bft_candidates_ms=0,
    )
    anchor = build_snapshot_anchor(leader.state)

    with pytest.raises(ExecutorError, match="state_sync_snapshot_local_signing_history_present"):
        lagger.request_and_apply_state_sync(
            _SyncPeer(leader),
            "leader",
            trusted_anchor=anchor,
            timeout_ms=100,
            sleep_ms=0,
        )

    assert lagger.state == before_state
    assert lagger._bft.last_voted_view == 7
    assert lagger._bft.last_voted_block_id == "local-vote"
    assert lagger._bft.last_proposed_view == 7
    assert lagger._bft.last_proposed_block_id == "local-proposal"
    assert lagger._bft.record_local_vote(view=7, block_id="conflicting-vote") is False
    assert lagger._bft.record_local_proposal(view=7, block_id="conflicting-proposal") is False
