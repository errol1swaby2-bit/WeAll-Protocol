from __future__ import annotations

from pathlib import Path

import pytest

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor
from weall.runtime.bft_hotstuff import QuorumCert
from weall.runtime.executor import ExecutorError, WeAllExecutor
from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _hdr() -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        corr_id="c1",
    )


def test_state_sync_verify_rejects_delta_past_finalized_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    st = {
        "height": 5,
        "tip_hash": "tip5",
        "accounts": {},
        "finalized": {"height": 3, "block_id": "b3"},
    }
    svc = StateSyncService(
        chain_id="test",
        schema_version="1",
        tx_index_hash="deadbeef",
        state_provider=lambda: st,
        block_provider=lambda h: {
            "height": h,
            "block_id": f"b{h}",
            "parent_block_id": "" if h <= 1 else f"b{h - 1}",
        },
    )
    anchor = build_snapshot_anchor(st)
    req = StateSyncRequestMsg(
        header=_hdr(), mode="delta", from_height=0, to_height=5, selector={"trusted_anchor": anchor}
    )
    resp = svc.handle_request(req)
    bad = resp.__class__(
        header=resp.header,
        ok=True,
        reason=None,
        height=5,
        snapshot=None,
        snapshot_hash=None,
        snapshot_anchor=anchor,
        blocks=(
            {"height": 1, "block_id": "b1", "parent_block_id": ""},
            {"height": 2, "block_id": "b2", "parent_block_id": "b1"},
            {"height": 3, "block_id": "b3", "parent_block_id": "b2"},
            {"height": 4, "block_id": "b4", "parent_block_id": "b3"},
        ),
    )
    with pytest.raises(StateSyncVerifyError, match="block_height_exceeds_finalized_anchor"):
        svc.verify_response(bad, trusted_anchor=anchor)


def test_restart_rejects_production_consensus_profile_hash_mismatch(tmp_path: Path) -> None:
    db_path = str(tmp_path / "weall.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path()
    )
    st = ex.read_state()
    st.setdefault("meta", {})["production_consensus_profile_hash"] = "bad-hash"
    ex._ledger_store.write(st)
    with pytest.raises(ExecutorError, match="production_consensus_profile_hash mismatch"):
        WeAllExecutor(
            db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path()
        )


def test_restart_rejects_tx_index_hash_mismatch(tmp_path: Path) -> None:
    db_path = str(tmp_path / "weall.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path()
    )
    st = ex.read_state()
    st.setdefault("meta", {})["tx_index_hash"] = "bad-hash"
    ex._ledger_store.write(st)
    with pytest.raises(ExecutorError, match="tx_index_hash mismatch"):
        WeAllExecutor(
            db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path()
        )


def test_restart_preserves_finalized_frontier_after_qc_observation(tmp_path: Path) -> None:
    db_path = str(tmp_path / "weall.db")
    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path()
    )
    ex._bft.blocks = {
        "B0": {"prev_block_id": "", "view": 0},
        "B1": {"prev_block_id": "B0", "view": 1},
        "B2": {"prev_block_id": "B1", "view": 2},
        "B3": {"prev_block_id": "B2", "view": 3},
    }
    qc = QuorumCert(
        chain_id="chain-A", block_id="B3", block_hash="B3-h", parent_id="B2", view=10, votes=()
    )
    finalized = ex._bft.observe_qc(blocks=ex._bft.blocks, qc=qc)
    assert finalized == "B1"
    ex._persist_bft_state()

    ex2 = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path()
    )
    assert (
        ex2.state.get("meta", {}).get("production_consensus_profile_hash")
        == PRODUCTION_CONSENSUS_PROFILE.profile_hash()
    )
    assert ex2._bft.finalized_block_id == "B1"
    assert int(ex2._bft.finalized_view) == 10
