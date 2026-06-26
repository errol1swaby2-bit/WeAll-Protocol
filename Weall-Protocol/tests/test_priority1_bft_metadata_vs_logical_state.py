from __future__ import annotations

import hashlib
import json

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def _qc(chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def _logical_bft_state(hs: HotStuffBFT) -> dict:
    st = hs.export_state()
    return {
        "high_qc": st.get("high_qc"),
        "locked_qc": st.get("locked_qc"),
        "finalized_view": int(st.get("finalized_view") or 0),
        "finalized_block_id": str(st.get("finalized_block_id") or ""),
        "last_voted_view": int(st.get("last_voted_view") or 0),
        "last_voted_block_id": str(st.get("last_voted_block_id") or ""),
    }


def _logical_hash(hs: HotStuffBFT) -> str:
    payload = json.dumps(
        _logical_bft_state(hs),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_roundtrip_metadata_drift_does_not_change_logical_bft_hash_batch83() -> None:
    hs = HotStuffBFT(chain_id="batch83")
    hs.high_qc = _qc("batch83", 7, "B7", "B6")
    hs.locked_qc = _qc("batch83", 5, "B5", "B4")
    hs.finalized_view = 4
    hs.finalized_block_id = "B4"
    assert hs.record_local_vote(view=8, block_id="B8") is True

    h1 = _logical_hash(hs)

    hs2 = HotStuffBFT(chain_id="batch83")
    hs2.load_from_state({"bft": hs.export_state()})
    h2 = _logical_hash(hs2)

    assert h1 == h2
    assert _logical_bft_state(hs) == _logical_bft_state(hs2)


def test_higher_qc_updates_logical_hash_monotonically_batch83() -> None:
    hs = HotStuffBFT(chain_id="batch83")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch83", 3, "B", "A"))
    h1 = _logical_hash(hs)

    hs.observe_qc(blocks=blocks, qc=_qc("batch83", 4, "C", "B"))
    h2 = _logical_hash(hs)

    assert h1 != h2
    assert hs.high_qc is not None
    assert hs.high_qc.block_id == "C"
    assert int(hs.high_qc.view) == 4


def test_stale_qc_does_not_change_logical_bft_hash_batch83() -> None:
    hs = HotStuffBFT(chain_id="batch83")
    blocks = {
        "A": {"prev_block_id": ""},
        "B": {"prev_block_id": "A"},
        "C": {"prev_block_id": "B"},
    }

    hs.observe_qc(blocks=blocks, qc=_qc("batch83", 4, "C", "B"))
    h1 = _logical_hash(hs)

    hs.observe_qc(blocks=blocks, qc=_qc("batch83", 3, "B", "A"))
    h2 = _logical_hash(hs)

    assert h1 == h2


def test_same_logical_bft_state_same_hash_across_instances_batch83() -> None:
    hs1 = HotStuffBFT(chain_id="batch83")
    hs2 = HotStuffBFT(chain_id="batch83")

    qc_high = _qc("batch83", 6, "H6", "H5")
    qc_lock = _qc("batch83", 4, "L4", "L3")

    hs1.high_qc = qc_high
    hs1.locked_qc = qc_lock
    hs1.finalized_view = 3
    hs1.finalized_block_id = "F3"

    hs2.high_qc = qc_high
    hs2.locked_qc = qc_lock
    hs2.finalized_view = 3
    hs2.finalized_block_id = "F3"

    assert _logical_bft_state(hs1) == _logical_bft_state(hs2)
    assert _logical_hash(hs1) == _logical_hash(hs2)
