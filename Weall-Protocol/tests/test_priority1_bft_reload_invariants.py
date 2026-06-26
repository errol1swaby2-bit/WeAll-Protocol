from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, QuorumCert


def _qc(*, chain_id: str, view: int, block_id: str, parent_id: str) -> QuorumCert:
    return QuorumCert(
        chain_id=chain_id,
        view=view,
        block_id=block_id,
        block_hash=f"{block_id}-h",
        parent_id=parent_id,
        votes=tuple(),
    )


def test_timeout_backoff_and_last_timeout_view_survive_multiple_reloads_batch45() -> None:
    hs = HotStuffBFT(chain_id="batch45")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=2)
    hs.note_timeout_emitted(view=3)

    state1 = hs.export_state()
    assert int(state1.get("last_timeout_view") or 0) == 3
    assert int(state1.get("timeout_backoff_exp") or 0) >= 2
    assert hs.pacemaker_timeout_ms() == 4000

    hs2 = HotStuffBFT(chain_id="batch45")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": state1})
    assert int(hs2.export_state().get("last_timeout_view") or 0) == 3
    assert hs2.pacemaker_timeout_ms() == 4000

    hs3 = HotStuffBFT(chain_id="batch45")
    hs3.timeout_base_ms = 1000
    hs3.load_from_state({"bft": hs2.export_state()})
    assert int(hs3.export_state().get("last_timeout_view") or 0) == 3
    assert hs3.pacemaker_timeout_ms() == 4000


def test_progress_resets_backoff_and_reset_survives_reload_batch45() -> None:
    hs = HotStuffBFT(chain_id="batch45")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=4)
    hs.note_timeout_emitted(view=5)
    assert hs.pacemaker_timeout_ms() == 4000

    hs.note_progress()
    assert hs.pacemaker_timeout_ms() == 1000

    hs2 = HotStuffBFT(chain_id="batch45")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": hs.export_state()})
    assert hs2.pacemaker_timeout_ms() == 1000
    assert int(hs2.export_state().get("timeout_backoff_exp", 99)) == 0


def test_high_qc_roundtrip_preserves_fresher_state_batch45() -> None:
    hs = HotStuffBFT(chain_id="batch45")

    high = _qc(chain_id="batch45", view=8, block_id="B8", parent_id="B7")
    hs.high_qc = high

    hs2 = HotStuffBFT(chain_id="batch45")
    hs2.load_from_state({"bft": hs.export_state()})
    assert hs2.high_qc is not None
    assert int(hs2.high_qc.view) == 8
    assert hs2.high_qc.block_id == "B8"

    stale_state = dict(hs2.export_state())
    stale_state["high_qc"] = {
        "chain_id": "batch45",
        "view": 3,
        "block_id": "B3",
        "block_hash": "B3-h",
        "parent_id": "B2",
        "votes": [],
    }

    hs3 = HotStuffBFT(chain_id="batch45")
    hs3.load_from_state({"bft": stale_state})
    assert hs3.high_qc is not None
    assert int(hs3.high_qc.view) == 3

    hs4 = HotStuffBFT(chain_id="batch45")
    hs4.load_from_state({"bft": hs.export_state()})
    assert hs4.high_qc is not None
    assert int(hs4.high_qc.view) == 8
    assert hs4.high_qc.block_id == "B8"


def test_local_vote_state_remains_monotonic_across_multiple_reloads_batch45() -> None:
    hs = HotStuffBFT(chain_id="batch45")

    assert hs.record_local_vote(view=6, block_id="B6") is True
    assert hs.record_local_vote(view=6, block_id="B6") is True
    assert hs.record_local_vote(view=6, block_id="X6") is False

    hs2 = HotStuffBFT(chain_id="batch45")
    hs2.load_from_state({"bft": hs.export_state()})
    st2 = hs2.export_state()
    assert int(st2.get("last_voted_view") or 0) == 6
    assert str(st2.get("last_voted_block_id") or "") == "B6"

    assert hs2.record_local_vote(view=5, block_id="B5") is False
    assert hs2.record_local_vote(view=7, block_id="B7") is True

    hs3 = HotStuffBFT(chain_id="batch45")
    hs3.load_from_state({"bft": hs2.export_state()})
    st3 = hs3.export_state()
    assert int(st3.get("last_voted_view") or 0) == 7
    assert str(st3.get("last_voted_block_id") or "") == "B7"
