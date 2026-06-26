from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT


def test_timeout_backoff_grows_monotonically_batch78() -> None:
    hs = HotStuffBFT(chain_id="batch78")
    hs.timeout_base_ms = 1000

    t0 = hs.pacemaker_timeout_ms()
    hs.note_timeout_emitted(view=1)
    t1 = hs.pacemaker_timeout_ms()
    hs.note_timeout_emitted(view=2)
    t2 = hs.pacemaker_timeout_ms()

    assert t0 == 1000
    assert t1 >= t0
    assert t2 >= t1


def test_progress_resets_timeout_backoff_batch78() -> None:
    hs = HotStuffBFT(chain_id="batch78")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=1)
    hs.note_timeout_emitted(view=2)
    grown = hs.pacemaker_timeout_ms()
    assert grown >= 2000

    hs.note_progress()
    reset = hs.pacemaker_timeout_ms()
    assert reset == 1000


def test_timeout_backoff_survives_roundtrip_without_regression_batch78() -> None:
    hs = HotStuffBFT(chain_id="batch78")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=3)
    hs.note_timeout_emitted(view=4)
    grown = hs.pacemaker_timeout_ms()
    state1 = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch78")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": state1})
    state2 = hs2.export_state()

    assert state1 == state2
    assert hs2.pacemaker_timeout_ms() == grown
    assert int(state2.get("last_timeout_view") or 0) == 4


def test_progress_after_roundtrip_keeps_liveness_reset_batch78() -> None:
    hs = HotStuffBFT(chain_id="batch78")
    hs.timeout_base_ms = 1000

    hs.note_timeout_emitted(view=5)
    hs.note_timeout_emitted(view=6)

    state = hs.export_state()

    hs2 = HotStuffBFT(chain_id="batch78")
    hs2.timeout_base_ms = 1000
    hs2.load_from_state({"bft": state})
    hs2.note_progress()

    assert hs2.pacemaker_timeout_ms() == 1000

    state2 = hs2.export_state()
    hs3 = HotStuffBFT(chain_id="batch78")
    hs3.timeout_base_ms = 1000
    hs3.load_from_state({"bft": state2})

    assert hs3.pacemaker_timeout_ms() == 1000
    assert int(hs3.export_state().get("timeout_backoff_exp") or 0) == 0
