from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT


def test_pacemaker_timeout_backs_off_then_resets() -> None:
    hs = HotStuffBFT(chain_id="c")
    hs.timeout_base_ms = 1000
    assert hs.pacemaker_timeout_ms() == 1000
    hs.note_timeout_emitted(view=0)
    assert hs.pacemaker_timeout_ms() == 2000
    hs.note_timeout_emitted(view=1)
    assert hs.pacemaker_timeout_ms() == 4000
    hs.note_progress()
    assert hs.pacemaker_timeout_ms() == 1000
