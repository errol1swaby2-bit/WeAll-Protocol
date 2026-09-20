from __future__ import annotations

import pytest

from weall.runtime import bft_hotstuff
from weall.runtime.bft_hotstuff import HotStuffBFT


def test_process_local_pacemaker_anchor_is_not_exported_or_roundtripped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bft_hotstuff, "_now_ms", lambda: 1_000)
    hs = HotStuffBFT(chain_id="pb001baf")
    hs.view = 7
    hs.finalized_block_id = "block-5"
    hs.finalized_view = 5

    state1 = hs.export_state()
    assert "last_progress_ms" not in state1

    monkeypatch.setattr(bft_hotstuff, "_now_ms", lambda: 2_000)
    restored = HotStuffBFT(chain_id="pb001baf")
    restored.load_from_state({"bft": state1})
    state2 = restored.export_state()

    assert restored.last_progress_ms == 2_000
    assert state1 == state2
