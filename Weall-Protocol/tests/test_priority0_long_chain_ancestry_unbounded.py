from __future__ import annotations

from weall.runtime.bft_hotstuff import HotStuffBFT, qc_from_json
from weall.runtime.block_admission import admit_bft_commit_block
from weall.runtime.fork_choice import choose_head


def _chain(length: int) -> dict[str, dict[str, object]]:
    blocks: dict[str, dict[str, object]] = {"G": {"prev_block_id": "", "height": 0}}
    prev = "G"
    for height in range(1, length + 1):
        bid = f"B{height}"
        blocks[bid] = {"block_id": bid, "prev_block_id": prev, "height": height}
        prev = bid
    return blocks


def _qc(chain_id: str, view: int, block_id: str, parent_id: str) -> dict[str, object]:
    return {
        "t": "QC",
        "chain_id": chain_id,
        "view": view,
        "block_id": block_id,
        "block_hash": f"h:{block_id}",
        "parent_id": parent_id,
        "votes": [],
    }


def test_hotstuff_can_vote_for_descendant_past_old_hop_cap() -> None:
    blocks = _chain(2605)
    hs = HotStuffBFT(chain_id="long-chain")
    hs.locked_qc = qc_from_json(_qc("long-chain", 100, "B5", "B4"))
    assert hs.locked_qc is not None
    assert hs.can_vote_for(blocks=blocks, block_id="B2605", justify_qc=None) is True


def test_observe_qc_advances_lock_and_finality_past_old_hop_cap() -> None:
    blocks = _chain(2605)
    hs = HotStuffBFT(chain_id="long-chain")
    hs.locked_qc = qc_from_json(_qc("long-chain", 100, "B5", "B4"))
    hs.finalized_block_id = "B3"
    hs.finalized_view = 90

    finalized = hs.observe_qc(
        blocks=blocks, qc=qc_from_json(_qc("long-chain", 2605, "B2605", "B2604"))
    )

    assert hs.locked_qc is not None
    assert hs.locked_qc.block_id == "B2605"
    assert finalized == "B2603"
    assert hs.finalized_block_id == "B2603"


def test_fork_choice_prefers_high_qc_head_on_long_chain() -> None:
    blocks = _chain(2605)
    state = {
        "blocks": blocks,
        "bft": {
            "finalized_block_id": "B5",
            "high_qc": _qc("long-chain", 2605, "B2605", "B2604"),
        },
        "block_attestations": {},
    }
    assert choose_head(state) == "B2605"


def test_commit_admission_accepts_finalized_descendant_on_long_chain() -> None:
    blocks = _chain(2605)
    block = {"block_id": "B2605", "prev_block_id": "B2604", "height": 2605}
    state = {
        "config": {"validators": ["v1", "v2", "v3", "v4"]},
        "validator_pubkeys": {},
        "bft": {
            "enabled": True,
            "finalized_block_id": "B5",
            "locked_qc": _qc("long-chain", 100, "B5", "B4"),
            "high_qc": _qc("long-chain", 2604, "B2604", "B2603"),
        },
    }

    ok, rej = admit_bft_commit_block(block=block, state=state, blocks_map=blocks)

    assert ok is True
    assert rej is None
