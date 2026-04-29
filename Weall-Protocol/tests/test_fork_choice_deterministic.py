from __future__ import annotations

from weall.runtime.fork_choice import choose_head


def test_choose_head_prefers_more_attestations_then_lexical_tiebreak() -> None:
    st = {
        "finalized": {"height": 0, "block_id": None},
        "blocks": {
            "b1": {"height": 1, "prev_block_id": "gen"},
            "b2": {"height": 2, "prev_block_id": "b1"},
            "c2": {"height": 2, "prev_block_id": "b1"},
        },
        "block_attestations": {
            "b2": {"v1": {"nonce": 1, "payload": {"height": 2, "round": 0}}},
            "c2": {
                "v1": {"nonce": 1, "payload": {"height": 2, "round": 0}},
                "v2": {"nonce": 1, "payload": {"height": 2, "round": 0}},
            },
        },
    }

    head = choose_head(st)
    assert head == "c2"

    # Now tie on attestations, break ties lexicographically.
    st["block_attestations"]["b2"]["v2"] = {"nonce": 1, "payload": {"height": 2, "round": 0}}
    head2 = choose_head(st)
    assert head2 == max("b2", "c2")
