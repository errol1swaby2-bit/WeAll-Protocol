from __future__ import annotations

from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _state() -> dict:
    return {
        "height": 25,
        "accounts": {
            "alice": {"poh_tier": 2, "banned": False, "locked": False},
            "juror": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {"validators": {"active_set": ["juror"]}},
        "params": {
            "reputation": {
                "dispute": {
                    "juror_vote_window_blocks": 12,
                    "safe_withdraw_blocks": 3,
                    "late_withdraw_penalty_milli": 500,
                    "timeout_penalty_milli": 1500,
                }
            }
        },
        "content": {"posts": {"post-1": {"author": "alice", "visibility": "public"}}, "comments": {}},
    }


def test_dispute_open_and_assignment_record_block_height_phase_markers() -> None:
    state = _state()

    apply_dispute(
        state,
        _env(
            "DISPUTE_OPEN",
            "alice",
            1,
            {
                "dispute_id": "d-height",
                "target_type": "content",
                "target_id": "post-1",
                "reason": "height markers",
                "_due_height": 999,
            },
        ),
    )

    dispute = state["disputes_by_id"]["d-height"]
    assert dispute["opened_at_height"] == 25
    assert dispute["stage_set_at_height"] == 25

    state["height"] = 26
    apply_dispute(
        state,
        _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d-height", "juror": "juror"}, system=True, parent="tx:alice:1"),
    )

    dispute = state["disputes_by_id"]["d-height"]
    assert dispute["stage"] == "juror_review"
    assert dispute["stage_set_at_height"] == 26
    assert dispute["jurors"]["juror"]["assigned_at_height"] == 26


def test_dispute_acceptance_deadlines_are_block_height_based() -> None:
    state = _state()
    apply_dispute(state, _env("DISPUTE_OPEN", "alice", 1, {"dispute_id": "d-window", "target_type": "content", "target_id": "post-1", "reason": "window"}))
    apply_dispute(state, _env("DISPUTE_JUROR_ASSIGN", "SYSTEM", 1, {"dispute_id": "d-window", "juror": "juror"}, system=True, parent="tx:alice:1"))

    state["height"] = 31
    out = apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", "juror", 2, {"dispute_id": "d-window"})) or {}

    juror = state["disputes_by_id"]["d-window"]["jurors"]["juror"]
    assert out["vote_deadline_height"] == 43
    assert out["safe_withdraw_until_height"] == 34
    assert juror["reputation_policy"]["clock"] == "block_height"
