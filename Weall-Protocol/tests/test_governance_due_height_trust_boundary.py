from __future__ import annotations

from weall.runtime.apply.governance import apply_governance
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def test_user_governance_payload_cannot_forge_due_height_for_creation_or_vote() -> None:
    state = {"height": 10, "accounts": {"alice": {"poh_tier": 2}}, "gov_proposals_by_id": {}}

    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "alice",
            1,
            {
                "proposal_id": "p-forged-height",
                "title": "Height trust boundary",
                "body": "User payload metadata must not become protocol height truth.",
                "rules": {"start_stage": "voting"},
                "_due_height": 999,
            },
        ),
    )

    proposal = state["gov_proposals_by_id"]["p-forged-height"]
    assert proposal["created_at_height"] == 11
    assert proposal["voting_opened_at_height"] == 11

    apply_governance(
        state,
        _env(
            "GOV_VOTE_CAST",
            "alice",
            2,
            {"proposal_id": "p-forged-height", "vote": "yes", "_due_height": 999},
        ),
    )

    assert proposal["votes"]["alice"]["height"] == 11
    assert proposal["updated_at_height"] == 11


def test_system_governance_queue_due_height_remains_authoritative() -> None:
    state = {"height": 10, "accounts": {"alice": {"poh_tier": 2}}, "gov_proposals_by_id": {}}

    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "alice",
            1,
            {"proposal_id": "p-system-height", "title": "System height", "body": "draft"},
        ),
    )
    apply_governance(
        state,
        _env(
            "GOV_STAGE_SET",
            "SYSTEM",
            1,
            {"proposal_id": "p-system-height", "stage": "poll", "_due_height": 99},
            system=True,
            parent="gov:p-system-height:99",
        ),
    )

    proposal = state["gov_proposals_by_id"]["p-system-height"]
    assert proposal["stage"] == "poll"
    assert proposal["poll_opened_at_height"] == 99
    assert state["gov_stage_set_receipts"][-1]["_height"] == 99
