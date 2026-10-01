from __future__ import annotations

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="",
        system=system,
        parent=parent,
    )


def _base_state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 10,
        "time": 9_999,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "balance": 0,
            },
            "@validator-only": {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "balance": 0,
            },
        },
        "roles": {
            "validators": {
                "active_set": ["@validator-only"],
                "by_id": {"@validator-only": {"status": "active", "active": True}},
            }
        },
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 1,
            "economics_enabled": False,
            "gov_action_allowlist": [
                "ECONOMICS_ACTIVATION",
                "GOV_QUORUM_SET",
                "VALIDATOR_SET_UPDATE",
            ],
        },
        "system_queue": [],
    }


def test_executable_governance_uses_protocol_tier2_electorate_without_validator_fallback() -> None:
    st = _base_state()

    out = apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-econ",
                "title": "activate economics",
                "rules": {"start_stage": "voting"},
                "actions": [{"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}}],
            },
        ),
    )

    assert out == {"applied": True, "proposal_id": "p-econ"}
    proposal = st["gov_proposals_by_id"]["p-econ"]
    assert proposal["electorate_scope"] == "protocol_tier2"
    assert proposal["electorate_source"] == "protocol_tier2_accounts"
    assert proposal["eligible_voter_ids"] == ["@alice"]
    assert proposal["eligible_validator_ids"] == ["@alice"]
    assert proposal["required_votes"] == 1
    assert proposal["electorate_commitment"]
    assert "@validator-only" not in proposal["eligible_voter_ids"]


def test_non_executable_production_decision_uses_same_verified_human_scope() -> None:
    st = _base_state()

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-community",
                "title": "community signal",
                "rules": {"start_stage": "voting"},
            },
        ),
    )
    proposal = st["gov_proposals_by_id"]["p-community"]

    assert proposal["electorate_scope"] == "protocol_tier2"
    assert proposal["eligible_voter_ids"] == ["@alice"]
    assert proposal["required_votes"] == 1
    assert proposal["actions"] == []


def test_validator_role_does_not_grant_production_governance_vote_authority() -> None:
    st = _base_state()

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {
                "proposal_id": "p-safe",
                "title": "safe quorum update",
                "rules": {"start_stage": "voting"},
                "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 5000}}],
            },
        ),
    )
    proposal = st["gov_proposals_by_id"]["p-safe"]

    assert proposal["eligible_voter_ids"] == ["@alice"]
    assert proposal["eligible_validator_ids"] == ["@alice"]
    assert "@validator-only" not in proposal["eligible_voter_ids"]
    assert proposal["electorate_source"] == "protocol_tier2_accounts"
    assert "electorate_failure_reason" not in proposal


def test_editing_actions_into_existing_decision_preserves_verified_human_electorate() -> None:
    st = _base_state()
    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {"proposal_id": "p-edit", "title": "draft", "rules": {"start_stage": "draft"}},
        ),
    )

    out = apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_EDIT",
            "@alice",
            2,
            {
                "proposal_id": "p-edit",
                "actions": [{"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}}],
            },
        ),
    )

    assert out == {"applied": True, "proposal_id": "p-edit"}
    proposal = st["gov_proposals_by_id"]["p-edit"]
    assert proposal["electorate_scope"] == "protocol_tier2"
    assert proposal["electorate_source"] == "protocol_tier2_accounts"
    assert proposal["eligible_voter_ids"] == ["@alice"]
    assert proposal["required_votes"] == 1
    assert proposal["actions"] == [
        {"tx_type": "ECONOMICS_ACTIVATION", "payload": {"enable": True}}
    ]
