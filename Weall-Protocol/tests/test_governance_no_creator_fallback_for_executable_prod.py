from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system, parent=parent)


def _base_state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 10,
        "time": 9_999,
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "balance": 0},
        },
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 1,
            "economics_enabled": False,
            "gov_action_allowlist": ["ECONOMICS_ACTIVATION", "GOV_QUORUM_SET", "VALIDATOR_SET_UPDATE"],
        },
        "system_queue": [],
    }


def _state_with_explicit_electorate() -> dict:
    st = _base_state()
    st["roles"] = {
        "validators": {
            "active_set": ["@alice"],
            "by_id": {"@alice": {"status": "active", "active": True}},
        }
    }
    return st


def test_executable_governance_rejects_creator_fallback_when_no_explicit_electorate() -> None:
    st = _base_state()

    with pytest.raises(ApplyError) as ei:
        apply_tx(
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

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "executable_governance_requires_explicit_electorate"
    assert not st.get("gov_proposals_by_id")
    assert not st.get("system_queue")


def test_non_executable_community_decision_preserves_creator_fallback() -> None:
    st = _base_state()

    apply_tx(
        st,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@alice",
            1,
            {"proposal_id": "p-community", "title": "community signal", "rules": {"start_stage": "voting"}},
        ),
    )
    proposal = st["gov_proposals_by_id"]["p-community"]

    assert proposal["eligible_validator_ids"] == ["@alice"]
    assert proposal["required_votes"] == 1
    assert proposal["actions"] == []


def test_executable_governance_uses_explicit_electorate_and_not_creator_fallback() -> None:
    st = _state_with_explicit_electorate()

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

    assert proposal["eligible_validator_ids"] == ["@alice"]
    assert proposal["required_votes"] == 1
    assert "electorate_failure_reason" not in proposal


def test_editing_actions_into_existing_decision_requires_explicit_electorate() -> None:
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

    with pytest.raises(ApplyError) as ei:
        apply_tx(
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

    assert ei.value.reason == "executable_governance_requires_explicit_electorate"
