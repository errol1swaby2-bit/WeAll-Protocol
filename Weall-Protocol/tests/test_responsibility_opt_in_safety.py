from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    *,
    signer: str,
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def _tier2_account() -> dict:
    return {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation": 10}


def _roles_with_empty_jurors() -> dict:
    return {"jurors": {"by_id": {}, "active_set": []}}


def test_node_operator_activation_does_not_opt_in_reviewer_lanes() -> None:
    state = {
        "height": 1,
        "accounts": {"alice": _tier2_account()},
        "roles": {"node_operators": {"by_id": {"alice": {"account_id": "alice", "enrolled": True}}, "active_set": []}},
    }

    out = apply_tx(
        state,
        _env(
            "ROLE_NODE_OPERATOR_ACTIVATE",
            {"account_id": "alice"},
            signer="SYSTEM",
            nonce=1,
            system=True,
        ),
    )

    assert out["applied"] == "ROLE_NODE_OPERATOR_ACTIVATE"
    rec = state["roles"]["node_operators"]["by_id"]["alice"]
    assert rec["active"] is True
    assert "reviewer" not in rec.get("responsibilities", {})
    assert rec["responsibilities"]["validator"]["opted_in"] is False
    assert rec["responsibilities"]["storage"]["opted_in"] is False


def test_dispute_juror_assign_rejects_validator_without_juror_opt_in() -> None:
    state = {
        "height": 1,
        "accounts": {"validator1": _tier2_account(), "reporter": _tier2_account()},
        "roles": {
            "validators": {"active_set": ["validator1"], "by_id": {"validator1": {"active": True}}},
            **_roles_with_empty_jurors(),
        },
        "disputes_by_id": {
            "d1": {
                "id": "d1",
                "stage": "open",
                "target_type": "content",
                "target_id": "post:reporter:1",
                "opened_by": "reporter",
                "jurors": {},
                "assigned_jurors": [],
                "eligible_juror_ids": [],
            }
        },
    }

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            state,
            _env(
                "DISPUTE_JUROR_ASSIGN",
                {"dispute_id": "d1", "juror": "validator1"},
                signer="SYSTEM",
                nonce=4,
                system=True,
            ),
        )

    assert ei.value.code == "forbidden"
    assert ei.value.reason == "reviewer_responsibility_not_active"


def test_dispute_juror_assign_accepts_explicit_juror_reviewer_lane() -> None:
    state = {
        "height": 1,
        "accounts": {"juror1": _tier2_account(), "reporter": _tier2_account()},
        "roles": _roles_with_empty_jurors(),
        "disputes_by_id": {
            "d1": {
                "id": "d1",
                "stage": "open",
                "target_type": "content",
                "target_id": "post:reporter:1",
                "opened_by": "reporter",
                "jurors": {},
                "assigned_jurors": [],
                "eligible_juror_ids": [],
            }
        },
    }

    apply_tx(state, _env("ROLE_JUROR_ENROLL", {"account_id": "juror1"}, signer="juror1", nonce=1))
    apply_tx(state, _env("REVIEWER_LANE_OPT_IN", {"account_id": "juror1", "lane": "dispute_review"}, signer="juror1", nonce=2))
    out = apply_tx(
        state,
        _env(
            "DISPUTE_JUROR_ASSIGN",
            {"dispute_id": "d1", "juror": "juror1"},
            signer="SYSTEM",
            nonce=2,
            system=True,
        ),
    )

    assert out["applied"] == "DISPUTE_JUROR_ASSIGN"
    assert state["disputes_by_id"]["d1"]["assigned_jurors"] == ["juror1"]


def test_poh_tier2_assignment_rejects_tier2_without_juror_opt_in_when_roles_exist() -> None:
    state = {
        "height": 1,
        "chain_id": "test",
        "params": {"poh": {"tier2_n_jurors": 1, "tier2_min_total_reviews": 1, "tier2_pass_threshold": 1, "tier2_fail_max": 0}},
        "accounts": {"alice": {**_tier2_account(), "poh_tier": 1}, "tier2_no_role": _tier2_account()},
        "roles": _roles_with_empty_jurors(),
    }

    opened = apply_tx(
        state,
        _env(
            "POH_TIER2_REQUEST_OPEN",
            {"account_id": "alice", "video_commitment": "cmt:vid"},
            signer="alice",
            nonce=1,
        ),
    )
    case_id = str(opened["case_id"])

    with pytest.raises(ApplyError) as ei:
        apply_tx(
            state,
            _env(
                "POH_TIER2_JUROR_ASSIGN",
                {"case_id": case_id, "jurors": ["tier2_no_role"], "n_jurors": 1},
                signer="SYSTEM",
                nonce=2,
                system=True,
                parent="POH_TIER2_REQUEST_OPEN",
            ),
        )

    assert ei.value.code == "invalid_tx"
    assert ei.value.reason == "reviewer_responsibility_not_active"


def test_poh_tier2_assignment_accepts_explicit_juror_reviewer_lane() -> None:
    state = {
        "height": 1,
        "chain_id": "test",
        "params": {"poh": {"tier2_n_jurors": 1, "tier2_min_total_reviews": 1, "tier2_pass_threshold": 1, "tier2_fail_max": 0}},
        "accounts": {"alice": {**_tier2_account(), "poh_tier": 1}, "juror1": _tier2_account()},
        "roles": _roles_with_empty_jurors(),
    }

    apply_tx(state, _env("ROLE_JUROR_ENROLL", {"account_id": "juror1"}, signer="juror1", nonce=1))
    apply_tx(state, _env("REVIEWER_LANE_OPT_IN", {"account_id": "juror1", "lane": "poh_async_review"}, signer="juror1", nonce=2))
    opened = apply_tx(
        state,
        _env(
            "POH_TIER2_REQUEST_OPEN",
            {"account_id": "alice", "video_commitment": "cmt:vid"},
            signer="alice",
            nonce=3,
        ),
    )
    case_id = str(opened["case_id"])

    out = apply_tx(
        state,
        _env(
            "POH_TIER2_JUROR_ASSIGN",
            {"case_id": case_id, "jurors": ["juror1"], "n_jurors": 1},
            signer="SYSTEM",
            nonce=3,
            system=True,
            parent="POH_TIER2_REQUEST_OPEN",
        ),
    )

    assert out["applied"] == "POH_TIER2_JUROR_ASSIGN"
    assert "juror1" in state["poh"]["tier2_cases"][case_id]["jurors"]
