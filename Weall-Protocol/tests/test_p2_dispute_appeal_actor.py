from __future__ import annotations

import pytest

from weall.api.routes_public_parts.disputes import _appeal_eligibility
from weall.runtime.apply.dispute import (
    DisputeApplyError,
    _appeal_allowed_accounts,
    _require_dispute_appeal_actor,
    apply_dispute,
)
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, object]) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        system=False,
    )


def test_account_dispute_binds_appeal_to_target_account() -> None:
    state = {
        "height": 10,
        "accounts": {
            "@reporter": {"poh_tier": 2},
            "@subject": {"poh_tier": 2},
            "@intruder": {"poh_tier": 2},
        },
        "roles": {},
        "system_queue": [],
    }
    apply_dispute(
        state,
        _env(
            "DISPUTE_OPEN",
            "@reporter",
            1,
            {
                "dispute_id": "d-account",
                "target_type": "account",
                "target_id": "@subject",
                "reason": "account restriction review",
            },
        ),
    )
    dispute = state["disputes_by_id"]["d-account"]
    assert dispute["appeal_allowed_accounts"] == ["@subject"]
    assert _appeal_allowed_accounts(state, dispute) == ["@subject"]

    _require_dispute_appeal_actor(state, dispute, "@subject")
    with pytest.raises(DisputeApplyError) as exc_info:
        _require_dispute_appeal_actor(state, dispute, "@intruder")
    assert exc_info.value.code == "forbidden"
    assert exc_info.value.reason == "appeal_not_target_owner"


def test_unresolved_noncontent_appeal_binding_fails_closed() -> None:
    state = {
        "accounts": {"@intruder": {"poh_tier": 2}},
    }
    dispute = {
        "dispute_id": "d-group",
        "target_type": "group",
        "target_id": "group:unknown",
        "appeal_allowed_accounts": [],
    }
    assert _appeal_allowed_accounts(state, dispute) == []
    with pytest.raises(DisputeApplyError) as exc_info:
        _require_dispute_appeal_actor(state, dispute, "@intruder")
    assert exc_info.value.code == "forbidden"
    assert exc_info.value.reason == "appeal_actor_unresolved"


def test_legacy_account_dispute_read_model_derives_subject() -> None:
    state = {"accounts": {"@subject": {"poh_tier": 2}}}
    dispute = {
        "dispute_id": "d-legacy-account",
        "target_type": "account",
        "target_id": "@subject",
        "stage": "appeal_window",
    }
    eligibility = _appeal_eligibility(state, dispute, viewer="@subject")
    assert eligibility["can_file"] is True
    assert eligibility["allowed_accounts"] == ["@subject"]
