from __future__ import annotations

import pytest

from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.tx_admission_types import TxEnvelope


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict,
    *,
    system: bool = False,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        system=system,
        parent=(f"p:{max(0, nonce - 1)}" if system else None),
    )


def _prepare_group_with_open_spend() -> dict:
    state = {
        "height": 100,
        "params": {"system_signer": "SYSTEM"},
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 3},
            "@bob": {"nonce": 0, "poh_tier": 3},
            "SYSTEM": {"nonce": 0, "poh_tier": 3},
        },
    }
    apply_groups(state, _env("GROUP_CREATE", "@alice", 1, {"group_id": "g-open", "charter": "x"}))
    g = state["roles"]["groups_by_id"]["g-open"]
    g["signers"] = ["@alice", "@bob"]
    g["threshold"] = 2
    state["group_treasury_spends"] = {
        "gsp1": {
            "spend_id": "gsp1",
            "group_id": "g-open",
            "treasury_id": "TREASURY_GROUP::g-open",
            "status": "proposed",
            "allowed_signers": ["@alice", "@bob"],
            "threshold": 2,
            "signatures": {},
            "payload": {"amount": 5},
        }
    }
    return state


def test_group_signers_set_rejects_while_group_spend_open_batch110() -> None:
    state = _prepare_group_with_open_spend()
    with pytest.raises(GroupsApplyError) as exc:
        apply_groups(
            state,
            _env(
                "GROUP_SIGNERS_SET",
                "@alice",
                3,
                {"group_id": "g-open", "signers": ["@alice", "@bob"], "threshold": 2},
            ),
        )
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "group_treasury_spend_open"


def test_group_treasury_policy_set_rejects_while_group_spend_open_batch110() -> None:
    state = _prepare_group_with_open_spend()
    with pytest.raises(GroupsApplyError) as exc:
        apply_groups(
            state,
            _env(
                "GROUP_TREASURY_POLICY_SET",
                "SYSTEM",
                4,
                {"group_id": "g-open", "policy": {"cap": 10}},
                system=True,
            ),
        )
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "group_treasury_spend_open"


def test_group_signers_set_allowed_after_group_spend_cancel_batch110() -> None:
    state = _prepare_group_with_open_spend()
    state["group_treasury_spends"]["gsp1"]["status"] = "canceled"
    meta = apply_groups(
        state,
        _env(
            "GROUP_SIGNERS_SET",
            "@alice",
            5,
            {"group_id": "g-open", "signers": ["@alice", "@bob"], "threshold": 2},
        ),
    )
    assert meta and meta["applied"] == "GROUP_SIGNERS_SET"


def test_group_treasury_policy_set_allowed_after_group_spend_execute_batch110() -> None:
    state = _prepare_group_with_open_spend()
    state["group_treasury_spends"]["gsp1"]["status"] = "executed"
    meta = apply_groups(
        state,
        _env(
            "GROUP_TREASURY_POLICY_SET",
            "SYSTEM",
            6,
            {"group_id": "g-open", "policy": {"cap": 10}},
            system=True,
        ),
    )
    assert meta and meta["applied"] == "GROUP_TREASURY_POLICY_SET"
