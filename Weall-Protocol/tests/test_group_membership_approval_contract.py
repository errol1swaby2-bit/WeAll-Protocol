from __future__ import annotations

from typing import Any

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import admit_tx
from weall.tx.canon import TxIndex


def _canon() -> TxIndex:
    rows = [
        {
            "id": 1,
            "name": "GROUP_CREATE",
            "context": "mempool",
            "origin": "USER",
            "subject_gate": "Tier2+",
        },
        {
            "id": 2,
            "name": "GROUP_MEMBERSHIP_REQUEST",
            "context": "mempool",
            "origin": "USER",
            "subject_gate": "Tier1+",
        },
        {
            "id": 3,
            "name": "GROUP_MEMBERSHIP_DECIDE",
            "context": "mempool",
            "origin": "USER",
            "subject_gate": "GroupModerator",
        },
    ]
    return TxIndex(
        tx_types=rows,
        by_name={row["name"]: row for row in rows},
        by_id={row["id"]: row for row in rows},
        by_id_str={str(row["id"]): row for row in rows},
        meta={"generated_from": "unit"},
        source_sha256="unit",
    )


@pytest.fixture(autouse=True)
def _unsafe_dev_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")


def _state() -> dict[str, Any]:
    return {
        "chain_id": "membership-contract-test",
        "height": 1,
        "tip": "a" * 64,
        "params": {},
        "accounts": {
            "@owner": {
                "nonce": 0,
                "poh_tier": 2,
                "reputation_milli": 10000,
                "banned": False,
                "locked": False,
            },
            "@member": {
                "nonce": 0,
                "poh_tier": 1,
                "reputation_milli": 10000,
                "banned": False,
                "locked": False,
            },
            "@outsider": {
                "nonce": 0,
                "poh_tier": 2,
                "reputation_milli": 10000,
                "banned": False,
                "locked": False,
            },
        },
        "roles": {"groups_by_id": {}, "treasuries_by_id": {}},
    }


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {"tx_type": tx_type, "signer": signer, "nonce": nonce, "payload": payload, "sig": "x"}


def _admit(state: dict[str, Any], tx: dict[str, Any]):
    return admit_tx(tx, state, _canon(), context="mempool")


def test_canonical_approval_required_journey_admission_apply_and_replay() -> None:
    state = _state()

    create = _env(
        "GROUP_CREATE",
        "@owner",
        1,
        {
            "group_id": "g:approval",
            "charter": "Public charter",
            "membership_mode": "approval_required",
        },
    )
    verdict = _admit(state, create)
    assert verdict.ok is True
    created = apply_tx(state, create)
    assert created["membership_mode"] == "approval_required"
    group = state["roles"]["groups_by_id"]["g:approval"]
    assert group["moderators"] == ["@owner"]
    assert group["membership_requests"] == {}
    assert group["read_visibility"] == "public"
    state["accounts"]["@owner"]["nonce"] = 1

    request = _env(
        "GROUP_MEMBERSHIP_REQUEST",
        "@member",
        1,
        {"group_id": "g:approval", "note": "I agree to the charter"},
    )
    verdict = _admit(state, request)
    assert verdict.ok is True
    requested = apply_tx(state, request)
    assert requested["membership"] == "pending"
    assert "@member" not in group["members"]
    assert group["membership_requests"]["@member"]["note"] == "I agree to the charter"
    state["accounts"]["@member"]["nonce"] = 1

    unauthorized = _env(
        "GROUP_MEMBERSHIP_DECIDE",
        "@outsider",
        1,
        {"group_id": "g:approval", "account": "@member", "decision": "accept"},
    )
    denied = _admit(state, unauthorized)
    assert denied.ok is False
    assert denied.rejection is not None
    assert denied.rejection.code == "gate_denied"
    assert "@member" in group["membership_requests"]

    decide = _env(
        "GROUP_MEMBERSHIP_DECIDE",
        "@owner",
        2,
        {"group_id": "g:approval", "account": "@member", "decision": "accept"},
    )
    verdict = _admit(state, decide)
    assert verdict.ok is True
    decided = apply_tx(state, decide)
    assert decided["request_consumed"] is True
    assert "@member" not in group["membership_requests"]
    assert group["members"]["@member"]["joined_via"] == "moderator_accept"

    state["accounts"]["@owner"]["nonce"] = 2
    replay = _admit(state, decide)
    assert replay.ok is False
    assert replay.rejection is not None
    assert replay.rejection.code == "bad_nonce"

    with pytest.raises(ApplyError) as exc:
        apply_tx(state, decide)
    assert exc.value.code == "not_found"
    assert exc.value.reason == "membership_request_not_found"


def test_schema_rejects_unknown_membership_mode() -> None:
    state = _state()
    bad = _env(
        "GROUP_CREATE",
        "@owner",
        1,
        {"group_id": "g:bad", "membership_mode": "invite_only"},
    )
    verdict = _admit(state, bad)
    assert verdict.ok is False
    assert verdict.rejection is not None
    assert verdict.rejection.code == "invalid_payload"
    assert verdict.rejection.reason == "schema_validation_failed"
