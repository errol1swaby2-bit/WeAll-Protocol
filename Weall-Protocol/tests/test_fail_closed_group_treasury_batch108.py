from __future__ import annotations

import pytest

from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.apply.treasury import apply_treasury
from weall.runtime.tx_admission_types import TxEnvelope


def test_group_treasury_spend_sign_fails_closed_when_execute_enqueue_breaks(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {
        "height": 7,
        "group_treasury_spends": {
            "spend-1": {
                "spend_id": "spend-1",
                "group_id": "group-1",
                "status": "proposed",
                "allowed_signers": ["alice"],
                "threshold": 1,
                "signatures": {},
                "earliest_execute_height": 8,
            }
        },
    }

    def _boom(state: dict, *, spend: dict) -> str | None:
        raise RuntimeError("queue unavailable")

    monkeypatch.setattr(
        "weall.runtime.apply.groups.maybe_enqueue_group_spend_execute",
        _boom,
    )

    env = TxEnvelope(
        tx_type="GROUP_TREASURY_SPEND_SIGN",
        signer="alice",
        nonce=4,
        payload={"spend_id": "spend-1"},
    )

    with pytest.raises(GroupsApplyError) as excinfo:
        apply_groups(state, env)

    assert excinfo.value.reason == "group_spend_execute_enqueue_failed"


def test_group_treasury_spend_propose_fails_closed_when_expire_enqueue_breaks(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {
        "height": 11,
        "params": {"group_treasury_spend_expiry_blocks": 5},
        "roles": {
            "groups_by_id": {
                "group-1": {
                    "group_id": "group-1",
                    "members": {"alice": {}},
                    "signers": ["alice"],
                    "threshold": 1,
                    "treasury_id": "TREASURY_GROUP::group-1",
                }
            },
            "treasuries_by_id": {
                "TREASURY_GROUP::group-1": {
                    "signers": ["alice"],
                    "threshold": 1,
                }
            },
        },
        "groups_by_id": {
            "group-1": {
                "group_id": "group-1",
                "members": {"alice": {}},
                "signers": ["alice"],
                "threshold": 1,
                "treasury_id": "TREASURY_GROUP::group-1",
            }
        },
        "treasury_wallets": {"TREASURY_GROUP::group-1": {"balance": 25}},
        "group_treasury_spends": {},
    }

    def _boom(state: dict, *, spend: dict) -> str | None:
        raise RuntimeError("queue unavailable")

    monkeypatch.setattr(
        "weall.runtime.apply.groups.maybe_enqueue_group_spend_expire",
        _boom,
    )

    env = TxEnvelope(
        tx_type="GROUP_TREASURY_SPEND_PROPOSE",
        signer="alice",
        nonce=5,
        payload={"group_id": "group-1", "spend_id": "spend-1", "to": "bob", "amount": 10},
    )

    with pytest.raises(GroupsApplyError) as excinfo:
        apply_groups(state, env)

    assert excinfo.value.reason == "group_spend_expire_enqueue_failed"


def test_group_signers_set_fails_closed_when_treasury_sync_breaks(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {
        "roles": {
            "groups_by_id": {
                "group-1": {
                    "group_id": "group-1",
                    "members": {"alice": {}},
                    "signers": ["alice"],
                    "threshold": 1,
                    "treasury_id": "TREASURY_GROUP::group-1",
                }
            }
        },
        "groups_by_id": {
            "group-1": {
                "group_id": "group-1",
                "members": {"alice": {}},
                "signers": ["alice"],
                "threshold": 1,
                "treasury_id": "TREASURY_GROUP::group-1",
            }
        },
    }

    def _boom(state: dict, treasury_id: str, signers: list[str], threshold: int = 1) -> None:
        raise RuntimeError("roles unavailable")

    monkeypatch.setattr("weall.runtime.apply.groups.set_treasury_signers", _boom)

    env = TxEnvelope(
        tx_type="GROUP_SIGNERS_SET",
        signer="alice",
        nonce=6,
        payload={"group_id": "group-1", "signers": ["alice"], "threshold": 1},
    )

    with pytest.raises(GroupsApplyError) as excinfo:
        apply_groups(state, env)

    assert excinfo.value.reason == "treasury_signer_sync_failed"


def test_treasury_spend_expire_removes_pending_spend() -> None:
    state = {
        "treasury": {
            "spends": {
                "spend-1": {
                    "spend_id": "spend-1",
                    "status": "proposed",
                    "payload": {"to": "bob", "amount": 10},
                }
            }
        }
    }

    env = TxEnvelope(
        tx_type="TREASURY_SPEND_EXPIRE",
        signer="SYSTEM",
        nonce=9,
        payload={"spend_id": "spend-1"},
        system=True,
    )

    result = apply_treasury(state, env)

    assert result == {"applied": "TREASURY_SPEND_EXPIRE", "spend_id": "spend-1"}
    assert "spend-1" not in state["treasury"]["spends"]
    assert state["treasury_spends_expired"] == [
        {"spend_id": "spend-1", "expired_at_nonce": 9, "payload": {"to": "bob", "amount": 10}}
    ]
