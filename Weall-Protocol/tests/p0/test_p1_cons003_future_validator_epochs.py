from __future__ import annotations

import copy

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError


def _env(tx_type: str, payload: dict, *, nonce: int = 1) -> dict:
    return {
        "tx_type": tx_type,
        "signer": "SYSTEM",
        "nonce": nonce,
        "sig": "",
        "payload": payload,
        "system": True,
        "parent": "gov:exec:p1-cons003",
    }


def _seed_current_epoch(state: dict, epoch: int) -> None:
    state.setdefault("consensus", {})
    state["consensus"]["epochs"] = {"current": epoch, "events": []}
    state["consensus"]["validator_set"] = {
        "active_set": ["alice"],
        "epoch": epoch,
    }
    state.setdefault("roles", {}).setdefault("validators", {})["active_set"] = ["alice"]
    state.setdefault("validators", {}).setdefault("registry", {})["alice"] = {
        "account": "alice",
        "pubkey": "mldsa:alice",
        "status": "active",
        "active": True,
    }


@pytest.mark.parametrize(
    ("tx_type", "payload"),
    [
        ("VALIDATOR_CANDIDATE_APPROVE", {"account": "bob", "activate_at_epoch": 4}),
        ("VALIDATOR_SUSPEND", {"account": "alice", "effective_epoch": 4, "reason": "test"}),
        ("VALIDATOR_REMOVE", {"account": "alice", "effective_epoch": 4, "reason": "test"}),
    ],
)
def test_validator_lifecycle_rejects_current_epoch_without_mutation(
    base_state, tx_type: str, payload: dict
) -> None:
    state = copy.deepcopy(base_state)
    _seed_current_epoch(state, 4)
    if tx_type == "VALIDATOR_CANDIDATE_APPROVE":
        state["validators"]["registry"]["bob"] = {
            "account": "bob",
            "pubkey": "mldsa:bob",
            "status": "candidate",
            "active": False,
        }
    before = copy.deepcopy(state)
    with pytest.raises(ApplyError) as exc_info:
        apply_tx(state, _env(tx_type, payload))
    assert exc_info.value.code == "invalid_payload"
    assert exc_info.value.reason == "validator_lifecycle_epoch_must_be_future"
    assert state == before


def test_validator_candidate_approve_accepts_next_epoch(base_state) -> None:
    state = copy.deepcopy(base_state)
    _seed_current_epoch(state, 4)
    state["validators"]["registry"]["bob"] = {
        "account": "bob",
        "pubkey": "mldsa:bob",
        "status": "candidate",
        "active": False,
    }
    out = apply_tx(
        state,
        _env("VALIDATOR_CANDIDATE_APPROVE", {"account": "bob", "activate_at_epoch": 5}),
    )
    assert out["status"] == "pending_activation"
    assert state["consensus"]["validator_set"]["pending"]["activate_at_epoch"] == 5
