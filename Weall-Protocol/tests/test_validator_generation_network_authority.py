from __future__ import annotations

import copy

import pytest

from weall.api.routes_nodes import _active_validators_from_state
from weall.net.node import NetNode
from weall.runtime.bft_runtime_adapter import _current_validator_epoch
from weall.runtime.block_admission import _current_validator_epoch_from_state
from weall.runtime.bootstrap_manifest import validator_epoch_and_hash
from weall.runtime.commitments import validator_set_hash
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError


class _LedgerHolder:
    def __init__(self, state: dict) -> None:
        self.state = state

    def _get_ledger(self) -> dict:
        return self.state


def _authority_state() -> dict:
    return {
        "params": {
            "system_signer": "SYSTEM",
            "validator_candidate_lifecycle_gate_enabled": True,
        },
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 2},
            "bob": {"nonce": 0, "poh_tier": 2},
            "stale": {"nonce": 0, "poh_tier": 2},
        },
        "validators": {
            "registry": {
                "alice": {"account": "alice", "pubkey": "pk-alice", "status": "active"},
                "bob": {"account": "bob", "pubkey": "pk-bob", "status": "candidate"},
            }
        },
        "roles": {
            "validators": {
                "active_set": ["stale"],
                "by_id": {"stale": {"active": True, "status": "active"}},
            }
        },
        "consensus": {
            "epochs": {
                "current": 1,
                "events": [{"event": "open", "epoch": 1}],
            },
            "validator_set": {
                "epoch": 1,
                "active_set": ["alice"],
                "set_hash": validator_set_hash(["alice"]),
            },
            "validators": {
                "registry": {
                    "alice": {"pubkey": "pk-alice", "status": "active"},
                    "bob": {"pubkey": "pk-bob", "status": "candidate"},
                }
            },
        },
    }


def _system_env(tx_type: str, payload: dict, *, nonce: int = 1, parent: str = "gov:test") -> dict:
    return {
        "tx_type": tx_type,
        "signer": "SYSTEM",
        "nonce": nonce,
        "sig": "",
        "system": True,
        "parent": parent,
        "payload": payload,
    }


def test_bft_and_handshake_use_validator_set_generation_not_protocol_epoch() -> None:
    state = _authority_state()
    state["consensus"]["epochs"]["current"] = 9
    state["consensus"]["validator_set"]["epoch"] = 3

    holder = _LedgerHolder(state)

    assert _current_validator_epoch(holder) == 3
    assert _current_validator_epoch_from_state(state) == 3
    assert NetNode._handshake_validator_epoch(holder) == 3
    manifest_epoch, _set_hash, validators = validator_epoch_and_hash(state)
    assert manifest_epoch == 3
    assert validators == ["alice"]


def test_network_and_nodes_surfaces_use_explicit_consensus_membership() -> None:
    state = _authority_state()
    holder = _LedgerHolder(state)

    assert NetNode._is_validator(holder, state, "alice") is True
    assert NetNode._is_validator(holder, state, "stale") is False
    assert _active_validators_from_state(state) == ["alice"]

    state["consensus"]["validator_set"]["set_hash"] = ""
    assert NetNode._handshake_validator_set_hash(holder) == validator_set_hash(["alice"])

    state["consensus"]["validator_set"]["active_set"] = []
    assert NetNode._is_validator(holder, state, "stale") is False
    assert _active_validators_from_state(state) == []
    assert NetNode._handshake_validator_set_hash(holder) == ""
    _epoch, _set_hash, validators = validator_epoch_and_hash(state)
    assert validators == []


def test_production_validator_set_generation_cannot_change_immediately_once_established() -> None:
    state = _authority_state()
    before_validator_set = copy.deepcopy(state["consensus"]["validator_set"])
    before_validator_registry = copy.deepcopy(state["validators"]["registry"])
    before_consensus_registry = copy.deepcopy(state["consensus"]["validators"]["registry"])

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _system_env(
                "VALIDATOR_SET_UPDATE",
                {"active_set": ["alice", "bob"]},
            ),
        )

    assert excinfo.value.code == "invalid_payload"
    assert excinfo.value.reason == "validator_set_update_requires_future_activation"
    assert state["consensus"]["validator_set"] == before_validator_set
    assert state["validators"]["registry"] == before_validator_registry
    assert state["consensus"]["validators"]["registry"] == before_consensus_registry


def test_same_membership_new_generation_is_bound_by_validator_epoch() -> None:
    state = _authority_state()
    holder = _LedgerHolder(state)
    original_hash = state["consensus"]["validator_set"]["set_hash"]

    out = apply_tx(
        state,
        _system_env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["alice"], "activate_at_epoch": 2},
            nonce=1,
            parent="gov:set-generation-2",
        ),
    )
    assert out["pending"] is True
    assert _current_validator_epoch(holder) == 1

    apply_tx(
        state,
        _system_env("EPOCH_CLOSE", {"epoch": 1}, nonce=2, parent="epoch:1:close"),
    )
    opened = apply_tx(
        state,
        _system_env("EPOCH_OPEN", {"epoch": 2}, nonce=3, parent="epoch:2:open"),
    )

    assert opened["validator_set_activated"]["validator_epoch"] == 2
    assert state["consensus"]["validator_set"]["set_hash"] == original_hash
    assert _current_validator_epoch(holder) == 2
    assert _current_validator_epoch_from_state(state) == 2
    assert NetNode._handshake_validator_epoch(holder) == 2


def test_initial_bootstrap_set_can_still_activate_immediately_before_any_generation_exists() -> (
    None
):
    state = _authority_state()
    state["consensus"]["epochs"] = {"current": 0, "events": []}
    state["consensus"]["validator_set"] = {"epoch": 0, "active_set": [], "set_hash": ""}

    out = apply_tx(
        state,
        _system_env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["alice"]},
            parent="bootstrap:set",
        ),
    )

    assert out["validator_epoch"] == 1
    assert state["consensus"]["validator_set"]["active_set"] == ["alice"]
    assert _current_validator_epoch(_LedgerHolder(state)) == 1
