from __future__ import annotations

import copy

import pytest

from weall.net import state_sync
from weall.runtime.apply.dispute import _active_validator_ids as dispute_active_validator_ids
from weall.runtime.apply.governance import (
    _configured_active_validator_ids as governance_active_validator_ids,
)
from weall.runtime.apply.poh import _active_validator_count_for_bootstrap_sunset
from weall.runtime.commitments import validator_set_hash
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.gate_expr import eval_gate
from weall.runtime.poh.bootstrap_quorum import active_validator_count


def _conflicting_state() -> dict:
    return {
        "accounts": {
            "@stale": {"poh_tier": 2},
            "@canonical": {"poh_tier": 2},
        },
        "roles": {
            "validators": {
                "active_set": ["@stale"],
                "by_id": {"@stale": {"status": "active", "active": True}},
            }
        },
        "consensus": {
            "validator_set": {
                "active_set": ["@canonical"],
                "epoch": 7,
                "set_hash": "canonical-set",
            },
            "validators": {
                "registry": {"@canonical": {"pubkey": "pk-canonical", "status": "active"}}
            },
        },
    }


def test_explicit_consensus_validator_set_excludes_stale_role_authority() -> None:
    state = _conflicting_state()

    stale_ok, _ = eval_gate("Validator", signer="@stale", ledger=state, payload={})
    canonical_ok, _ = eval_gate("Validator", signer="@canonical", ledger=state, payload={})

    assert stale_ok is False
    assert canonical_ok is True
    assert governance_active_validator_ids(state) == ["@canonical"]
    assert dispute_active_validator_ids(state) == ["@canonical"]
    assert active_validator_count(state) == 1
    assert _active_validator_count_for_bootstrap_sunset(state) == 1


def test_explicit_empty_consensus_validator_set_cannot_fall_back_to_role_authority() -> None:
    state = _conflicting_state()
    state["consensus"]["validator_set"]["active_set"] = []

    stale_ok, _ = eval_gate("Validator", signer="@stale", ledger=state, payload={})

    assert stale_ok is False
    assert governance_active_validator_ids(state) == []
    assert dispute_active_validator_ids(state) == []
    assert active_validator_count(state) == 0
    assert _active_validator_count_for_bootstrap_sunset(state) == 0


def _system_set_update_state() -> dict:
    return {
        "params": {
            "system_signer": "SYSTEM",
            "validator_candidate_lifecycle_gate_enabled": True,
        },
        "accounts": {"alice": {"poh_tier": 2, "nonce": 0}},
        "validators": {"registry": {}},
        "consensus": {
            "epochs": {"current": 0},
            "validators": {"registry": {}},
        },
    }


def _set_update(active_set: list[str]) -> dict:
    return {
        "tx_type": "VALIDATOR_SET_UPDATE",
        "signer": "SYSTEM",
        "nonce": 1,
        "sig": "",
        "system": True,
        "parent": "gov:validator-set:1",
        "payload": {"active_set": active_set, "activate_at_epoch": 1},
    }


def test_production_validator_set_update_rejects_unregistered_ghost_without_mutation() -> None:
    state = _system_set_update_state()
    before = copy.deepcopy(state)

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _set_update(["ghost"]))

    assert excinfo.value.code == "forbidden"
    assert excinfo.value.reason == "validator_set_member_not_registered"
    assert state == before


def test_production_validator_set_update_rejects_key_registry_disagreement() -> None:
    state = _system_set_update_state()
    state["validators"]["registry"]["alice"] = {
        "account": "alice",
        "pubkey": "canonical-key",
        "status": "candidate",
    }
    state["consensus"]["validators"]["registry"]["alice"] = {"pubkey": "different-key"}
    before = copy.deepcopy(state)

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _set_update(["alice"]))

    assert excinfo.value.code == "invalid_state"
    assert excinfo.value.reason == "validator_set_member_pubkey_authority_mismatch"
    assert state == before


def test_production_validator_set_update_accepts_registered_matching_key_authority() -> None:
    state = _system_set_update_state()
    state["validators"]["registry"]["alice"] = {
        "account": "alice",
        "pubkey": "canonical-key",
        "status": "candidate",
    }
    state["consensus"]["validators"]["registry"]["alice"] = {"pubkey": "canonical-key"}

    result = apply_tx(state, _set_update(["alice"]))

    assert result["applied"] == "VALIDATOR_SET_UPDATE"
    assert state["consensus"]["validator_set"]["pending"]["active_set"] == ["alice"]
    assert state["validators"]["registry"]["alice"]["status"] == "pending_activation"


@pytest.mark.parametrize("tx_type", ["VALIDATOR_SUSPEND", "VALIDATOR_REMOVE"])
def test_validator_lifecycle_system_actions_cannot_fabricate_missing_records(tx_type: str) -> None:
    state = _system_set_update_state()
    before = copy.deepcopy(state)
    envelope = {
        "tx_type": tx_type,
        "signer": "SYSTEM",
        "nonce": 1,
        "sig": "",
        "system": True,
        "parent": "gov:validator-lifecycle:1",
        "payload": {
            "account": "ghost",
            "effective_epoch": 1,
            "reason": "test",
        },
    }

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, envelope)

    assert excinfo.value.code == "forbidden"
    assert excinfo.value.reason == "validator_not_registered"
    assert state == before


@pytest.mark.parametrize(
    ("fault", "snapshot_reason", "domain_code", "domain_reason"),
    [
        (
            "unregistered",
            "member_not_registered",
            "forbidden",
            "validator_set_member_not_registered",
        ),
        (
            "missing_canonical",
            "missing_canonical_pubkey",
            "invalid_state",
            "validator_set_member_missing_canonical_pubkey",
        ),
        (
            "missing_consensus",
            "missing_consensus_pubkey",
            "invalid_state",
            "validator_set_member_missing_consensus_pubkey",
        ),
        (
            "mismatched",
            "pubkey_mismatch",
            "invalid_state",
            "validator_set_member_pubkey_authority_mismatch",
        ),
    ],
)
def test_snapshot_and_canonical_update_share_key_authority_failure_contract(
    fault: str, snapshot_reason: str, domain_code: str, domain_reason: str
) -> None:
    state = _system_set_update_state()
    state["consensus"]["validator_set"] = {
        "active_set": ["alice"],
        "epoch": 0,
        "set_hash": validator_set_hash(["alice"]),
    }
    state["validators"]["registry"]["alice"] = {
        "account": "alice",
        "pubkey": "canonical-key",
        "status": "candidate",
    }
    state["consensus"]["validators"]["registry"]["alice"] = {"pubkey": "canonical-key"}
    if fault == "unregistered":
        state["validators"]["registry"].pop("alice")
    elif fault == "missing_canonical":
        state["validators"]["registry"]["alice"]["pubkey"] = ""
    elif fault == "missing_consensus":
        state["consensus"]["validators"]["registry"].pop("alice")
    else:
        state["consensus"]["validators"]["registry"]["alice"]["pubkey"] = "wrong-key"

    before = copy.deepcopy(state)
    with pytest.raises(
        state_sync.StateSyncVerifyError,
        match=f"snapshot_validator_authority_invalid:{snapshot_reason}:alice",
    ):
        state_sync._validate_snapshot_validator_authority(state)
    assert state == before

    with pytest.raises(ApplyError) as caught:
        apply_tx(state, _set_update(["alice"]))
    assert caught.value.code == domain_code
    assert caught.value.reason == domain_reason
    assert state == before


def test_snapshot_and_canonical_update_accept_matching_registered_validator_keys() -> None:
    state = _system_set_update_state()
    state["validators"]["registry"]["alice"] = {
        "account": "alice",
        "pubkey": "canonical-key",
        "status": "candidate",
    }
    state["consensus"]["validators"]["registry"]["alice"] = {"pubkey": "canonical-key"}
    state["consensus"]["validator_set"] = {
        "active_set": ["alice"],
        "epoch": 0,
        "set_hash": validator_set_hash(["alice"]),
    }
    before = copy.deepcopy(state)

    state_sync._validate_snapshot_validator_authority(state)
    assert state == before
    result = apply_tx(state, _set_update(["alice"]))
    assert result["pending"] is True
    assert state["consensus"]["validator_set"]["pending"]["active_set"] == ["alice"]
