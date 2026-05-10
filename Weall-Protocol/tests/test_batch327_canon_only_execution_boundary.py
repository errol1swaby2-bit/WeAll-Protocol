from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import admit_tx
from weall.runtime.tx_contracts import load_default_tx_index, noncanon_registry_tx_types
from weall.runtime.tx_schema import model_for_tx_type


NONCANON_LEGACY_TXS = [
    "SLASH",
    "POST_CREATE",
    "POST_EDIT",
    "POST_DELETE",
    "TREASURY_PARAMS_SET",
    "TREASURY_PROGRAM_RECEIPT",
    "ACCOUNT_UNBAN",
    "ACCOUNT_RECOVERY_PROPOSE",
    "ACCOUNT_RECOVERY_EXECUTE",
    "ACCOUNT_RECOVERY_VOTE",
]


def _state() -> dict:
    genesis_time = 1_700_000_000
    unlock_time = genesis_time + (90 * 24 * 60 * 60)
    return {
        "chain_id": "weall-test",
        "height": 0,
        "time": unlock_time + 1,
        "params": {
            "genesis_time": genesis_time,
            "economic_unlock_time": unlock_time,
            "economics_enabled": True,
            "system_signer": "SYSTEM",
        },
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "balance": 100,
            },
            "SYSTEM": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False},
        },
        "slashing": {"events": []},
    }


def _tx(tx_type: str, *, signer: str = "@alice", nonce: int = 1, system: bool = False, payload: dict | None = None) -> dict:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "payload": payload or {},
        "system": system,
        "chain_id": "weall-test",
    }


@pytest.mark.parametrize("tx_type", NONCANON_LEGACY_TXS)
def test_noncanon_txs_rejected_by_admission_with_tx_index(tx_type: str) -> None:
    verdict = admit_tx(_tx(tx_type), _state(), canon=load_default_tx_index(), context="mempool")

    assert verdict.ok is False
    assert verdict.code == "invalid_tx"
    assert verdict.reason == "noncanonical_tx_type"
    assert verdict.details["tx_type"] == tx_type


def test_noncanon_txs_not_claimed_by_handler_registry() -> None:
    assert noncanon_registry_tx_types(load_default_tx_index()) == []


def test_legacy_slash_cannot_mutate_state() -> None:
    state = _state()

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _tx("SLASH", payload={"validator": "@alice", "reason": "legacy"}))

    assert excinfo.value.code == "invalid_tx"
    assert excinfo.value.reason == "noncanonical_tx_type"
    assert state["slashing"]["events"] == []


@pytest.mark.parametrize("alias", ["POST_CREATE", "POST_EDIT", "POST_DELETE"])
def test_post_aliases_rejected_use_canonical_content_txs(alias: str) -> None:
    state = _state()

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(state, _tx(alias, payload={"body": "legacy alias"}))

    assert excinfo.value.reason == "noncanonical_tx_type"

    accepted = apply_tx(
        state,
        _tx(
            "CONTENT_POST_CREATE",
            payload={"post_id": "post:alice:1", "body": "canonical", "visibility": "public"},
        ),
    )
    assert accepted["applied"] == "CONTENT_POST_CREATE"
    assert "post:alice:1" in state["content"]["posts"]


def test_treasury_params_set_removed_use_treasury_policy_set() -> None:
    state = _state()

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx("TREASURY_PARAMS_SET", signer="SYSTEM", nonce=1, system=True, payload={"timelock_blocks": 5}),
        )
    assert excinfo.value.reason == "noncanonical_tx_type"

    out = apply_tx(
        state,
        _tx(
            "TREASURY_POLICY_SET",
            signer="SYSTEM",
            nonce=2,
            system=True,
            payload={"policy": {"timelock_blocks": 5}},
        ),
    )
    assert out["applied"] == "TREASURY_POLICY_SET"
    assert state["treasury_policy"]["value"] == {"timelock_blocks": 5}


def test_supported_schema_map_does_not_include_noncanon_aliases() -> None:
    for tx_type in NONCANON_LEGACY_TXS:
        assert model_for_tx_type(tx_type) is None

    assert model_for_tx_type("CONTENT_POST_CREATE") is not None
    assert model_for_tx_type("TREASURY_POLICY_SET") is not None
