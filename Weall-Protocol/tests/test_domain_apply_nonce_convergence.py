from __future__ import annotations

import copy

import pytest

from weall.runtime.domain_apply import NonceSideEffectError, apply_tx_atomic


def _base_state() -> dict:
    return {"accounts": {}, "roles": {}, "params": {"system_signer": "SYSTEM"}, "poh": {}, "last_block_ts_ms": 0}


def test_nonce_convergence_preserves_existing_success_path_batch3() -> None:
    st = _base_state()
    st = apply_tx_atomic(
        copy.deepcopy(st),
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user000",
            "nonce": 1,
            "payload": {"pubkey": "k:u"},
            "sig": "x",
        },
    )
    st = apply_tx_atomic(
        copy.deepcopy(st),
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@user000",
            "nonce": 2,
            "payload": {"device_id": "dev1", "pubkey": "k:dev1"},
            "sig": "x",
        },
    )
    assert st["accounts"]["@user000"]["nonce"] == 2


def test_nonce_convergence_fails_closed_on_overshoot_batch3(monkeypatch: pytest.MonkeyPatch) -> None:
    st = _base_state()
    st = apply_tx_atomic(
        copy.deepcopy(st),
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user001",
            "nonce": 1,
            "payload": {"pubkey": "k:u1"},
            "sig": "x",
        },
    )

    from weall.runtime import domain_apply as da

    original = da._apply_tx_internal

    def _overshoot(snapshot, env):
        original(snapshot, env)
        snapshot["accounts"][env.signer]["nonce"] = int(env.nonce) + 1
        return None

    monkeypatch.setattr(da, "_apply_tx_internal", _overshoot)

    with pytest.raises(NonceSideEffectError, match="nonce_side_effect_overshoot"):
        apply_tx_atomic(
            copy.deepcopy(st),
            {
                "tx_type": "ACCOUNT_DEVICE_REGISTER",
                "signer": "@user001",
                "nonce": 2,
                "payload": {"device_id": "dev1", "pubkey": "k:dev1"},
                "sig": "x",
            },
        )


def test_nonce_convergence_ignores_system_paths_without_signer_account_batch3() -> None:
    st = _base_state()
    st["params"]["system_signer"] = "SYSTEM"
    st = apply_tx_atomic(
        copy.deepcopy(st),
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user002",
            "nonce": 1,
            "payload": {"pubkey": "k:u2"},
            "sig": "x",
        },
    )
    out = apply_tx_atomic(
        copy.deepcopy(st),
        {
            "tx_type": "ACCOUNT_LOCK",
            "signer": "SYSTEM",
            "nonce": 0,
            "payload": {"target": "@user002"},
            "sig": "x",
            "system": True,
            "parent": "p:0",
        },
    )
    assert out["accounts"]["@user002"]["locked"] is True
    assert "SYSTEM" not in out["accounts"]
