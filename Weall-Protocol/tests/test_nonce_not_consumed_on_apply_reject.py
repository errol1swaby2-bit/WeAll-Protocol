from __future__ import annotations

import copy

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx_atomic


def _empty_state() -> dict:
    return {"accounts": {}, "roles": {}, "params": {}, "poh": {}, "last_block_ts_ms": 0}


def test_nonce_not_consumed_when_apply_rejects() -> None:
    st = _empty_state()

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
    assert st["accounts"]["@user000"]["nonce"] == 1

    with pytest.raises(ApplyError):
        apply_tx_atomic(
            st,
            {
                "tx_type": "ACCOUNT_DEVICE_REVOKE",
                "signer": "@user000",
                "nonce": 2,
                "payload": {"device_id": "missing"},
                "sig": "x",
            },
        )

    assert st["accounts"]["@user000"]["nonce"] == 1

    st2 = apply_tx_atomic(
        copy.deepcopy(st),
        {
            "tx_type": "ACCOUNT_DEVICE_REGISTER",
            "signer": "@user000",
            "nonce": 2,
            "payload": {"device_id": "dev1", "pubkey": "k:dev1"},
            "sig": "x",
        },
    )
    assert st2["accounts"]["@user000"]["nonce"] == 2
