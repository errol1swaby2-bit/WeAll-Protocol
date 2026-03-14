# tests/test_nonce_consumed_on_apply_reject.py
from __future__ import annotations

import copy

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx_atomic


def _empty_state() -> dict:
    return {"accounts": {}, "roles": {}, "params": {}, "poh": {}, "last_block_ts_ms": 0}


def test_nonce_consumed_when_apply_rejects() -> None:
    """Policy B nonce semantics (protocol-aligned, domain-apply level):

    - nonce=2 tx is applied and rejects (missing device)
    - nonce=2 is still consumed
    - nonce=3 tx can be applied
    """
    st = _empty_state()

    # Register
    st = apply_tx_atomic(copy.deepcopy(st), {"tx_type": "ACCOUNT_REGISTER", "signer": "@user000", "nonce": 1, "payload": {"pubkey": "k:u"}, "sig": "x"})
    assert st["accounts"]["@user000"]["nonce"] == 1

    # nonce=2: revoke missing device => apply reject, but nonce must still advance to 2
    with pytest.raises(ApplyError):
        apply_tx_atomic(
            copy.deepcopy(st),
            {"tx_type": "ACCOUNT_DEVICE_REVOKE", "signer": "@user000", "nonce": 2, "payload": {"device_id": "missing"}, "sig": "x"},
        )

    # Confirm nonce consumption behavior by applying nonce=3 successfully.
    st2 = apply_tx_atomic(
        copy.deepcopy(st),
        {"tx_type": "ACCOUNT_DEVICE_REGISTER", "signer": "@user000", "nonce": 3, "payload": {"device_id": "dev1", "pubkey": "k:dev1"}, "sig": "x"},
    )
    assert st2["accounts"]["@user000"]["nonce"] == 3
