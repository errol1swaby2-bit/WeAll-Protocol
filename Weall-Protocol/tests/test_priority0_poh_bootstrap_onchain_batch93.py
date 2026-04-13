from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _state() -> dict:
    return {
        "chain_id": "weall-test",
        "height": 10,
        "accounts": {},
        "params": {
            "system_signer": "SYSTEM",
            "poh_bootstrap_open": True,
            "poh_bootstrap_max_height": 50,
        },
        "poh": {},
        "roles": {},
    }


def _tx(
    tx_type: str,
    *,
    signer: str = "alice",
    nonce: int = 1,
    payload: dict | None = None,
) -> dict:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        system=False,
        payload=payload or {"account_id": "alice"},
    ).to_json()


def test_poh_bootstrap_onchain_allows_valid_self_grant_for_registered_account() -> None:
    state = _state()
    state["accounts"]["alice"] = {
        "nonce": 0,
        "pubkey": "abcd" * 16,
        "poh_tier": 0,
    }

    apply_tx(
        state,
        _tx(
            "POH_BOOTSTRAP_TIER3_GRANT",
            signer="alice",
            nonce=1,
            payload={"account_id": "alice"},
        ),
    )

    acct = state["accounts"]["alice"]
    assert acct.get("poh_tier") == 3
    assert acct.get("poh_bootstrap_mode") == "open"
    assert acct.get("poh_bootstrap_height") == 10
    assert acct.get("poh_bootstrap_granted") is True


def test_poh_bootstrap_onchain_rejects_unregistered_account() -> None:
    state = _state()

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx(
                "POH_BOOTSTRAP_TIER3_GRANT",
                signer="alice",
                nonce=1,
                payload={"account_id": "alice"},
            ),
        )

    assert excinfo.value.reason in {"account_not_found", "account_not_registered"}


def test_poh_bootstrap_onchain_rejects_account_mismatch() -> None:
    state = _state()
    state["accounts"]["alice"] = {
        "nonce": 0,
        "pubkey": "abcd" * 16,
        "poh_tier": 0,
    }

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx(
                "POH_BOOTSTRAP_TIER3_GRANT",
                signer="alice",
                nonce=1,
                payload={"account_id": "bob"},
            ),
        )

    assert excinfo.value.reason in {"bootstrap_self_only", "account_mismatch"}


def test_poh_bootstrap_onchain_rejects_pubkey_mismatch_when_provided() -> None:
    state = _state()
    state["accounts"]["alice"] = {
        "nonce": 0,
        "pubkey": "abcd" * 16,
        "poh_tier": 0,
    }

    with pytest.raises(ApplyError) as excinfo:
        apply_tx(
            state,
            _tx(
                "POH_BOOTSTRAP_TIER3_GRANT",
                signer="alice",
                nonce=1,
                payload={"account_id": "alice", "pubkey": "ffff" * 16},
            ),
        )

    assert excinfo.value.reason in {"bootstrap_pubkey_mismatch", "pubkey_mismatch"}
