from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str = "SYSTEM",
    nonce: int = 1,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def test_validator_set_update_rejects_conflicting_pending_update() -> None:
    st: dict = {}

    apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v2"], "activate_at_epoch": 3},
            nonce=1,
            system=True,
        ),
    )

    with pytest.raises(ApplyError):
        apply_tx(
            st,
            _env(
                "VALIDATOR_SET_UPDATE",
                {"active_set": ["v1", "v3"], "activate_at_epoch": 4},
                nonce=2,
                system=True,
            ),
        )


def test_validator_set_update_allows_idempotent_restaging_of_same_pending_update() -> None:
    st: dict = {}

    meta1 = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v2"], "activate_at_epoch": 3},
            nonce=1,
            system=True,
        ),
    )
    meta2 = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v2", "v1"], "activate_at_epoch": 3},
            nonce=2,
            system=True,
        ),
    )

    assert meta1 and meta1["pending"] is True
    assert meta2 and meta2["pending"] is True
    pending = st["consensus"]["validator_set"]["pending"]
    assert pending["activate_at_epoch"] == 3
    assert pending["active_set"] == ["v1", "v2"]
    assert meta1["validator_set_hash"] == meta2["validator_set_hash"] == pending["set_hash"]


def test_epoch_open_rejects_skipping_pending_validator_activation_boundary() -> None:
    st: dict = {}

    apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v2"], "activate_at_epoch": 2},
            nonce=1,
            system=True,
        ),
    )

    with pytest.raises(ApplyError):
        apply_tx(st, _env("EPOCH_OPEN", {"epoch": 3}, nonce=2, system=True))
