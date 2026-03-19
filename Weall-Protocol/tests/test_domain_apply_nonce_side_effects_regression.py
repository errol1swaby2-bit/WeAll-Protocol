from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, NonceSideEffectError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, *, signer: str = "ci", nonce: int = 1, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload={},
        sig="sig",
        parent=(f"p:{max(0, nonce - 1)}" if system else None),
        system=system,
    )


def test_apply_tx_claim_checks_do_not_require_accounts_map() -> None:
    st = {}

    with pytest.raises(ApplyError):
        apply_tx(st, _env("ACCOUNT_REGISTER"))

    assert st == {}


def test_nonce_side_effect_still_fails_closed_on_malformed_accounts_map() -> None:
    st = {"accounts": []}

    with pytest.raises((NonceSideEffectError, TypeError)):
        apply_tx(st, _env("ACCOUNT_REGISTER"))
