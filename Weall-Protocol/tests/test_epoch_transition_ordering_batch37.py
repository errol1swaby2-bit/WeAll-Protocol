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


def test_epoch_open_requires_sequential_progression() -> None:
    st: dict = {}

    apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=1, system=True))

    with pytest.raises(ApplyError):
        apply_tx(st, _env("EPOCH_OPEN", {"epoch": 3}, nonce=2, system=True))


def test_epoch_open_requires_previous_epoch_close() -> None:
    st: dict = {}

    apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=1, system=True))

    with pytest.raises(ApplyError):
        apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=2, system=True))

    close_meta = apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=3, system=True))
    assert close_meta and close_meta["applied"] == "EPOCH_CLOSE"

    open_meta = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=4, system=True))
    assert open_meta and open_meta["applied"] == "EPOCH_OPEN"
    assert st["consensus"]["epochs"]["current"] == 2


def test_epoch_close_must_match_current_epoch() -> None:
    st: dict = {}

    apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=1, system=True))

    with pytest.raises(ApplyError):
        apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 2}, nonce=2, system=True))

    close_meta = apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=3, system=True))
    assert close_meta and close_meta["applied"] == "EPOCH_CLOSE"

    with pytest.raises(ApplyError):
        apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=4, system=True))


def test_pending_validator_set_activation_still_occurs_on_exact_epoch_boundary() -> None:
    st: dict = {}

    apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v2", "v3"], "activate_at_epoch": 2},
            nonce=1,
            system=True,
        ),
    )
    apply_tx(st, _env("EPOCH_OPEN", {"epoch": 1}, nonce=2, system=True))
    apply_tx(st, _env("EPOCH_CLOSE", {"epoch": 1}, nonce=3, system=True))
    meta = apply_tx(st, _env("EPOCH_OPEN", {"epoch": 2}, nonce=4, system=True))

    activated = meta.get("validator_set_activated") if meta else None
    assert isinstance(activated, dict)
    assert activated["activate_at_epoch"] == 2
    assert activated["validator_epoch"] == 1
    assert st["roles"]["validators"]["active_set"] == ["v1", "v2", "v3"]
